"""EC2 security checks.

Covers the "big hitters" for EC2 compute/network/storage security (all
read-only, runnable under the AWS-managed ``SecurityAudit`` policy). The
selection follows the CIS AWS Foundations Benchmark, AWS Security Hub
controls, and the Well-Architected security pillar (SEC05 network
protection, SEC06 compute protection, SEC08 data at rest). EC2 is
regional, so every enabled region is scanned.

Region-level (one row per check in the region-posture table):

1. Publicly restorable EBS snapshots -- anyone on the internet can copy
   the disk contents (a classic mass-leak vector)
2. Public AMIs -- images shared with *all* AWS accounts frequently leak
   baked-in credentials, code, and configuration
3. Security groups opening admin ports (SSH/RDP) or all traffic to the
   world (0.0.0.0/0 or ::/0)
4. Default security groups that still allow traffic -- CIS wants them
   rule-free so an accidental launch into one gets no connectivity
5. EBS encryption-by-default off -- newly created volumes start life
   unencrypted

Per-instance (one row per instance in the instance table):

6. IMDSv2 not enforced (``HttpTokens != required``) -- IMDSv1 is the
   classic SSRF -> instance-credential-theft pivot; a disabled metadata
   endpoint also counts as a pass
7. Public IPv4 address -- direct internet exposure instead of going
   through a load balancer / NAT
8. Attached EBS volumes that are not encrypted at rest
9. Internet-exposed admin port -- the synthesis of 3 + 7: a public IP
   *and* an attached security group opening 22/3389 (or everything) to
   the world. Emitted as a FAIL-only finding (the per-SG and public-IP
   findings already carry the PASS side).

Design notes / known blind spots (kept deliberately simple):
* Security-group exposure looks at SG rules only; an instance in a
  private subnet (no route from an IGW) is unreachable even with an open
  SG, and NACLs are not consulted. Conversely severity is raised when an
  offending SG is attached to at least one network interface.
* "Admin ports" means SSH (22) and RDP (3389); a rule opening a range
  that covers them (or all traffic) counts. Other ports (databases,
  web) are not judged -- opening 80/443 to the world is often intended.
* Terminated / shutting-down instances are skipped; stopped instances
  are still checked (their configuration survives a restart).

Output: alongside the per-resource findings (which drive ``--fail-on``
and the JSON ``findings`` array), the module builds two tables: a
region-posture grid (checks as rows, regions as columns, GuardDuty
style) and an instance grid (instances as rows, checks as columns, S3
style).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "ec2"

CIS = "CIS AWS Foundations Benchmark"

# Short status tokens used in the table cells (colored by the reporter).
_OK, _FAIL, _OPEN, _ON, _OFF, _NA, _ERR = "OK", "FAIL", "OPEN", "ON", "OFF", "-", "ERR"

# The remote-administration ports CIS 5.2/5.3 cares about.
_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}

# Instance states whose configuration no longer matters.
_SKIP_STATES = {"terminated", "shutting-down"}

# Region-posture table rows: (check_id, row label), in display order.
_REGION_ROWS = [
    ("ec2_public_snapshots", "Public Snapshots"),
    ("ec2_public_amis", "Public AMIs"),
    ("ec2_sg_open_admin_ports", "Open Admin-Port SGs"),
    ("ec2_default_sg_restricts_traffic", "Default SGs Restricted"),
    ("ec2_ebs_default_encryption", "EBS Default Encryption"),
]

# Instance table columns: (header, cell key). Region first so rows are
# self-describing; the rest are one column per check.
_INSTANCE_COLUMNS = [
    ("Region", "region"),
    ("IMDSv2", "imdsv2"),
    ("PubIP", "public_ip"),
    ("EBS", "ebs"),
    ("SG", "sg"),
]


def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus two coverage tables."""
    return _Ec2Scanner(ctx).scan()


# ---------------------------------------------------------------------------
# Security-group rule helpers (module-private)
# ---------------------------------------------------------------------------
def _world_open_exposures(sg: dict) -> list[str]:
    """Describe this SG's ingress rules that expose admin ports to the world.

    Returns human-readable labels like ``SSH (22/tcp)`` or ``ALL traffic``
    for every rule whose source is 0.0.0.0/0 or ::/0 and whose port range
    covers an admin port (or every port). Empty list means the SG is fine.
    """
    out = []
    for perm in sg.get("IpPermissions", []):
        open_v4 = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", []))
        open_v6 = any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
        if not (open_v4 or open_v6):
            continue
        proto = perm.get("IpProtocol")
        if proto == "-1":  # "all traffic": every protocol, every port
            out.append("ALL traffic")
            continue
        if proto not in ("tcp", "udp"):
            continue  # e.g. ICMP open to the world is not an admin-port issue
        low = perm.get("FromPort", 0)
        high = perm.get("ToPort", 65535)
        for port, label in sorted(_ADMIN_PORTS.items()):
            if low <= port <= high:
                out.append(f"{label} ({port}/{proto})")
    # Dedup (a port opened by both an IPv4 and an IPv6 rule) preserving order.
    return list(dict.fromkeys(out))


class _Ec2Scanner:
    """Checks region-level EC2 posture plus the configuration of every instance."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # region -> {check_id: token}; powers the region-posture table.
        self.region_cells: dict[str, dict[str, str]] = {}
        # (region, instance_id, {cell key: token}); powers the instance table.
        self.instance_rows: list[tuple[str, str, dict[str, str]]] = []

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check each region, then assemble the two coverage tables."""
        regions = self._regions()
        for i, region in enumerate(regions, start=1):
            self.ctx.progress.update(f"ec2: {region} ({i}/{len(regions)})")
            self._scan_region(region)
        tables = [self._region_table(regions)]
        if self.instance_rows:
            tables.append(self._instance_table())
        else:
            # Make "nothing to scan" visible rather than a silently absent table.
            self._add(
                check_id="ec2_instances",
                title="No EC2 instances found",
                severity=Severity.INFO,
                status=Status.PASS,
                detail="DescribeInstances returned no (non-terminated) instances "
                "in any scanned region.",
            )
        return ScanResult(findings=self.findings, tables=tables)

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        """Append a Finding, stamping the service so callers don't repeat it."""
        self.findings.append(Finding(service=SERVICE, **kwargs))

    @staticmethod
    def _code(err: ClientError) -> str:
        return err.response.get("Error", {}).get("Code", "Unknown")

    def _fetch(self, errors: list[str], what: str, call):
        """Run one read call; on failure record it and return None.

        Failures are collected into ``errors`` so each region gets a single
        rolled-up ERROR finding instead of one per failed call.
        """
        try:
            return call()
        except ClientError as err:
            errors.append(f"{what}: {self._code(err)}")
            return None

    @staticmethod
    def _paged(client, op: str, key: str, **kwargs) -> list:
        """Collect every ``key`` item across all pages of a paginated call."""
        return [
            item
            for page in client.get_paginator(op).paginate(**kwargs)
            for item in page.get(key, [])
        ]

    def _regions(self) -> list[str]:
        """List the regions enabled for this account (sorted).

        Uses the shared (cached) ``ScanContext.enabled_regions()`` helper.
        Falls back to the context region if that fails.
        """
        try:
            return self.ctx.enabled_regions()
        except ClientError as err:
            self._add(
                check_id="ec2_region_lookup",
                title="Could not list regions",
                severity=Severity.INFO,
                status=Status.ERROR,
                detail=f"ec2:DescribeRegions failed: {self._code(err)}. "
                f"Falling back to {self.ctx.region} only.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return [self.ctx.region]

    # ---- per-region scan ----------------------------------------------
    def _scan_region(self, region: str) -> None:
        """Run every region-level check plus each instance in one region."""
        cells: dict[str, str] = {}
        self.region_cells[region] = cells
        errors: list[str] = []
        ec2 = self.ctx.session.client("ec2", region_name=region)

        # Bulk data loads shared by several checks. Each degrades to None
        # (and an entry in ``errors``) independently, so one denied call
        # doesn't take out the whole region.
        instances = self._fetch(errors, "DescribeInstances", lambda: self._load_instances(ec2))
        sgs = self._fetch(
            errors,
            "DescribeSecurityGroups",
            lambda: self._paged(ec2, "describe_security_groups", "SecurityGroups"),
        )
        # SG ids attached to at least one ENI: an open-but-unattached SG is
        # dormant risk, so attachment drives the severity of SG findings.
        in_use = self._fetch(
            errors,
            "DescribeNetworkInterfaces",
            lambda: {
                g["GroupId"]
                for eni in self._paged(ec2, "describe_network_interfaces", "NetworkInterfaces")
                for g in eni.get("Groups", [])
            },
        )
        vol_encrypted = self._fetch(
            errors,
            "DescribeVolumes",
            lambda: {
                v["VolumeId"]: bool(v.get("Encrypted"))
                for v in self._paged(ec2, "describe_volumes", "Volumes")
            },
        )

        open_sgs = self._check_security_groups(region, cells, sgs, in_use)
        self._check_default_sgs(region, cells, sgs, in_use)
        self._check_public_snapshots(ec2, region, cells, errors)
        self._check_public_amis(ec2, region, cells, errors)
        self._check_ebs_default_encryption(ec2, region, cells, errors)

        for inst in instances or []:
            self._scan_instance(region, inst, vol_encrypted, open_sgs)

        # One rolled-up ERROR finding per region instead of one per failed call.
        if errors:
            self._add(
                check_id="ec2_region_scan",
                title="Could not fully check EC2 in region",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=region,
                detail="; ".join(errors),
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )

    @staticmethod
    def _load_instances(ec2) -> list[dict]:
        """Flatten DescribeInstances' Reservations->Instances nesting."""
        return [
            inst
            for page in ec2.get_paginator("describe_instances").paginate()
            for res in page.get("Reservations", [])
            for inst in res.get("Instances", [])
        ]

    # ---- region-level checks -------------------------------------------
    def _check_security_groups(self, region, cells, sgs, in_use):
        """Check 3: SGs opening admin ports (or all traffic) to the world.

        Returns the set of offending SG ids (used again by the per-instance
        exposure check), or None when the SG list could not be read.
        """
        if sgs is None:
            cells["ec2_sg_open_admin_ports"] = _ERR
            return None
        open_ids: set[str] = set()
        for sg in sgs:
            exposures = _world_open_exposures(sg)
            if not exposures:
                continue
            open_ids.add(sg["GroupId"])
            attached = in_use is not None and sg["GroupId"] in in_use
            if attached:
                usage = " and is attached to at least one network interface."
            elif in_use is not None:
                usage = "; it is not currently attached to anything (dormant risk)."
            else:  # attachment unknown (ENI call failed)
                usage = "."
            self._add(
                check_id="ec2_sg_open_admin_ports",
                title="Security group opens admin ports to the internet",
                severity=Severity.HIGH if attached else Severity.MEDIUM,
                status=Status.FAIL,
                resource=f"sg:{region}/{sg['GroupId']}",
                detail=f"'{sg.get('GroupName', '?')}' allows {', '.join(exposures)} "
                f"from 0.0.0.0/0 or ::/0{usage}",
                recommendation="Restrict the source to known CIDRs -- or better, drop "
                "direct SSH/RDP exposure in favor of SSM Session Manager.",
                references=[f"{CIS} 5.2/5.3", "Security Hub EC2.13/EC2.14",
                            "Well-Architected SEC05"],
            )
        cells["ec2_sg_open_admin_ports"] = _OPEN if open_ids else _OK
        if not open_ids:
            self._add(
                check_id="ec2_sg_open_admin_ports",
                title="No security group opens admin ports to the internet",
                severity=Severity.HIGH,
                status=Status.PASS,
                resource=region,
                detail=f"{len(sgs)} security group(s) checked; none allow SSH/RDP "
                "or all traffic from the whole internet.",
            )
        return open_ids

    def _check_default_sgs(self, region, cells, sgs, in_use) -> None:
        """Check 4: default security groups have no rules at all (CIS 5.4)."""
        if sgs is None:
            cells["ec2_default_sg_restricts_traffic"] = _ERR
            return
        defaults = [sg for sg in sgs if sg.get("GroupName") == "default"]
        if not defaults:  # no VPCs in this region
            cells["ec2_default_sg_restricts_traffic"] = _NA
            return
        open_defaults = []
        for sg in defaults:
            n_in = len(sg.get("IpPermissions", []))
            n_out = len(sg.get("IpPermissionsEgress", []))
            if not n_in and not n_out:
                continue
            open_defaults.append(sg)
            attached = in_use is not None and sg["GroupId"] in in_use
            self._add(
                check_id="ec2_default_sg_restricts_traffic",
                title="Default security group still allows traffic",
                # Only really bites if something uses it; dormant ones are LOW.
                severity=Severity.MEDIUM if attached else Severity.LOW,
                status=Status.FAIL,
                resource=f"sg:{region}/{sg['GroupId']}",
                detail=f"The default security group of {sg.get('VpcId', '?')} has "
                f"{n_in} ingress and {n_out} egress rule(s)"
                + (" and is in use." if attached else " (not currently in use)."),
                recommendation="Remove every rule from the default security group so "
                "an accidental launch into it gets no connectivity; use purpose-built "
                "groups instead.",
                references=[f"{CIS} 5.4", "Security Hub EC2.2"],
            )
        cells["ec2_default_sg_restricts_traffic"] = _FAIL if open_defaults else _OK
        if not open_defaults:
            self._add(
                check_id="ec2_default_sg_restricts_traffic",
                title="Default security groups restrict all traffic",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                resource=region,
                detail=f"All {len(defaults)} default security group(s) have no rules.",
            )

    def _check_public_snapshots(self, ec2, region, cells, errors) -> None:
        """Check 1: EBS snapshots restorable by everyone (public).

        ``RestorableByUserIds=["all"]`` combined with ``OwnerIds=[account]``
        makes AWS return exactly the account's public snapshots -- one
        paginated call, no per-snapshot attribute lookups.
        """
        snaps = self._fetch(
            errors,
            "DescribeSnapshots",
            lambda: self._paged(
                ec2,
                "describe_snapshots",
                "Snapshots",
                OwnerIds=[self.ctx.account_id],
                RestorableByUserIds=["all"],
            ),
        )
        if snaps is None:
            cells["ec2_public_snapshots"] = _ERR
            return
        cells["ec2_public_snapshots"] = _FAIL if snaps else _OK
        if not snaps:
            self._add(
                check_id="ec2_public_snapshots",
                title="No public EBS snapshots",
                severity=Severity.CRITICAL,
                status=Status.PASS,
                resource=region,
                detail="No snapshot owned by this account is publicly restorable.",
            )
            return
        for snap in snaps:
            self._add(
                check_id="ec2_public_snapshots",
                title="EBS snapshot is publicly restorable",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                resource=f"snapshot:{region}/{snap['SnapshotId']}",
                detail="Anyone with an AWS account can create a volume from this "
                "snapshot and read every block on it.",
                recommendation="Remove the 'all' createVolumePermission from the "
                "snapshot (make it private) and rotate any secrets it contains.",
                references=["Security Hub EC2.1", "Well-Architected SEC08"],
            )

    def _check_public_amis(self, ec2, region, cells, errors) -> None:
        """Check 2: AMIs shared publicly (Public flag on DescribeImages)."""
        images = self._fetch(errors, "DescribeImages", lambda: self._describe_images(ec2))
        if images is None:
            cells["ec2_public_amis"] = _ERR
            return
        public = [i for i in images if i.get("Public")]
        cells["ec2_public_amis"] = _FAIL if public else _OK
        if not public:
            self._add(
                check_id="ec2_public_amis",
                title="No public AMIs",
                severity=Severity.HIGH,
                status=Status.PASS,
                resource=region,
                detail=f"{len(images)} AMI(s) owned by this account; none are public.",
            )
            return
        for image in public:
            self._add(
                check_id="ec2_public_amis",
                title="AMI is shared publicly",
                severity=Severity.HIGH,
                status=Status.FAIL,
                resource=f"ami:{region}/{image['ImageId']}",
                detail=f"Image '{image.get('Name', '?')}' is launchable by every AWS "
                "account; baked-in credentials, code, and configuration are exposed.",
                recommendation="Make the AMI private (remove the 'all' launch "
                "permission) unless it is an intentionally published image.",
                references=["Well-Architected SEC08", "AWS AMI sharing best practices"],
            )

    @staticmethod
    def _describe_images(ec2) -> list[dict]:
        """List the account's own AMIs (paginated where botocore supports it)."""
        if ec2.can_paginate("describe_images"):
            return [
                i
                for page in ec2.get_paginator("describe_images").paginate(Owners=["self"])
                for i in page.get("Images", [])
            ]
        return ec2.describe_images(Owners=["self"]).get("Images", [])

    def _check_ebs_default_encryption(self, ec2, region, cells, errors) -> None:
        """Check 5: EBS encryption-by-default is on for the region."""
        resp = self._fetch(
            errors, "GetEbsEncryptionByDefault", lambda: ec2.get_ebs_encryption_by_default()
        )
        if resp is None:
            cells["ec2_ebs_default_encryption"] = _ERR
            return
        on = bool(resp.get("EbsEncryptionByDefault"))
        cells["ec2_ebs_default_encryption"] = _ON if on else _OFF
        self._add(
            check_id="ec2_ebs_default_encryption",
            title="EBS encryption by default is " + ("on" if on else "off"),
            severity=Severity.MEDIUM,
            status=Status.PASS if on else Status.FAIL,
            resource=region,
            detail="New EBS volumes in this region are encrypted automatically."
            if on
            else "New EBS volumes in this region are created unencrypted unless "
            "each one opts in.",
            recommendation=""
            if on
            else f"Enable EBS encryption by default in {region} "
            "(EC2 console > Account attributes, or enable-ebs-encryption-by-default).",
            references=[f"{CIS} 2.2.1", "Security Hub EC2.7", "Well-Architected SEC08"],
        )

    # ---- per-instance checks ---------------------------------------------
    def _scan_instance(self, region, inst, vol_encrypted, open_sgs) -> None:
        """Run checks 6-9 for one instance and record its table row."""
        state = (inst.get("State") or {}).get("Name", "")
        if state in _SKIP_STATES:
            return
        iid = inst["InstanceId"]
        resource = f"instance:{region}/{iid}"
        name = next(
            (t["Value"] for t in inst.get("Tags", []) if t.get("Key") == "Name"), ""
        )
        who = f"'{name}' ({iid})" if name else iid
        cells: dict[str, str] = {"region": region}
        self.instance_rows.append((region, iid, cells))

        # 6) IMDSv2 enforced (or the metadata endpoint disabled outright).
        meta = inst.get("MetadataOptions") or {}
        endpoint_off = meta.get("HttpEndpoint") == "disabled"
        enforced = meta.get("HttpTokens") == "required" or endpoint_off
        cells["imdsv2"] = _OK if enforced else _FAIL
        self._add(
            check_id="ec2_imdsv2_required",
            title="IMDSv2 is " + ("enforced" if enforced else "not enforced"),
            severity=Severity.HIGH,
            status=Status.PASS if enforced else Status.FAIL,
            resource=resource,
            detail=(
                "The instance metadata endpoint is disabled entirely."
                if endpoint_off
                else f"{who} requires session tokens for the metadata service."
            )
            if enforced
            else f"{who} still answers IMDSv1 requests (HttpTokens="
            f"'{meta.get('HttpTokens', 'unset')}'); an SSRF or proxy bug can steal "
            "the instance role's credentials with one unauthenticated GET.",
            recommendation=""
            if enforced
            else "Set HttpTokens=required on the instance (modify-instance-metadata-"
            "options) and in every launch template.",
            references=[f"{CIS} 5.6", "Security Hub EC2.8", "Well-Architected SEC06"],
        )

        # 7) Public IPv4 address (instance-level or on any attached ENI).
        public_ip = inst.get("PublicIpAddress") or next(
            (
                ni["Association"]["PublicIp"]
                for ni in inst.get("NetworkInterfaces", [])
                if (ni.get("Association") or {}).get("PublicIp")
            ),
            None,
        )
        cells["public_ip"] = _FAIL if public_ip else _OK
        self._add(
            check_id="ec2_instance_public_ip",
            title="Instance has " + ("a public IP" if public_ip else "no public IP"),
            severity=Severity.MEDIUM,
            status=Status.FAIL if public_ip else Status.PASS,
            resource=resource,
            detail=f"{who} is directly addressable from the internet at {public_ip}."
            if public_ip
            else f"{who} has no public IPv4 address.",
            recommendation=""
            if not public_ip
            else "Prefer private subnets behind a load balancer / NAT gateway; if the "
            "instance must be public, keep its security groups tight.",
            references=["Security Hub EC2.9", "Well-Architected SEC05"],
        )

        # 8) Every attached EBS volume is encrypted at rest.
        vol_ids = [
            b["Ebs"]["VolumeId"]
            for b in inst.get("BlockDeviceMappings", [])
            if (b.get("Ebs") or {}).get("VolumeId")
        ]
        if not vol_ids:
            cells["ebs"] = _NA  # instance-store only; nothing to check
        elif vol_encrypted is None:
            cells["ebs"] = _ERR  # DescribeVolumes failed for this region
        else:
            # A volume missing from the map (deleted mid-scan) counts as fine.
            unencrypted = [v for v in vol_ids if vol_encrypted.get(v) is False]
            cells["ebs"] = _FAIL if unencrypted else _OK
            self._add(
                check_id="ec2_instance_ebs_encrypted",
                title="Attached EBS volumes are "
                + ("not all encrypted" if unencrypted else "encrypted"),
                severity=Severity.MEDIUM,
                status=Status.FAIL if unencrypted else Status.PASS,
                resource=resource,
                detail=f"Unencrypted volume(s) on {who}: {', '.join(unencrypted)}."
                if unencrypted
                else f"All {len(vol_ids)} attached volume(s) are encrypted at rest.",
                recommendation=""
                if not unencrypted
                else "Snapshot the volume, copy the snapshot with encryption on, and "
                "swap the volume; enable EBS encryption by default to stop new ones.",
                references=["Security Hub EC2.3", "Well-Architected SEC08"],
            )

        # 9) The killer combo: public IP + an attached SG open to the world.
        if open_sgs is None:
            cells["sg"] = _ERR
            return
        exposed = [
            g["GroupId"] for g in inst.get("SecurityGroups", []) if g["GroupId"] in open_sgs
        ]
        cells["sg"] = _OPEN if exposed else _OK
        if exposed and public_ip:
            self._add(
                check_id="ec2_instance_exposed_admin_port",
                title="Instance exposes admin ports to the internet",
                severity=Severity.HIGH,
                status=Status.FAIL,
                resource=resource,
                detail=f"{who} has public IP {public_ip} and its security group(s) "
                f"{', '.join(exposed)} open SSH/RDP or all traffic to the world -- "
                "it is directly attackable right now.",
                recommendation="Close the security group rule (see the matching "
                "ec2_sg_open_admin_ports finding) or move the instance behind "
                "SSM Session Manager / a bastion.",
                references=["Well-Architected SEC05"],
            )

    # ---- tables ----------------------------------------------------------
    def _region_table(self, regions: list[str]) -> Table:
        """Region posture: checks as rows, regions as columns (GuardDuty style)."""
        rows = [
            TableRow(
                label=label,
                key=check_id,
                # Fall back to ERR if a region somehow produced no cell.
                cells=[self.region_cells.get(r, {}).get(check_id, _ERR) for r in regions],
            )
            for check_id, label in _REGION_ROWS
        ]
        return Table(
            title="EC2 region posture",
            service=SERVICE,
            corner="Check",
            columns=regions,
            rows=rows,
        )

    def _instance_table(self) -> Table:
        """Instance security: instances as rows, checks as columns (S3 style)."""
        rows = [
            TableRow(
                label=iid,
                key=f"{region}/{iid}",
                cells=[cells.get(key, _ERR) for _, key in _INSTANCE_COLUMNS],
            )
            for region, iid, cells in sorted(
                self.instance_rows, key=lambda r: (r[0], r[1])
            )
        ]
        return Table(
            title="EC2 instance security",
            service=SERVICE,
            corner="Instance",
            columns=[header for header, _ in _INSTANCE_COLUMNS],
            rows=rows,
        )
