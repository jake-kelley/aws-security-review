"""EKS (Elastic Kubernetes Service) security checks.

Covers the "big hitters" for the EKS control plane (all read-only,
runnable under the AWS-managed ``SecurityAudit`` policy). The selection
follows AWS Security Hub's EKS controls and the Well-Architected security
pillar (SEC04 detective controls, SEC05 network, SEC08 data at rest). EKS
is regional, so every enabled region is scanned; each cluster is one
``describe_cluster`` call.

Per cluster:

1. Public API endpoint open to the world -- ``endpointPublicAccess`` on
   with ``0.0.0.0/0`` in ``publicAccessCidrs`` means the Kubernetes API
   server is reachable from the entire internet (HIGH). A public endpoint
   restricted to specific CIDRs is flagged for review but not failed.
2. Kubernetes version out of support -- old versions stop getting
   security patches (point-in-time list; see ``_MIN_SUPPORTED_K8S``).
3. Secrets envelope encryption with KMS off -- without an
   ``encryptionConfig`` for ``secrets``, Kubernetes Secrets sit in etcd
   under only the AWS-owned default key, not a customer-managed KMS key.
4. Control-plane audit logging off -- without the ``audit`` log type, API
   server activity isn't recorded in CloudWatch Logs.

Design notes / known blind spots (kept deliberately simple):
* Control-plane configuration only. Node groups, Fargate profiles,
  in-cluster RBAC, network policies, and add-ons are not inspected -- the
  Kubernetes API itself is out of scope for an AWS-config scanner.
* The supported-version floor is point-in-time (mid-2026). Refresh
  ``_MIN_SUPPORTED_K8S`` against the EKS version calendar.

Output: alongside the per-cluster findings (which drive ``--fail-on`` and
the JSON ``findings`` array), the module builds one table -- clusters as
rows, checks as columns. The Version column shows the version string
itself (``EOL`` when unsupported); the Endpoint column shows ``OPEN`` for
internet-facing, ``COND`` for restricted-public, ``OK`` for private.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "eks"

# Short status tokens used in the table cells (colored by the reporter).
_ON, _OFF, _OK, _OPEN, _COND, _EOL, _ERR = "ON", "OFF", "OK", "OPEN", "COND", "EOL", "ERR"

# Oldest Kubernetes minor version still in EKS standard support. Clusters below
# this are flagged. Kept in sync with the Security Hub EKS.2 control's
# ``oldestVersionSupported`` parameter (1.33 as of mid-2026); refresh against
# the EKS version calendar -- this is the EKS analogue of Lambda's
# deprecated-runtime list.
_MIN_SUPPORTED_K8S = (1, 33)

# Table columns: (header, cell key). Region first as context.
_COLUMNS = [
    ("Region", "region"),
    ("Version", "version"),
    ("Endpoint", "endpoint"),
    ("Audit", "audit"),
    ("SecretsEnc", "secrets_enc"),
]


def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus the coverage table."""
    return _EksScanner(ctx).scan()


def _parse_version(value) -> tuple[int, ...] | None:
    """Parse ``"1.29"`` into ``(1, 29)``; None if it isn't dotted numerics."""
    try:
        return tuple(int(part) for part in str(value).split("."))
    except (ValueError, AttributeError):
        return None


class _EksScanner:
    """Checks the control-plane configuration of every EKS cluster."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # (region, cluster name, {cell key: token}); powers the table.
        self.rows: list[tuple[str, str, dict[str, str]]] = []

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check every cluster in every enabled region, then build the table."""
        regions = self._regions()
        for i, region in enumerate(regions, start=1):
            self.ctx.progress.update(f"eks: {region} ({i}/{len(regions)})")
            self._scan_region(region)
        if not self.rows:
            # Make "nothing to scan" visible rather than a silently absent table.
            self._add(
                check_id="eks_clusters",
                title="No EKS clusters found",
                severity=Severity.INFO,
                status=Status.PASS,
                detail="ListClusters returned no clusters in any scanned region.",
            )
            return ScanResult(findings=self.findings)
        return ScanResult(findings=self.findings, tables=[self._build_table()])

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        """Append a Finding, stamping the service so callers don't repeat it."""
        self.findings.append(Finding(service=SERVICE, **kwargs))

    @staticmethod
    def _code(err: ClientError) -> str:
        return err.response.get("Error", {}).get("Code", "Unknown")

    def _regions(self) -> list[str]:
        """List the regions enabled for this account (sorted).

        Uses the shared (cached) ``ScanContext.enabled_regions()`` helper.
        Falls back to the context region if that fails.
        """
        try:
            return self.ctx.enabled_regions()
        except ClientError as err:
            self._add(
                check_id="eks_region_lookup",
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
        """List the region's clusters and check each one."""
        eks = self.ctx.session.client("eks", region_name=region)
        try:
            names = [
                name
                for page in eks.get_paginator("list_clusters").paginate()
                for name in page.get("clusters", [])
            ]
        except ClientError as err:
            self._add(
                check_id="eks_region_scan",
                title="Could not list EKS clusters",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=region,
                detail=f"eks:ListClusters failed in {region}: {self._code(err)}.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return
        for name in names:
            self.ctx.progress.update(f"eks: {region}/{name}")
            try:
                cluster = eks.describe_cluster(name=name)["cluster"]
            except ClientError as err:
                self._add(
                    check_id="eks_cluster_scan",
                    title="Could not describe EKS cluster",
                    severity=Severity.INFO,
                    status=Status.ERROR,
                    resource=f"cluster:{region}/{name}",
                    detail=f"eks:DescribeCluster failed: {self._code(err)}.",
                    recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
                )
                continue
            self._scan_cluster(region, name, cluster)

    def _scan_cluster(self, region: str, name: str, cluster: dict) -> None:
        """Run all four checks for one cluster and record its table row."""
        resource = f"cluster:{region}/{name}"
        cells: dict[str, str] = {"region": region}
        self.rows.append((region, name, cells))

        self._check_endpoint(resource, cells, cluster)
        self._check_version(resource, cells, cluster)
        self._check_audit_logging(resource, cells, cluster)
        self._check_secrets_encryption(resource, cells, cluster)

    # ---- checks ----------------------------------------------------------
    def _check_endpoint(self, resource, cells, cluster) -> None:
        """Check 1: the public API endpoint is not open to the whole internet."""
        vpc = cluster.get("resourcesVpcConfig") or {}
        public = vpc.get("endpointPublicAccess", True)  # AWS default is True
        cidrs = vpc.get("publicAccessCidrs") or []
        open_world = public and ("0.0.0.0/0" in cidrs or not cidrs)
        if not public:
            cells["endpoint"] = _OK
            self._add(
                check_id="eks_endpoint_public",
                title="Cluster API endpoint is private",
                severity=Severity.HIGH,
                status=Status.PASS,
                resource=resource,
                detail="The Kubernetes API endpoint is private (endpointPublicAccess "
                "is off).",
            )
        elif open_world:
            cells["endpoint"] = _OPEN
            self._add(
                check_id="eks_endpoint_public",
                title="Cluster API endpoint is open to the internet",
                severity=Severity.HIGH,
                status=Status.FAIL,
                resource=resource,
                detail="endpointPublicAccess is on and publicAccessCidrs allow "
                "0.0.0.0/0: the Kubernetes API server is reachable from the entire "
                "internet.",
                recommendation="Restrict publicAccessCidrs to known ranges, or make the "
                "endpoint private and reach it over a VPN / bastion.",
                references=["Security Hub EKS.1", "Well-Architected SEC05"],
            )
        else:
            # Public but CIDR-restricted: a legitimate pattern, so this is a PASS,
            # but the COND token flags it for a human to confirm the ranges.
            cells["endpoint"] = _COND
            self._add(
                check_id="eks_endpoint_public",
                title="Cluster API endpoint is public but CIDR-restricted",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                resource=resource,
                detail=f"endpointPublicAccess is on but limited to {', '.join(cidrs)}. "
                "Verify these ranges are as tight as possible.",
                references=["Security Hub EKS.1"],
            )

    def _check_version(self, resource, cells, cluster) -> None:
        """Check 2: the Kubernetes version is still in support."""
        version = cluster.get("version")
        parsed = _parse_version(version)
        unsupported = parsed is not None and parsed < _MIN_SUPPORTED_K8S
        min_str = ".".join(str(p) for p in _MIN_SUPPORTED_K8S)
        cells["version"] = _EOL if unsupported else (version or _ERR)
        self._add(
            check_id="eks_version_supported",
            title=f"Kubernetes version {version} is "
            + ("out of standard support" if unsupported else "supported"),
            severity=Severity.MEDIUM,
            status=Status.FAIL if unsupported else Status.PASS,
            resource=resource,
            detail=f"Cluster runs Kubernetes {version}, below the {min_str} standard-"
            "support floor; it may no longer receive security patches."
            if unsupported
            else f"Cluster runs Kubernetes {version}.",
            recommendation=""
            if not unsupported
            else "Upgrade the cluster to a version in EKS standard support.",
            references=["Security Hub EKS.2"],
        )

    def _check_audit_logging(self, resource, cells, cluster) -> None:
        """Check 4: control-plane audit logging is enabled."""
        enabled_types = set()
        for entry in (cluster.get("logging") or {}).get("clusterLogging") or []:
            if entry.get("enabled"):
                enabled_types.update(entry.get("types") or [])
        audit_on = "audit" in enabled_types
        cells["audit"] = _ON if audit_on else _OFF
        self._add(
            check_id="eks_audit_logging",
            title="Control-plane audit logging is " + ("on" if audit_on else "off"),
            severity=Severity.MEDIUM,
            status=Status.PASS if audit_on else Status.FAIL,
            resource=resource,
            detail="The 'audit' control-plane log type is enabled to CloudWatch Logs."
            if audit_on
            else "The 'audit' control-plane log type is not enabled, so API server "
            "activity is not recorded for detection or investigation.",
            recommendation=""
            if audit_on
            else "Enable at least the 'audit' and 'authenticator' control-plane log "
            "types on the cluster.",
            references=["Security Hub EKS.8", "Well-Architected SEC04"],
        )

    def _check_secrets_encryption(self, resource, cells, cluster) -> None:
        """Check 3: Kubernetes Secrets use envelope encryption with KMS."""
        encrypted = any(
            "secrets" in (entry.get("resources") or [])
            for entry in (cluster.get("encryptionConfig") or [])
        )
        cells["secrets_enc"] = _ON if encrypted else _OFF
        self._add(
            check_id="eks_secrets_encryption",
            title="Kubernetes Secrets envelope encryption is "
            + ("on" if encrypted else "off"),
            severity=Severity.MEDIUM,
            status=Status.PASS if encrypted else Status.FAIL,
            resource=resource,
            detail="Secrets are envelope-encrypted with a KMS key (encryptionConfig "
            "covers 'secrets')."
            if encrypted
            else "No encryptionConfig covers 'secrets', so Kubernetes Secrets rely on "
            "the AWS-owned default etcd encryption rather than a customer-managed KMS key.",
            recommendation=""
            if encrypted
            else "Enable envelope encryption of Kubernetes Secrets with a customer-"
            "managed KMS key.",
            references=["Security Hub EKS.3", "Well-Architected SEC08"],
        )

    # ---- table -----------------------------------------------------------
    def _build_table(self) -> Table:
        """Assemble the clusters-as-rows, checks-as-columns coverage grid."""
        rows = [
            TableRow(
                label=name,
                key=f"{region}/{name}",
                cells=[cells.get(key, _ERR) for _, key in _COLUMNS],
            )
            for region, name, cells in sorted(self.rows, key=lambda r: (r[0], r[1]))
        ]
        return Table(
            title="EKS cluster security",
            service=SERVICE,
            corner="Cluster",
            columns=[header for header, _ in _COLUMNS],
            rows=rows,
        )
