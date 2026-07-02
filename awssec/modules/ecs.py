"""ECS (Elastic Container Service) security checks.

Covers the "big hitters" for ECS container security (all read-only,
runnable under the AWS-managed ``SecurityAudit`` policy). The selection
follows AWS Security Hub's ECS controls and the Well-Architected security
pillar (SEC02 secrets, SEC04 detective controls, SEC05 network, SEC06
compute). ECS is regional, so every enabled region is scanned.

The security-rich surface is the **task definition**, so most checks live
there. For each container in a task definition (a task def "fails" a
check if *any* of its containers does):

1. Privileged container (``privileged: true``) -- full host device
   access; a container escape becomes host root
2. Host network mode (``networkMode: host``) -- shares the host network
   namespace, bypassing awsvpc isolation and security groups
3. Host PID mode (``pidMode: host``) -- can see and signal every process
   on the host
4. Root filesystem writable (``readonlyRootFilesystem`` not true) --
   defense-in-depth against runtime tampering
5. Runs as root (no non-root ``user`` set) -- least-privilege at runtime
6. Plaintext secrets in ``environment`` -- credential-looking variable
   *names* that should use ``secrets`` (Secrets Manager / SSM) instead.
   Only names are inspected; values are never read.
7. No log configuration (``logConfiguration`` missing) -- no container
   logs to detect or investigate anything

Plus, per **service**:

8. Auto-assigned public IP (``assignPublicIp: ENABLED``) -- tasks get a
   public address instead of sitting behind a load balancer / NAT

Design notes / known blind spots (kept deliberately simple):
* Only the **latest active revision of each task-definition family** is
  described (newest-first, deduped by family), so old revisions don't
  flood the report. A task still running an older revision is not
  separately flagged.
* Task-definition checks read the definition only -- not the running
  container image or its runtime behavior.
* Container Insights / platform-version currency are intentionally out of
  scope (observability / operational, not security big-hitters).

Output: alongside the per-resource findings (which drive ``--fail-on``
and the JSON ``findings`` array), the module builds up to two tables: a
task-definition grid (families as rows, the 7 checks as columns) and a
service grid (services as rows, with a PublicIP check column).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.secrets import looks_like_secret_name
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "ecs"

# Short status tokens used in the table cells (colored by the reporter).
_OK, _FAIL, _NA, _ERR = "OK", "FAIL", "-", "ERR"

# Task-definition table columns: (header, cell key). Region first as context.
_TASK_COLUMNS = [
    ("Region", "region"),
    ("Privileged", "privileged"),
    ("HostNet", "host_net"),
    ("HostPID", "host_pid"),
    ("ReadOnlyFS", "readonly_fs"),
    ("NonRoot", "nonroot"),
    ("Secrets", "secrets"),
    ("Logging", "logging"),
]

# Service table columns. Cluster + Launch are context (like the Region column).
_SERVICE_COLUMNS = [
    ("Region", "region"),
    ("Cluster", "cluster"),
    ("Launch", "launch"),
    ("PublicIP", "public_ip"),
]


def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus coverage tables."""
    return _EcsScanner(ctx).scan()


def _is_root_user(user) -> bool:
    """True if a container definition's ``user`` runs as root (or is unset).

    An unset user means "whatever the image defaults to" -- commonly root --
    so the task definition is not *enforcing* a non-root user either way.
    ``user`` may be ``"0"``, ``"root"``, or ``"uid:gid"`` form.
    """
    if not user:
        return True
    return user.split(":", 1)[0].strip().lower() in ("", "0", "root")


class _EcsScanner:
    """Checks ECS task definitions and services across every enabled region."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # (region, family:revision, {cell key: token}); powers the task table.
        self.task_rows: list[tuple[str, str, dict[str, str]]] = []
        # (region, cluster/service, {cell key: token}); powers the service table.
        self.service_rows: list[tuple[str, str, dict[str, str]]] = []

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check each region, then assemble the coverage tables."""
        regions = self._regions()
        for i, region in enumerate(regions, start=1):
            self.ctx.progress.update(f"ecs: {region} ({i}/{len(regions)})")
            self._scan_region(region)

        tables = []
        if self.task_rows:
            tables.append(self._task_table())
        if self.service_rows:
            tables.append(self._service_table())
        if not tables:
            # Make "nothing to scan" visible rather than silently empty.
            self._add(
                check_id="ecs_resources",
                title="No ECS task definitions or services found",
                severity=Severity.INFO,
                status=Status.PASS,
                detail="No ECS task definitions or services in any scanned region.",
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

        Failures accumulate into ``errors`` so each region gets a single
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
                check_id="ecs_region_lookup",
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
        """Check every latest task definition and every service in one region."""
        errors: list[str] = []
        ecs = self.ctx.session.client("ecs", region_name=region)

        for arn in self._latest_task_def_arns(ecs, errors) or []:
            resp = self._fetch(
                errors,
                "DescribeTaskDefinition",
                lambda a=arn: ecs.describe_task_definition(taskDefinition=a),
            )
            if resp is not None:
                self._scan_task_def(region, resp.get("taskDefinition", {}))

        for cluster_arn in self._fetch(
            errors, "ListClusters", lambda: self._paged(ecs, "list_clusters", "clusterArns")
        ) or []:
            self._scan_cluster_services(ecs, region, cluster_arn, errors)

        # One rolled-up ERROR finding per region instead of one per failed call.
        if errors:
            self._add(
                check_id="ecs_region_scan",
                title="Could not fully check ECS in region",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=region,
                detail="; ".join(errors),
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )

    def _latest_task_def_arns(self, ecs, errors) -> list[str] | None:
        """Return the ARN of the newest revision of each task-def family.

        ``list_task_definitions`` returns every active revision; sorting
        newest-first and keeping the first ARN seen per family gives one
        (the latest) per family without extra calls.
        """
        arns = self._fetch(
            errors,
            "ListTaskDefinitions",
            lambda: self._paged(ecs, "list_task_definitions", "taskDefinitionArns", sort="DESC"),
        )
        if arns is None:
            return None
        latest: dict[str, str] = {}
        for arn in arns:
            segment = arn.rsplit("/", 1)[-1]  # "family:revision"
            family = segment.rpartition(":")[0] or segment
            latest.setdefault(family, arn)  # DESC => first seen is highest revision
        return list(latest.values())

    def _scan_cluster_services(self, ecs, region, cluster_arn, errors) -> None:
        """Describe every service in one cluster and run the public-IP check."""
        cluster = cluster_arn.rsplit("/", 1)[-1]
        self.ctx.progress.update(f"ecs: {region}/{cluster} services")
        arns = self._fetch(
            errors,
            "ListServices",
            lambda: self._paged(ecs, "list_services", "serviceArns", cluster=cluster_arn),
        )
        # describe_services takes at most 10 service ARNs per call.
        for i in range(0, len(arns or []), 10):
            batch = arns[i : i + 10]
            resp = self._fetch(
                errors,
                "DescribeServices",
                lambda b=batch: ecs.describe_services(cluster=cluster_arn, services=b),
            )
            for svc in (resp or {}).get("services", []):
                self._scan_service(region, cluster, svc)

    # ---- task-definition checks ---------------------------------------
    def _scan_task_def(self, region: str, td: dict) -> None:
        """Run the seven task-definition checks and record the table row."""
        family = td.get("family", "?")
        revision = td.get("revision", "?")
        ref = f"{family}:{revision}"
        resource = f"taskdef:{region}/{ref}"
        containers = td.get("containerDefinitions", [])
        cells: dict[str, str] = {"region": region}
        self.task_rows.append((region, ref, cells))

        # Container-level booleans: a task def fails if ANY container fails.
        privileged = [c.get("name", "?") for c in containers if c.get("privileged")]
        writable = [
            c.get("name", "?") for c in containers if not c.get("readonlyRootFilesystem")
        ]
        as_root = [c.get("name", "?") for c in containers if _is_root_user(c.get("user"))]
        no_log = [c.get("name", "?") for c in containers if not c.get("logConfiguration")]
        plaintext = {
            c.get("name", "?"): sorted(
                e.get("name", "")
                for e in c.get("environment", [])
                if looks_like_secret_name(e.get("name", ""))
            )
            for c in containers
        }
        plaintext = {name: hits for name, hits in plaintext.items() if hits}

        # Task-level namespace/network modes.
        host_net = td.get("networkMode") == "host"
        host_pid = td.get("pidMode") == "host"

        self._task_finding(
            "ecs_task_privileged", "privileged", cells, resource, ref,
            bad=bool(privileged), severity=Severity.HIGH,
            issue="privileged container",
            bad_msg=f"Privileged container(s): {', '.join(privileged)}. A privileged "
            "container has full access to host devices; an escape becomes host root.",
            ok_msg="No container runs in privileged mode.",
            fix="Remove 'privileged': true; grant only the specific Linux capabilities "
            "the workload needs.",
            refs=["Security Hub ECS.4", "Well-Architected SEC06"],
        )
        self._task_finding(
            "ecs_task_host_network", "host_net", cells, resource, ref,
            bad=host_net, severity=Severity.HIGH,
            issue="host network mode",
            bad_msg="networkMode is 'host': the task shares the host network namespace, "
            "bypassing awsvpc isolation and per-task security groups.",
            ok_msg=f"networkMode is '{td.get('networkMode', 'unset')}', not host.",
            fix="Use the 'awsvpc' network mode so each task gets its own ENI and "
            "security group.",
            refs=["Security Hub ECS.1", "Well-Architected SEC05"],
        )
        self._task_finding(
            "ecs_task_host_pid", "host_pid", cells, resource, ref,
            bad=host_pid, severity=Severity.HIGH,
            issue="host PID mode",
            bad_msg="pidMode is 'host': containers can see and signal every process on "
            "the host instance.",
            ok_msg="pidMode does not share the host process namespace.",
            fix="Remove pidMode 'host' unless a monitoring agent genuinely requires it.",
            refs=["Security Hub ECS.3", "Well-Architected SEC06"],
        )
        self._task_finding(
            "ecs_task_readonly_rootfs", "readonly_fs", cells, resource, ref,
            bad=bool(writable), severity=Severity.MEDIUM,
            issue="writable root filesystem",
            bad_msg=f"Container(s) with a writable root filesystem: {', '.join(writable)}.",
            ok_msg="All containers use a read-only root filesystem.",
            fix="Set 'readonlyRootFilesystem': true and mount writable volumes only "
            "where needed.",
            refs=["Security Hub ECS.5", "Well-Architected SEC06"],
        )
        self._task_finding(
            "ecs_task_nonroot_user", "nonroot", cells, resource, ref,
            bad=bool(as_root), severity=Severity.MEDIUM,
            issue="container running as root",
            bad_msg=f"Container(s) running as root (or no user set): {', '.join(as_root)}.",
            ok_msg="All containers set a non-root user.",
            fix="Set a non-root 'user' (uid or uid:gid) in each container definition.",
            refs=["Security Hub ECS.1", "Well-Architected SEC06"],
        )
        secret_detail = "; ".join(f"{name}: {', '.join(hits)}" for name, hits in plaintext.items())
        self._task_finding(
            "ecs_task_env_secrets", "secrets", cells, resource, ref,
            bad=bool(plaintext), severity=Severity.HIGH,
            issue="plaintext secret in environment",
            bad_msg=f"Environment variable name(s) look like inline secrets ({secret_detail}). "
            "Plaintext env vars are visible to anyone who can read the task definition. "
            "(Values were not read by this tool.)",
            ok_msg="No plaintext environment variable names match credential patterns.",
            fix="Move secrets to Secrets Manager / SSM and reference them via the "
            "container 'secrets' field (valueFrom), not 'environment'.",
            refs=["Security Hub ECS.8", "Well-Architected SEC02"],
        )
        self._task_finding(
            "ecs_task_logging", "logging", cells, resource, ref,
            bad=bool(no_log), severity=Severity.MEDIUM,
            issue="missing log configuration",
            bad_msg=f"Container(s) without a logConfiguration: {', '.join(no_log)}. "
            "Their output is not shipped anywhere for detection or investigation.",
            ok_msg="All containers have a log configuration.",
            fix="Add a logConfiguration (e.g. awslogs / awsfirelens) to every container.",
            refs=["Security Hub ECS.9", "Well-Architected SEC04"],
        )

    def _task_finding(self, check_id, cell_key, cells, resource, ref, *, bad,
                      severity, issue, bad_msg, ok_msg, fix, refs) -> None:
        """Emit one task-def PASS/FAIL finding and set its table cell.

        ``issue`` is a short noun phrase naming the check (e.g. "privileged
        container"); it drives clean, consistent titles in the JSON/HTML
        output ("Task definition web:9: privileged container").
        """
        cells[cell_key] = _FAIL if bad else _OK
        self._add(
            check_id=check_id,
            title=f"Task definition {ref}: {issue}" + ("" if bad else " OK"),
            severity=severity,
            status=Status.FAIL if bad else Status.PASS,
            resource=resource,
            detail=bad_msg if bad else ok_msg,
            recommendation=fix if bad else "",
            references=refs,
        )

    # ---- service checks --------------------------------------------------
    def _scan_service(self, region: str, cluster: str, svc: dict) -> None:
        """Check 8: the service auto-assigns public IPs to its tasks."""
        name = svc.get("serviceName", "?")
        resource = f"service:{region}/{cluster}/{name}"
        launch = svc.get("launchType") or (
            "CAP_PROVIDER" if svc.get("capacityProviderStrategy") else "-"
        )
        awsvpc = (svc.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
        assign = awsvpc.get("assignPublicIp")  # ENABLED / DISABLED / None
        public = assign == "ENABLED"
        cells = {
            "region": region,
            "cluster": cluster,
            "launch": launch,
            "public_ip": _FAIL if public else _OK,
        }
        self.service_rows.append((region, f"{cluster}/{name}", cells))
        self._add(
            check_id="ecs_service_public_ip",
            title=f"Service {name} "
            + ("auto-assigns public IPs" if public else "does not assign public IPs"),
            severity=Severity.MEDIUM,
            status=Status.FAIL if public else Status.PASS,
            resource=resource,
            detail="networkConfiguration sets assignPublicIp=ENABLED, so tasks get a "
            "public IP and are directly reachable from the internet."
            if public
            else "Tasks do not receive an auto-assigned public IP.",
            recommendation=""
            if not public
            else "Run tasks in private subnets behind a load balancer / NAT gateway and "
            "set assignPublicIp=DISABLED.",
            references=["Security Hub ECS.2", "Well-Architected SEC05"],
        )

    # ---- tables ----------------------------------------------------------
    def _task_table(self) -> Table:
        """Task-definition security: families as rows, checks as columns."""
        rows = [
            TableRow(
                label=ref,
                key=f"{region}/{ref}",
                cells=[cells.get(key, _ERR) for _, key in _TASK_COLUMNS],
            )
            for region, ref, cells in sorted(self.task_rows, key=lambda r: (r[0], r[1]))
        ]
        return Table(
            title="ECS task definition security",
            service=SERVICE,
            corner="Task definition",
            columns=[header for header, _ in _TASK_COLUMNS],
            rows=rows,
        )

    def _service_table(self) -> Table:
        """Service exposure: services as rows, with a PublicIP check column."""
        rows = [
            TableRow(
                label=ref.rsplit("/", 1)[-1],
                key=f"{region}/{ref}",
                cells=[cells.get(key, _ERR) for _, key in _SERVICE_COLUMNS],
            )
            for region, ref, cells in sorted(self.service_rows, key=lambda r: (r[0], r[1]))
        ]
        return Table(
            title="ECS service exposure",
            service=SERVICE,
            corner="Service",
            columns=[header for header, _ in _SERVICE_COLUMNS],
            rows=rows,
        )
