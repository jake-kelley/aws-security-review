"""Lambda security checks.

Covers the "big hitters" for Lambda function security (all read-only,
runnable under the AWS-managed ``SecurityAudit`` policy -- it grants
``lambda:GetPolicy`` and ``lambda:List*``, which is everything used
here). The selection follows AWS Security Hub controls and the
Well-Architected security pillar. Lambda is regional, so every enabled
region is scanned; the module file is ``lambda_.py`` only because
``lambda`` is a Python keyword -- the CLI name is still ``lambda``.

Per function:

1. Public resource-based policy -- an ``Allow`` to principal ``*``. With
   no Condition the function is invokable by anyone (CRITICAL); with a
   Condition it is one loose key away from public and worth a human look
   (MEDIUM, ``COND`` in the table).
2. Function URL without auth -- a URL with ``AuthType: NONE`` is an
   unauthenticated HTTPS endpoint straight into the function.
3. Deprecated (end-of-life) runtime -- no more security patches from
   AWS for the language runtime.
4. Secret-looking environment variable names -- plaintext env vars are
   readable by anyone with ``GetFunctionConfiguration``; names matching
   credential patterns (PASSWORD, SECRET, TOKEN, ...) suggest secrets
   that belong in Secrets Manager / SSM Parameter Store. Only the
   *names* are inspected and reported -- values are never printed.

Design notes / known blind spots (kept deliberately simple):
* The public-policy check only looks at wildcard principals. A service
  principal (e.g. ``s3.amazonaws.com``) without an ``aws:SourceAccount``
  / ``aws:SourceArn`` condition is a confused-deputy risk this module
  does not judge.
* The deprecated-runtime list is point-in-time (mid-2026); extend it as
  AWS deprecates more runtimes. Container-image functions expose no
  runtime to check and show ``-`` in the table.
* The env-var check is a name heuristic: names that look like pointers
  (ending in ARN, NAME, PATH, URL, ...) are excluded, but false
  positives/negatives are possible.

Output: alongside the per-function findings (which drive ``--fail-on``
and the JSON ``findings`` array), the module builds one table --
functions as rows, checks as columns. The Runtime column shows the
runtime id itself (like S3's Encrypt column) or ``EOL`` when deprecated.
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..core import policy as pol
from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.secrets import looks_like_secret_name
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "lambda"

# Short status tokens used in the table cells (colored by the reporter).
_OK, _FAIL, _PUBLIC, _COND, _OPEN, _EOL, _NA, _ERR = (
    "OK", "FAIL", "PUBLIC", "COND", "OPEN", "EOL", "-", "ERR",
)

# Table columns: (header, cell key). Region first so rows are self-describing.
_COLUMNS = [
    ("Region", "region"),
    ("Public", "public"),
    ("URL", "url"),
    ("Runtime", "runtime"),
    ("Secrets", "secrets"),
]

# Runtimes AWS has deprecated (no more patches; point-in-time as of mid-2026).
# Source: the Lambda runtime deprecation schedule. java8 is the Amazon Linux 1
# build -- java8.al2 is still supported; "provided" is the AL1 custom runtime.
_DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7", "python3.8", "python3.9",
    "nodejs", "nodejs4.3", "nodejs4.3-edge", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "nodejs18.x",
    "java8",
    "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1", "dotnetcore3.1",
    "dotnet5.0", "dotnet6", "dotnet7",
    "go1.x",
    "ruby2.5", "ruby2.7", "ruby3.2",
    "provided",
}

def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus the coverage table."""
    return _LambdaScanner(ctx).scan()


class _LambdaScanner:
    """Checks the configuration and resource policy of every Lambda function."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # (region, function name) -> {cell key: token}; powers the table.
        self.cells: dict[tuple[str, str], dict[str, str]] = {}

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check every function in every enabled region, then build the table."""
        regions = self._regions()
        for i, region in enumerate(regions, start=1):
            self.ctx.progress.update(f"lambda: {region} ({i}/{len(regions)})")
            self._scan_region(region)
        if not self.cells:
            # Make "nothing to scan" visible rather than a silently absent table.
            self._add(
                check_id="lambda_functions",
                title="No Lambda functions found",
                severity=Severity.INFO,
                status=Status.PASS,
                detail="ListFunctions returned no functions in any scanned region.",
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
                check_id="lambda_region_lookup",
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
        """List the region's functions and check each one."""
        client = self.ctx.session.client("lambda", region_name=region)
        try:
            functions = [
                f
                for page in client.get_paginator("list_functions").paginate()
                for f in page.get("Functions", [])
            ]
        except ClientError as err:
            self._add(
                check_id="lambda_region_scan",
                title="Could not list Lambda functions",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=region,
                detail=f"lambda:ListFunctions failed in {region}: {self._code(err)}.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return
        # Two API calls per function, so this is the slow part with big fleets;
        # surface each function name as it is checked.
        for cfg in functions:
            self.ctx.progress.update(f"lambda: {region}/{cfg.get('FunctionName', '?')}")
            self._scan_function(client, region, cfg)

    def _scan_function(self, client, region: str, cfg: dict) -> None:
        """Run all four checks for one function and record its table row."""
        name = cfg.get("FunctionName", "?")
        resource = f"function:{region}/{name}"
        cells: dict[str, str] = {"region": region}
        self.cells[(region, name)] = cells
        errors: list[str] = []

        self._check_public(client, name, resource, cells, errors)
        self._check_url_auth(client, name, resource, cells, errors)
        self._check_runtime(cfg, resource, cells)
        self._check_env_secrets(cfg, resource, cells)

        # One rolled-up ERROR finding per function instead of one per failed call.
        if errors:
            self._add(
                check_id="lambda_function_scan",
                title="Could not fully check function",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=resource,
                detail="; ".join(errors),
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )

    # ---- checks ----------------------------------------------------------
    def _check_public(self, client, name, resource, cells, errors) -> None:
        """Check 1: resource-based policy allows a wildcard (*) principal."""
        try:
            policy = json.loads(client.get_policy(FunctionName=name)["Policy"])
        except ClientError as err:
            if self._code(err) == "ResourceNotFoundException":
                policy = None  # no resource policy at all: cannot be public
            else:
                errors.append(f"GetPolicy: {self._code(err)}")
                cells["public"] = _ERR
                return
        wild = [s for s in pol.allow_statements(policy or {}) if pol.principal_is_wildcard(s)]
        unconditioned = [s for s in wild if not s.get("Condition")]
        if unconditioned:
            cells["public"] = _PUBLIC
            self._add(
                check_id="lambda_function_public",
                title="Function is publicly invokable",
                severity=Severity.CRITICAL,
                status=Status.FAIL,
                resource=resource,
                detail="The resource policy allows principal '*' with no Condition; "
                "anyone with an AWS account can invoke this function (and pay you "
                "the compute bill, or reach whatever it fronts).",
                recommendation="Replace the '*' principal with the specific accounts "
                "or services that need invoke access.",
                references=["Security Hub Lambda.1", "Well-Architected SEC03"],
            )
            return
        if wild:  # wildcard principal saved only by a Condition
            cells["public"] = _COND
            self._add(
                check_id="lambda_function_public",
                title="Function policy allows a wildcard (*) principal",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                resource=resource,
                detail="An Allow statement grants access to principal '*', "
                "constrained only by a Condition (e.g. aws:SourceArn / "
                "aws:SourceAccount) -- verify the condition is sufficiently strict.",
                recommendation="Prefer explicit principals over '*' with conditions.",
                references=["Security Hub Lambda.1"],
            )
            return
        cells["public"] = _OK
        self._add(
            check_id="lambda_function_public",
            title="Function is not publicly invokable",
            severity=Severity.CRITICAL,
            status=Status.PASS,
            resource=resource,
            detail="No Allow statement with a '*' principal."
            if policy
            else "Function has no resource-based policy.",
        )

    def _check_url_auth(self, client, name, resource, cells, errors) -> None:
        """Check 2: function URLs require IAM auth (AuthType != NONE)."""
        try:
            if client.can_paginate("list_function_url_configs"):
                configs = [
                    c
                    for page in client.get_paginator("list_function_url_configs").paginate(
                        FunctionName=name
                    )
                    for c in page.get("FunctionUrlConfigs", [])
                ]
            else:
                configs = client.list_function_url_configs(FunctionName=name).get(
                    "FunctionUrlConfigs", []
                )
        except ClientError as err:
            errors.append(f"ListFunctionUrlConfigs: {self._code(err)}")
            cells["url"] = _ERR
            return
        unauthenticated = [c for c in configs if c.get("AuthType") == "NONE"]
        if unauthenticated:
            cells["url"] = _OPEN
            self._add(
                check_id="lambda_url_auth",
                title="Function URL requires no authentication",
                severity=Severity.HIGH,
                status=Status.FAIL,
                resource=resource,
                detail=f"Function URL {unauthenticated[0].get('FunctionUrl', '?')} has "
                "AuthType NONE: it is an unauthenticated HTTPS endpoint anyone on "
                "the internet can call.",
                recommendation="Switch the URL to AuthType AWS_IAM, or front the "
                "function with API Gateway / an ALB that authenticates callers.",
                references=["Lambda function URL security", "Well-Architected SEC05"],
            )
            return
        cells["url"] = _OK if configs else _NA
        self._add(
            check_id="lambda_url_auth",
            title="Function URL is IAM-authenticated"
            if configs
            else "Function has no function URL",
            severity=Severity.HIGH,
            status=Status.PASS,
            resource=resource,
            detail="All function URL(s) use AuthType AWS_IAM."
            if configs
            else "No function URL is configured.",
        )

    def _check_runtime(self, cfg, resource, cells) -> None:
        """Check 3: the runtime still receives security patches from AWS."""
        runtime = cfg.get("Runtime")
        if not runtime:
            # Container-image function: the runtime lives inside the image,
            # which this tool cannot see. Shown as '-' with no finding.
            cells["runtime"] = _NA
            return
        deprecated = runtime in _DEPRECATED_RUNTIMES
        # The table shows the runtime id itself when supported (like S3's
        # Encrypt column) so the fleet's runtime spread is visible at a glance.
        cells["runtime"] = _EOL if deprecated else runtime
        self._add(
            check_id="lambda_runtime_supported",
            title=f"Runtime {runtime} is "
            + ("deprecated" if deprecated else "supported"),
            severity=Severity.MEDIUM,
            status=Status.FAIL if deprecated else Status.PASS,
            resource=resource,
            detail=f"'{runtime}' no longer receives security patches from AWS "
            "(and function updates on it are eventually blocked)."
            if deprecated
            else f"'{runtime}' is a supported runtime.",
            recommendation=""
            if not deprecated
            else "Migrate the function to a current runtime version.",
            references=["Security Hub Lambda.2"],
        )

    def _check_env_secrets(self, cfg, resource, cells) -> None:
        """Check 4: environment variable *names* that look like credentials.

        Values are deliberately never read or reported -- only the names.
        """
        names = ((cfg.get("Environment") or {}).get("Variables") or {})
        suspicious = sorted(n for n in names if looks_like_secret_name(n))
        cells["secrets"] = _FAIL if suspicious else _OK
        self._add(
            check_id="lambda_env_secrets",
            title="Environment variables "
            + ("look like credentials" if suspicious else "look credential-free"),
            severity=Severity.MEDIUM,
            status=Status.FAIL if suspicious else Status.PASS,
            resource=resource,
            detail=f"Variable name(s) suggest inline secrets: {', '.join(suspicious)}. "
            "Plaintext env vars are visible to anyone who can read the function "
            "configuration. (Values were not read by this tool.)"
            if suspicious
            else "No environment variable names match common credential patterns.",
            recommendation=""
            if not suspicious
            else "Store secrets in Secrets Manager or SSM Parameter Store and fetch "
            "them at runtime; keep only the secret's ARN/name in the environment.",
            references=["Well-Architected SEC02", "Lambda environment variable security"],
        )

    # ---- table -----------------------------------------------------------
    def _build_table(self) -> Table:
        """Assemble the functions-as-rows, checks-as-columns coverage grid."""
        rows = [
            TableRow(
                label=name,
                key=f"{region}/{name}",
                cells=[self.cells[(region, name)].get(key, _ERR) for _, key in _COLUMNS],
            )
            for region, name in sorted(self.cells)
        ]
        return Table(
            title="Lambda function security",
            service=SERVICE,
            corner="Function",
            columns=[header for header, _ in _COLUMNS],
            rows=rows,
        )
