"""S3 security checks.

Covers the current "big hitters" for S3 bucket security (all read-only,
runnable under the AWS-managed ``SecurityAudit`` policy):

1. Block Public Access disabled -- at the account level (the account-wide
   backstop) and per bucket
2. Buckets that are *effectively public* -- via the bucket policy (using
   AWS's own ``GetBucketPolicyStatus`` verdict) or via legacy ACL grants
   to AllUsers / AuthenticatedUsers
3. Bucket policies that Allow a wildcard (``*``) principal but are saved
   from being public by a Condition (worth a human look)
4. Encryption in transit not enforced: no policy statement denying
   non-TLS requests (``aws:SecureTransport``)
5. SSE-C (customer-provided keys) not blocked. Attackers with stolen
   credentials have encrypted buckets for ransom using SSE-C (the 2025
   "Codefinger" campaign) because AWS never stores the key. Since April
   2026 AWS disables SSE-C on new buckets by default, but buckets in
   accounts that ever used SSE-C can still allow it.
6. Default encryption configuration missing (rare since Jan 2023 -- every
   bucket gets SSE-S3 by default -- but cheap to confirm while we're
   reading the config anyway). SSE-S3 counts as a PASS; the algorithm is
   surfaced in the table (``S3`` / ``KMS`` / ``DSSE``).
7. Versioning not enabled -- the recovery path for deletion/overwrite
   attacks and accidents
8. Legacy ACLs still enabled (S3 Object Ownership is not
   "bucket owner enforced")

Design notes / known blind spots (kept deliberately simple):
* Policy checks pattern-match the bucket policy document. An SCP/RCP or
  VPC-endpoint policy elsewhere could tighten (or loosen) the effective
  result. The headline "public" verdict, however, comes from
  ``GetBucketPolicyStatus`` -- AWS's own analysis -- not our matching.
* Only bucket *configuration* is scanned. Object-level state (object
  ACLs, per-object encryption) and access points are not inspected.

Output: alongside the per-bucket findings (which drive ``--fail-on`` and
the JSON ``findings`` array), the module builds a :class:`Table` --
buckets as rows, checks as columns -- with ``OK`` / ``FAIL`` / ``PUBLIC``
/ ``-`` / ``ERR`` cell tokens (the Encrypt column shows the encryption
algorithm instead). The first row, ``(account)``, carries the
account-wide Block Public Access result in the BPA column.
"""

from __future__ import annotations

import json

from botocore.exceptions import ClientError

from ..core import policy as pol
from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "s3"

CIS = "CIS AWS Foundations Benchmark"

# Short status tokens used in the table cells (colored by the reporter).
_OK, _FAIL, _PUBLIC, _NA, _ERR = "OK", "FAIL", "PUBLIC", "-", "ERR"

# Table columns: (header, cell key). One column per check, in report order.
_COLUMNS = [
    ("Public", "public"),
    ("BPA", "bpa"),
    ("Wildcard", "wildcard"),
    ("TLS", "tls"),
    ("SSE-C", "ssec"),
    ("Encrypt", "encryption"),
    ("Version", "versioning"),
    ("ACLs", "acls"),
]

# The four Block Public Access flags; all must be true to pass (CIS 2.1.4).
_BPA_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)

# ACL grantee URIs that mean "the public". AuthenticatedUsers only requires
# *some* AWS account, so it is public for any practical threat model.
_PUBLIC_GRANTEE_SUFFIXES = ("/AllUsers", "/AuthenticatedUsers")

# Condition key a bucket policy uses to deny SSE-C uploads.
_SSEC_CONDITION_KEY = "s3:x-amz-server-side-encryption-customer-algorithm"

# Table cell token per default-encryption algorithm.
_ALGO_TOKEN = {"AES256": "S3", "aws:kms": "KMS", "aws:kms:dsse": "DSSE"}

# Sentinel: the API call succeeded but the configuration does not exist
# (e.g. no bucket policy). Distinct from None, which means the call failed.
_ABSENT = object()


def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus the coverage table."""
    return _S3Scanner(ctx).scan()


# ---------------------------------------------------------------------------
# Policy-document pattern helpers (module-private)
# ---------------------------------------------------------------------------
def _condition_entries(stmt: dict):
    """Yield ``(condition key, value)`` pairs across all condition operators.

    Flattens ``{"Bool": {"aws:SecureTransport": "false"}}``-style nesting so
    callers can look for a key without caring which operator wraps it.
    """
    cond = stmt.get("Condition")
    if not isinstance(cond, dict):
        return
    for operator_block in cond.values():
        if isinstance(operator_block, dict):
            yield from operator_block.items()


def _denies_insecure_transport(policy: dict) -> bool:
    """True if the policy has a Deny keyed on ``aws:SecureTransport: false``.

    This is the standard TLS-enforcement statement (CIS 2.1.1 / the AWS
    Config rule ``s3-bucket-ssl-requests-only``).
    """
    for stmt in pol.statements(policy):
        if stmt.get("Effect") != "Deny":
            continue
        for key, value in _condition_entries(stmt):
            if key.lower() == "aws:securetransport" and any(
                str(v).lower() == "false" for v in pol.as_list(value)
            ):
                return True
    return False


def _denies_ssec(policy: dict) -> bool:
    """True if the policy has a Deny conditioned on the SSE-C header key.

    Any Deny that references the key counts (AWS's recommended statements
    use ``Null`` or ``StringNotEquals`` operators; we accept either).
    """
    for stmt in pol.statements(policy):
        if stmt.get("Effect") != "Deny":
            continue
        for key, _ in _condition_entries(stmt):
            if key.lower() == _SSEC_CONDITION_KEY:
                return True
    return False


def _public_acl_grants(grants: list) -> list[str]:
    """Describe ACL grants made to the public grantee groups (empty = none)."""
    out = []
    for grant in grants or []:
        uri = (grant.get("Grantee") or {}).get("URI", "")
        if uri.endswith(_PUBLIC_GRANTEE_SUFFIXES):
            who = uri.rsplit("/", 1)[-1]
            out.append(f"{who}:{grant.get('Permission')}")
    return out


class _S3Scanner:
    """Checks account-wide S3 posture plus the configuration of every bucket."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # bucket name -> {column key: token}; powers the table built at the end.
        self.cells: dict[str, dict[str, str]] = {}
        self.account_bpa_token = _ERR
        self._clients: dict[str, object] = {}  # region -> s3 client

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check the account setting, then every bucket, then build the table."""
        self.ctx.progress.update("s3: account-level Block Public Access")
        self._check_account_public_access_block()
        self.ctx.progress.update("s3: listing buckets")
        buckets = self._list_buckets()
        if not buckets:
            # Make "nothing to scan" visible rather than an empty section.
            self._add(
                check_id="s3_buckets",
                title="No S3 buckets found",
                severity=Severity.INFO,
                status=Status.PASS,
                detail="ListBuckets returned no general purpose buckets.",
            )
        # ~7 read calls per bucket, so this is the slow part with many buckets;
        # surface each bucket name as it is checked.
        for i, (name, region) in enumerate(sorted(buckets), start=1):
            self.ctx.progress.update(f"s3: {name} ({i}/{len(buckets)})")
            self._scan_bucket(name, region)
        return ScanResult(findings=self.findings, tables=[self._build_table()])

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        """Append a Finding, stamping the service so callers don't repeat it."""
        self.findings.append(Finding(service=SERVICE, **kwargs))

    @staticmethod
    def _code(err: ClientError) -> str:
        return err.response.get("Error", {}).get("Code", "Unknown")

    def _client(self, region: str):
        """Return (and cache) an S3 client for ``region``.

        Bucket read APIs must be called in the bucket's own region, so one
        client per region is kept rather than a single global one.
        """
        if region not in self._clients:
            self._clients[region] = self.ctx.session.client("s3", region_name=region)
        return self._clients[region]

    def _fetch(self, errors: list[str], what: str, call, absent_codes: tuple = ()):
        """Run one read call with the module's three-way error handling.

        Returns the response dict on success, the ``_ABSENT`` sentinel when
        the error code just means "this configuration does not exist" (a
        normal, meaningful state), or None on any other failure -- which is
        recorded in ``errors`` for one rolled-up ERROR finding per bucket.
        """
        try:
            return call()
        except ClientError as err:
            code = self._code(err)
            if code in absent_codes:
                return _ABSENT
            errors.append(f"{what}: {code}")
            return None

    # ---- data loading --------------------------------------------------
    def _list_buckets(self) -> list[tuple[str, str]]:
        """List every general purpose bucket as ``(name, region)`` pairs.

        ListBuckets now returns each bucket's region directly; the
        GetBucketLocation fallback covers responses that omit it.
        """
        s3 = self._client(self.ctx.region)
        try:
            found = []
            for page in s3.get_paginator("list_buckets").paginate():
                for bucket in page.get("Buckets", []):
                    found.append((bucket["Name"], bucket.get("BucketRegion")))
        except ClientError as err:
            self._add(
                check_id="s3_bucket_scan",
                title="Could not list S3 buckets",
                severity=Severity.INFO,
                status=Status.ERROR,
                detail=f"s3:ListAllMyBuckets failed: {self._code(err)}.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return []
        return [(name, region or self._bucket_region(s3, name)) for name, region in found]

    def _bucket_region(self, s3, bucket: str) -> str:
        """Resolve a bucket's region via GetBucketLocation (legacy responses).

        The API returns None for us-east-1 and the literal "EU" for buckets
        created against the original eu-west-1 endpoint.
        """
        try:
            loc = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
        except ClientError:
            return self.ctx.region  # best effort; per-check calls may still work
        if not loc:
            return "us-east-1"
        if loc == "EU":
            return "eu-west-1"
        return loc

    # ---- account-level check --------------------------------------------
    def _check_account_public_access_block(self) -> None:
        """Account-wide Block Public Access (CIS 2.1.4 / Security Hub S3.1).

        This is the single highest-leverage S3 control: it overrides any
        bucket policy or ACL below it. Lives on the s3control API, not s3.
        """
        s3control = self.ctx.session.client("s3control", region_name=self.ctx.region)
        try:
            config = s3control.get_public_access_block(AccountId=self.ctx.account_id)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as err:
            if self._code(err) == "NoSuchPublicAccessBlockConfiguration":
                config = {}  # never configured => all four flags are off
            else:
                self.account_bpa_token = _ERR
                self._add(
                    check_id="s3_account_public_access_block",
                    title="Could not check account-level Block Public Access",
                    severity=Severity.INFO,
                    status=Status.ERROR,
                    resource=f"account:{self.ctx.account_id}",
                    detail=f"s3control GetPublicAccessBlock failed: {self._code(err)}.",
                    recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
                )
                return
        missing = [flag for flag in _BPA_FLAGS if not config.get(flag)]
        self.account_bpa_token = _FAIL if missing else _OK
        self._add(
            check_id="s3_account_public_access_block",
            title="Account-level S3 Block Public Access is "
            + ("incomplete" if missing else "fully enabled"),
            severity=Severity.HIGH,
            status=Status.FAIL if missing else Status.PASS,
            resource=f"account:{self.ctx.account_id}",
            detail=(
                f"Account-wide Block Public Access flags disabled: {', '.join(missing)}."
                if missing
                else "All four account-wide Block Public Access flags are enabled."
            ),
            recommendation=""
            if not missing
            else "Enable all four Block Public Access settings at the account level "
            "unless the account intentionally serves public buckets.",
            references=[f"{CIS} 2.1.4", "Security Hub S3.1"],
        )

    # ---- per-bucket scan -------------------------------------------------
    def _scan_bucket(self, name: str, region: str) -> None:
        """Run every bucket check and populate self.cells[name]."""
        cells: dict[str, str] = {}
        self.cells[name] = cells
        errors: list[str] = []
        s3 = self._client(region)
        resource = f"bucket:{name}"

        # One policy fetch feeds four checks (public / wildcard / TLS / SSE-C).
        resp = self._fetch(
            errors,
            "GetBucketPolicy",
            lambda: s3.get_bucket_policy(Bucket=name),
            absent_codes=("NoSuchBucketPolicy",),
        )
        policy_known = resp is not None  # False only when the call *failed*
        policy = None if resp in (None, _ABSENT) else json.loads(resp["Policy"])

        # AWS's own public/not-public verdict for the policy.
        resp = self._fetch(
            errors,
            "GetBucketPolicyStatus",
            lambda: s3.get_bucket_policy_status(Bucket=name),
            absent_codes=("NoSuchBucketPolicy",),
        )
        if resp is _ABSENT:
            policy_public = False  # no policy => cannot be public via policy
        elif resp is None:
            policy_public = None  # unknown
        else:
            policy_public = bool(resp["PolicyStatus"].get("IsPublic"))

        resp = self._fetch(errors, "GetBucketAcl", lambda: s3.get_bucket_acl(Bucket=name))
        acl_grants = None if resp is None else resp.get("Grants", [])

        # Default-encryption config feeds both encryption checks.
        resp = self._fetch(
            errors,
            "GetBucketEncryption",
            lambda: s3.get_bucket_encryption(Bucket=name),
            absent_codes=("ServerSideEncryptionConfigurationNotFoundError",),
        )
        if resp is _ABSENT:
            enc_rules = []  # bucket predates default encryption and has none
        elif resp is None:
            enc_rules = None  # unknown
        else:
            enc_rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])

        self._check_public(resource, cells, policy_public, acl_grants)
        self._check_bucket_public_access_block(s3, name, resource, cells, errors)
        self._check_wildcard_principal(resource, cells, policy, policy_known, policy_public)
        self._check_tls(resource, cells, policy, policy_known)
        self._check_ssec(resource, cells, enc_rules, policy, policy_known)
        self._check_encryption(resource, cells, enc_rules)
        self._check_versioning(s3, name, resource, cells, errors)
        self._check_ownership(s3, name, resource, cells, errors)

        # One rolled-up ERROR finding per bucket instead of one per failed call.
        if errors:
            self._add(
                check_id="s3_bucket_scan",
                title="Could not fully check bucket",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=resource,
                detail="; ".join(errors),
                recommendation="Ensure the caller has the AWS-managed SecurityAudit "
                "policy and the bucket policy does not deny it read access.",
            )

    # ---- checks ----------------------------------------------------------
    def _check_public(self, resource, cells, policy_public, acl_grants) -> None:
        """Check 2: is the bucket effectively public (policy and/or ACL)?"""
        if policy_public is not None:
            self._add(
                check_id="s3_bucket_public_policy",
                title="Bucket policy makes the bucket public"
                if policy_public
                else "Bucket policy is not public",
                severity=Severity.CRITICAL,
                status=Status.FAIL if policy_public else Status.PASS,
                resource=resource,
                detail="GetBucketPolicyStatus reports this bucket policy as public."
                if policy_public
                else "No bucket policy, or AWS evaluates it as not public.",
                recommendation=""
                if not policy_public
                else "Remove the public statements (or enable Block Public Access "
                "to override them) unless this bucket is meant to be public.",
                references=["Security Hub S3.2/S3.3"],
            )

        public_grants = _public_acl_grants(acl_grants) if acl_grants is not None else []
        if acl_grants is not None:
            self._add(
                check_id="s3_bucket_public_acl",
                title="Bucket ACL grants public access"
                if public_grants
                else "Bucket ACL has no public grants",
                severity=Severity.CRITICAL,
                status=Status.FAIL if public_grants else Status.PASS,
                resource=resource,
                detail=f"ACL grants: {', '.join(public_grants)}. AuthenticatedUsers "
                "means ANY AWS account, not just yours."
                if public_grants
                else "No grants to AllUsers or AuthenticatedUsers.",
                recommendation=""
                if not public_grants
                else "Remove the public ACL grants and disable ACLs entirely "
                "(Object Ownership: bucket owner enforced).",
                references=["Security Hub S3.2/S3.3"],
            )

        if policy_public or public_grants:
            cells["public"] = _PUBLIC
        elif policy_public is None or acl_grants is None:
            cells["public"] = _ERR  # at least one signal unknown, none positive
        else:
            cells["public"] = _OK

    def _check_bucket_public_access_block(self, s3, name, resource, cells, errors) -> None:
        """Check 1 (bucket half): all four Block Public Access flags on."""
        resp = self._fetch(
            errors,
            "GetPublicAccessBlock",
            lambda: s3.get_public_access_block(Bucket=name),
            absent_codes=("NoSuchPublicAccessBlockConfiguration",),
        )
        if resp is None:
            cells["bpa"] = _ERR
            return
        config = {} if resp is _ABSENT else resp["PublicAccessBlockConfiguration"]
        missing = [flag for flag in _BPA_FLAGS if not config.get(flag)]
        cells["bpa"] = _FAIL if missing else _OK
        self._add(
            check_id="s3_bucket_public_access_block",
            title="Bucket Block Public Access is "
            + ("incomplete" if missing else "fully enabled"),
            severity=Severity.HIGH,
            status=Status.FAIL if missing else Status.PASS,
            resource=resource,
            detail=f"Disabled flags: {', '.join(missing)}."
            if missing
            else "All four bucket-level Block Public Access flags are enabled.",
            recommendation=""
            if not missing
            else "Enable all four Block Public Access settings on the bucket "
            "(buckets created before April 2023 never got them by default).",
            references=[f"{CIS} 2.1.4", "Security Hub S3.8"],
        )

    def _check_wildcard_principal(self, resource, cells, policy, policy_known,
                                  policy_public) -> None:
        """Check 3: policy Allows a ``*`` principal (but isn't outright public).

        An unconditioned wildcard Allow makes GetBucketPolicyStatus report
        the bucket public, which check 2 already flags as CRITICAL -- so to
        avoid double-counting the same statement, a wildcard on a *public*
        bucket only shows in the table, not as a second finding. What this
        check reports is the conditioned case: technically not public, but
        one loose Condition away from it, so worth a human look.
        """
        if not policy_known:
            cells["wildcard"] = _ERR
            return
        wild = [s for s in pol.allow_statements(policy or {}) if pol.principal_is_wildcard(s)]
        cells["wildcard"] = _FAIL if wild else _OK
        if not wild:
            self._add(
                check_id="s3_bucket_wildcard_principal",
                title="Bucket policy has no wildcard principal",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                resource=resource,
                detail="No Allow statement with a '*' principal."
                if policy
                else "Bucket has no bucket policy.",
            )
            return
        if policy_public:
            return  # already reported as CRITICAL by the public-policy check
        has_condition = any(bool(s.get("Condition")) for s in wild)
        self._add(
            check_id="s3_bucket_wildcard_principal",
            title="Bucket policy allows a wildcard (*) principal",
            severity=Severity.MEDIUM if has_condition else Severity.HIGH,
            status=Status.FAIL,
            resource=resource,
            detail="An Allow statement grants access to Principal '*'"
            + (
                ", constrained only by a Condition (e.g. aws:SourceVpce / "
                "aws:SourceArn) -- verify the condition is sufficiently strict."
                if has_condition
                else " and AWS does not consider the policy public -- review it."
            ),
            recommendation="Prefer explicit principals (account IDs / role ARNs) "
            "over '*' with conditions.",
        )

    def _check_tls(self, resource, cells, policy, policy_known) -> None:
        """Check 4: policy denies non-TLS requests (aws:SecureTransport)."""
        if not policy_known:
            cells["tls"] = _ERR
            return
        enforced = policy is not None and _denies_insecure_transport(policy)
        cells["tls"] = _OK if enforced else _FAIL
        self._add(
            check_id="s3_bucket_tls_enforced",
            title="Encryption in transit is "
            + ("enforced" if enforced else "not enforced"),
            severity=Severity.MEDIUM,
            status=Status.PASS if enforced else Status.FAIL,
            resource=resource,
            detail="Bucket policy denies requests with aws:SecureTransport = false."
            if enforced
            else "No bucket policy statement denies plaintext (non-TLS) requests, "
            "so HTTP access is accepted.",
            recommendation=""
            if enforced
            else "Add a Deny statement on s3:* with condition "
            'Bool {"aws:SecureTransport": "false"} for the bucket and its objects.',
            references=[f"{CIS} 2.1.1", "Security Hub S3.5"],
        )

    def _check_ssec(self, resource, cells, enc_rules, policy, policy_known) -> None:
        """Check 5: SSE-C uploads are blocked (ransomware hardening).

        Two ways a bucket can block SSE-C, either counts as a pass:
        the encryption configuration's BlockedEncryptionTypes (the setting
        AWS started applying by default in April 2026), or a bucket-policy
        Deny on the SSE-C header condition key. An org-level RCP/SCP could
        also block it account-wide -- that is invisible here (documented
        limitation).
        """
        blocked_by_config = any(
            "SSE-C" in ((rule.get("BlockedEncryptionTypes") or {}).get("EncryptionType") or [])
            for rule in (enc_rules or [])
        )
        blocked_by_policy = policy is not None and _denies_ssec(policy)
        if blocked_by_config or blocked_by_policy:
            cells["ssec"] = _OK
            self._add(
                check_id="s3_bucket_ssec_blocked",
                title="SSE-C uploads are blocked",
                severity=Severity.MEDIUM,
                status=Status.PASS,
                resource=resource,
                detail="Blocked via "
                + ("the bucket encryption configuration." if blocked_by_config
                   else "a bucket policy Deny on the SSE-C condition key."),
            )
            return
        if enc_rules is None or not policy_known:
            cells["ssec"] = _ERR  # could not rule out either blocking mechanism
            return
        cells["ssec"] = _FAIL
        self._add(
            check_id="s3_bucket_ssec_blocked",
            title="SSE-C uploads are not blocked",
            severity=Severity.MEDIUM,
            status=Status.FAIL,
            resource=resource,
            detail="Neither the encryption configuration nor the bucket policy "
            "blocks SSE-C. An attacker with write credentials can encrypt "
            "objects with keys AWS never stores (2025 'Codefinger' ransomware).",
            recommendation="Block SSE-C in the bucket's default encryption "
            "configuration (BlockedEncryptionTypes) unless a workload needs it.",
            references=["AWS security bulletin: preventing unintended S3 encryption"],
        )

    def _check_encryption(self, resource, cells, enc_rules) -> None:
        """Check 6: a default encryption configuration exists.

        Every bucket has had SSE-S3 applied by default since Jan 2023, so a
        missing config is a rare legacy relic. SSE-S3 deliberately counts as
        a PASS; the algorithm lands in the table so KMS users can see it.
        """
        if enc_rules is None:
            cells["encryption"] = _ERR
            return
        algorithm = None
        for rule in enc_rules:
            default = rule.get("ApplyServerSideEncryptionByDefault")
            if default:
                algorithm = default.get("SSEAlgorithm")
                break
        if not algorithm:
            cells["encryption"] = _FAIL
            self._add(
                check_id="s3_bucket_encryption",
                title="Bucket has no default encryption configuration",
                severity=Severity.MEDIUM,
                status=Status.FAIL,
                resource=resource,
                detail="No default server-side encryption algorithm is configured "
                "(bucket predates the Jan 2023 encryption-by-default rollout).",
                recommendation="Set a default encryption configuration (SSE-S3 or SSE-KMS).",
                references=["Security Hub S3.17 (loosely)"],
            )
            return
        cells["encryption"] = _ALGO_TOKEN.get(algorithm, algorithm)
        self._add(
            check_id="s3_bucket_encryption",
            title="Default encryption is configured",
            severity=Severity.MEDIUM,
            status=Status.PASS,
            resource=resource,
            detail=f"Default server-side encryption algorithm: {algorithm}.",
        )

    def _check_versioning(self, s3, name, resource, cells, errors) -> None:
        """Check 7: versioning is enabled (deletion/overwrite recovery)."""
        resp = self._fetch(
            errors, "GetBucketVersioning", lambda: s3.get_bucket_versioning(Bucket=name)
        )
        if resp is None:
            cells["versioning"] = _ERR
            return
        status = resp.get("Status")  # None (never enabled) / Enabled / Suspended
        enabled = status == "Enabled"
        cells["versioning"] = _OK if enabled else _FAIL
        self._add(
            check_id="s3_bucket_versioning",
            title="Versioning is " + (status.lower() if status else "not enabled"),
            severity=Severity.MEDIUM,
            status=Status.PASS if enabled else Status.FAIL,
            resource=resource,
            detail="Object versions are retained; overwrites and deletes are recoverable."
            if enabled
            else (
                "Versioning was enabled but is now suspended."
                if status == "Suspended"
                else "Versioning has never been enabled."
            )
            + " Without versions, a bad overwrite or delete is unrecoverable.",
            recommendation=""
            if enabled
            else "Enable versioning (pair it with a lifecycle rule to expire "
            "noncurrent versions and control cost).",
            references=["Security Hub S3.14"],
        )

    def _check_ownership(self, s3, name, resource, cells, errors) -> None:
        """Check 8: Object Ownership is bucket-owner-enforced (ACLs disabled)."""
        resp = self._fetch(
            errors,
            "GetBucketOwnershipControls",
            lambda: s3.get_bucket_ownership_controls(Bucket=name),
            absent_codes=("OwnershipControlsNotFoundError",),
        )
        if resp is None:
            cells["acls"] = _ERR
            return
        if resp is _ABSENT:
            mode = None  # never configured => legacy behavior, ACLs active
        else:
            rules = resp.get("OwnershipControls", {}).get("Rules", [])
            mode = rules[0].get("ObjectOwnership") if rules else None
        enforced = mode == "BucketOwnerEnforced"
        cells["acls"] = _OK if enforced else _FAIL
        self._add(
            check_id="s3_bucket_acls_disabled",
            title="Legacy ACLs are " + ("disabled" if enforced else "still enabled"),
            severity=Severity.MEDIUM,
            status=Status.PASS if enforced else Status.FAIL,
            resource=resource,
            detail="Object Ownership is 'bucket owner enforced'; all access is policy-based."
            if enforced
            else f"Object Ownership is '{mode or 'not configured (ObjectWriter)'}' -- "
            "ACLs still grant access outside policy-based control.",
            recommendation=""
            if enforced
            else "Set Object Ownership to 'bucket owner enforced' to disable ACLs "
            "(AWS's recommendation for all modern use cases).",
            references=["Security Hub S3.12"],
        )

    # ---- table -----------------------------------------------------------
    def _build_table(self) -> Table:
        """Assemble the buckets-as-rows, checks-as-columns coverage grid.

        The first row carries the account-wide Block Public Access verdict
        (only the BPA column applies to it; the rest are ``-``).
        """
        account_row = TableRow(
            label="(account)",
            key="s3_account_public_access_block",
            cells=[self.account_bpa_token if key == "bpa" else _NA for _, key in _COLUMNS],
        )
        rows = [account_row] + [
            TableRow(
                label=bucket,
                key=bucket,
                cells=[self.cells[bucket].get(key, _ERR) for _, key in _COLUMNS],
            )
            for bucket in sorted(self.cells)
        ]
        return Table(
            title="S3 bucket security coverage",
            service=SERVICE,
            corner="Bucket",
            columns=[header for header, _ in _COLUMNS],
            rows=rows,
        )
