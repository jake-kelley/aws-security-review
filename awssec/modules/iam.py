"""IAM security checks.

Implements the following checks (all read-only, runnable under the
AWS-managed ``SecurityAudit`` policy):

1. Root account MFA enabled / root access keys present
2. Overly broad permissions (Allow on Action:* + Resource:*, incl. the
   AWS-managed ``AdministratorAccess`` policy being attached)
3. Long-lived access keys (older than 90 days)
4. Password-only IAM users (console password enabled, MFA not active)
5. Excessive ``iam:PassRole`` (granted with a wildcard resource)
6. Wildcard principal (``*``) on a role's trust policy
7. Permissions that let a principal tamper with / delete GuardDuty

Design notes / known blind spots (kept deliberately simple):
* Checks 2/5/7 inspect policy *documents* for dangerous patterns. They do
  not resolve effective permissions, so a deny elsewhere (SCP, permission
  boundary, explicit Deny) could make a flagged statement moot. This is the
  documented trade-off of the pattern-matching approach.
* ``NotAction`` / ``NotResource`` are not interpreted (treated as not
  matching). Statements using them may be under-reported.
"""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from ..core import policy as pol
from ..core.finding import Finding, Severity, Status
from ..core.session import ScanContext, is_access_denied

SERVICE = "iam"

ACCESS_KEY_MAX_AGE_DAYS = 90

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

# High-signal actions that let a principal disable GuardDuty or hide findings.
GUARDDUTY_TAMPER_ACTIONS = [
    "guardduty:DeleteDetector",
    "guardduty:UpdateDetector",
    "guardduty:DeleteMembers",
    "guardduty:DisassociateFromMasterAccount",
    "guardduty:DisassociateFromAdministratorAccount",
    "guardduty:StopMonitoringMembers",
    "guardduty:ArchiveFindings",
    "guardduty:UpdateFindingsFeedback",
    "guardduty:CreateFilter",
    "guardduty:DeletePublishingDestination",
    "guardduty:UpdatePublishingDestination",
]

CIS = "CIS AWS Foundations Benchmark"


@dataclass
class _PolicyDoc:
    """A policy document plus where it came from, for reporting."""

    label: str  # e.g. "customer-managed policy" / "inline policy"
    resource: str  # ARN or "user:alice / policy:AdminInline"
    document: dict
    attached: bool = True  # is it actually attached to a principal?
    extra: str = ""  # free-text note (e.g. attachment count)


def run(ctx: ScanContext) -> list[Finding]:
    """Entry point called by the CLI. Returns all IAM findings."""
    scanner = _IamScanner(ctx)
    return scanner.scan()


class _IamScanner:
    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.iam = ctx.client("iam")
        self.findings: list[Finding] = []

    # ---- orchestration -------------------------------------------------
    def scan(self) -> list[Finding]:
        report = self._load_credential_report()
        self._check_root_account(report)
        self._check_access_key_age(report)
        self._check_password_only_users(report)

        identity_policies = self._collect_identity_policies()
        self._check_broad_permissions(identity_policies)
        self._check_passrole(identity_policies)
        self._check_guardduty_tampering(identity_policies)

        self._check_trust_policy_wildcard()
        return self.findings

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        self.findings.append(Finding(service=SERVICE, **kwargs))

    def _error(self, check_id: str, what: str, err: ClientError) -> None:
        """Record that a check could not run (usually missing permission)."""
        code = err.response.get("Error", {}).get("Code", "Unknown")
        self._add(
            check_id=check_id,
            title=f"Could not check {what}",
            severity=Severity.INFO,
            status=Status.ERROR,
            detail=f"{what}: {code} ({err.response.get('Error', {}).get('Message', '')})",
            recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
        )

    @staticmethod
    def _parse_dt(value: str):
        """Parse a credential-report timestamp; None for sentinel strings."""
        if not value or value in ("N/A", "no_information", "not_supported"):
            return None
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None

    @staticmethod
    def _age_days(when: datetime) -> int:
        return (datetime.now(timezone.utc) - when).days

    # ---- data loading --------------------------------------------------
    def _load_credential_report(self) -> list[dict] | None:
        """Generate (if needed) and parse the IAM credential report.

        Returns a list of row dicts, or None if it could not be retrieved.
        """
        try:
            for _ in range(15):
                state = self.iam.generate_credential_report()["State"]
                if state == "COMPLETE":
                    break
                time.sleep(2)
            content = self.iam.get_credential_report()["Content"]
        except ClientError as err:
            self._error("iam_credential_report", "the IAM credential report", err)
            return None
        rows = list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
        return rows

    def _collect_identity_policies(self) -> list[_PolicyDoc]:
        """Gather customer-managed and inline policy documents."""
        docs: list[_PolicyDoc] = []
        docs.extend(self._collect_customer_managed())
        docs.extend(self._collect_inline_policies())
        return docs

    def _collect_customer_managed(self) -> list[_PolicyDoc]:
        docs: list[_PolicyDoc] = []
        try:
            paginator = self.iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for p in page["Policies"]:
                    version = self.iam.get_policy_version(
                        PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"]
                    )
                    docs.append(
                        _PolicyDoc(
                            label="customer-managed policy",
                            resource=p["Arn"],
                            document=version["PolicyVersion"]["Document"],
                            attached=p.get("AttachmentCount", 0) > 0,
                            extra=f"attached to {p.get('AttachmentCount', 0)} entities",
                        )
                    )
        except ClientError as err:
            self._error("iam_policy_scan", "customer-managed policies", err)
        return docs

    def _collect_inline_policies(self) -> list[_PolicyDoc]:
        docs: list[_PolicyDoc] = []
        # (list_call, response_key, list_inline_call, get_call, id_key, label)
        kinds = [
            ("list_users", "Users", "list_user_policies", "get_user_policy", "UserName", "user"),
            ("list_roles", "Roles", "list_role_policies", "get_role_policy", "RoleName", "role"),
            ("list_groups", "Groups", "list_group_policies", "get_group_policy", "GroupName", "group"),
        ]
        for list_call, response_key, list_inline, get_call, id_key, label in kinds:
            try:
                for page in self.iam.get_paginator(list_call).paginate():
                    for item in page[response_key]:
                        name = item[id_key]
                        for ip in self.iam.get_paginator(list_inline).paginate(**{id_key: name}):
                            for pname in ip["PolicyNames"]:
                                doc = getattr(self.iam, get_call)(
                                    **{id_key: name, "PolicyName": pname}
                                )
                                docs.append(
                                    _PolicyDoc(
                                        label="inline policy",
                                        resource=f"{label}:{name} / policy:{pname}",
                                        document=doc["PolicyDocument"],
                                    )
                                )
            except ClientError as err:
                self._error("iam_inline_scan", f"inline policies on {label}s", err)
        return docs

    # ---- checks --------------------------------------------------------
    def _check_root_account(self, report: list[dict] | None) -> None:
        try:
            summary = self.iam.get_account_summary()["SummaryMap"]
        except ClientError as err:
            self._error("iam_root_account", "the root account summary", err)
            return

        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        keys_present = summary.get("AccountAccessKeysPresent", 0) == 1

        self._add(
            check_id="iam_root_mfa_enabled",
            title="Root account MFA is disabled",
            severity=Severity.CRITICAL,
            status=Status.FAIL if not mfa_enabled else Status.PASS,
            resource=f"root ({self.ctx.account_id})",
            detail="The root user does not have MFA enabled."
            if not mfa_enabled
            else "Root MFA is enabled.",
            recommendation="Enable a (preferably hardware) MFA device on the root user.",
            references=[f"{CIS} 1.5/1.6"],
        )
        self._add(
            check_id="iam_root_access_keys",
            title="Root account has access keys",
            severity=Severity.CRITICAL,
            status=Status.FAIL if keys_present else Status.PASS,
            resource=f"root ({self.ctx.account_id})",
            detail="The root user has active access keys."
            if keys_present
            else "Root user has no access keys.",
            recommendation="Delete all root access keys; use IAM principals or Identity Center instead.",
            references=[f"{CIS} 1.4"],
        )

    def _check_access_key_age(self, report: list[dict] | None) -> None:
        if report is None:
            return
        for row in report:
            if row.get("user") == "<root_account>":
                continue
            for idx in ("1", "2"):
                if row.get(f"access_key_{idx}_active") != "true":
                    continue
                rotated = self._parse_dt(row.get(f"access_key_{idx}_last_rotated", ""))
                if rotated is None:
                    continue
                age = self._age_days(rotated)
                if age > ACCESS_KEY_MAX_AGE_DAYS:
                    self._add(
                        check_id="iam_access_key_age",
                        title="Access key older than 90 days",
                        severity=Severity.MEDIUM,
                        status=Status.FAIL,
                        resource=f"user:{row['user']} key#{idx}",
                        detail=f"Access key has not been rotated in {age} days.",
                        recommendation="Rotate the access key and retire the old one.",
                        references=[f"{CIS} 1.14"],
                    )

    def _check_password_only_users(self, report: list[dict] | None) -> None:
        if report is None:
            return
        for row in report:
            if row.get("user") == "<root_account>":
                continue
            password_enabled = row.get("password_enabled") == "true"
            mfa_active = row.get("mfa_active") == "true"
            if password_enabled and not mfa_active:
                self._add(
                    check_id="iam_user_console_no_mfa",
                    title="IAM user has console access but no MFA",
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    resource=f"user:{row['user']}",
                    detail="Console password is enabled but no MFA device is active "
                    "(password-only sign-in).",
                    recommendation="Require an MFA device for every user with console access.",
                    references=[f"{CIS} 1.10"],
                )

    def _check_broad_permissions(self, docs: list[_PolicyDoc]) -> None:
        # 2a: policy documents that allow Action:* on Resource:*
        for d in docs:
            for stmt in pol.allow_statements(d.document):
                if pol.has_wildcard_action(stmt) and pol.has_wildcard_resource(stmt):
                    self._add(
                        check_id="iam_full_admin_policy",
                        title="Policy grants full administrative access (Action:* on Resource:*)",
                        severity=Severity.HIGH if d.attached else Severity.MEDIUM,
                        status=Status.FAIL,
                        resource=d.resource,
                        detail=f"{d.label} contains an Allow of Action '*' on Resource '*'. "
                        + (d.extra or ""),
                        recommendation="Scope the policy to only the actions and resources required.",
                        references=[f"{CIS} 1.16"],
                    )
                    break  # one finding per policy is enough

        # 2b: principals with the AWS-managed AdministratorAccess attached
        try:
            entities = self.iam.get_paginator("list_entities_for_policy").paginate(
                PolicyArn=ADMIN_POLICY_ARN
            )
            for page in entities:
                attached = (
                    [f"user:{u['UserName']}" for u in page.get("PolicyUsers", [])]
                    + [f"group:{g['GroupName']}" for g in page.get("PolicyGroups", [])]
                    + [f"role:{r['RoleName']}" for r in page.get("PolicyRoles", [])]
                )
                for ent in attached:
                    self._add(
                        check_id="iam_admin_access_attached",
                        title="AWS-managed AdministratorAccess is attached",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        resource=ent,
                        detail="Principal has the AWS-managed AdministratorAccess policy "
                        "(full Action:* / Resource:*).",
                        recommendation="Replace with a least-privilege policy unless full admin is required.",
                        references=[f"{CIS} 1.16"],
                    )
        except ClientError as err:
            self._error("iam_admin_access_attached", "AdministratorAccess attachments", err)

    def _check_passrole(self, docs: list[_PolicyDoc]) -> None:
        for d in docs:
            for stmt in pol.allow_statements(d.document):
                if pol.grants_any(stmt, ["iam:PassRole"]) and pol.has_wildcard_resource(stmt):
                    self._add(
                        check_id="iam_passrole_wildcard",
                        title="iam:PassRole allowed on any role (Resource:*)",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        resource=d.resource,
                        detail=f"{d.label} allows iam:PassRole with Resource '*', so the principal "
                        "can pass ANY role to a service (a common privilege-escalation path).",
                        recommendation="Restrict PassRole to the specific role ARNs that may be passed.",
                        references=["Privilege escalation (Cloudsplaining/PMapper)"],
                    )
                    break

    def _check_guardduty_tampering(self, docs: list[_PolicyDoc]) -> None:
        for d in docs:
            for stmt in pol.allow_statements(d.document):
                matched = pol.grants_any(stmt, GUARDDUTY_TAMPER_ACTIONS)
                if matched:
                    self._add(
                        check_id="iam_guardduty_tamper",
                        title="Policy can disable or tamper with GuardDuty",
                        severity=Severity.HIGH,
                        status=Status.FAIL,
                        resource=d.resource,
                        detail=f"{d.label} grants: {', '.join(matched)}. These allow disabling "
                        "GuardDuty or hiding/archiving findings (detection evasion).",
                        recommendation="Remove GuardDuty write/delete actions from this policy; "
                        "restrict them to a dedicated security-operations role.",
                        references=["Detection evasion"],
                    )
                    break

    def _check_trust_policy_wildcard(self) -> None:
        try:
            for page in self.iam.get_paginator("list_roles").paginate():
                for role in page["Roles"]:
                    trust = role.get("AssumeRolePolicyDocument") or {}
                    for stmt in pol.allow_statements(trust):
                        if not pol.principal_is_wildcard(stmt):
                            continue
                        has_condition = bool(stmt.get("Condition"))
                        self._add(
                            check_id="iam_trust_wildcard_principal",
                            title="Role trust policy allows a wildcard (*) principal",
                            severity=Severity.MEDIUM if has_condition else Severity.CRITICAL,
                            status=Status.FAIL,
                            resource=role["Arn"],
                            detail="Trust policy allows Principal '*'"
                            + (
                                " but is constrained by a Condition (verify it is sufficiently "
                                "restrictive, e.g. sts:ExternalId / aws:SourceArn)."
                                if has_condition
                                else " with NO Condition — anyone can assume this role."
                            ),
                            recommendation="Restrict the trust policy to specific account IDs / "
                            "principal ARNs, and add a Condition such as sts:ExternalId.",
                            references=["Confused-deputy / public role assumption"],
                        )
                        break
        except ClientError as err:
            self._error("iam_trust_wildcard_principal", "role trust policies", err)
