# aws-security-review (`awssec`)

A small, read-only scanner for common AWS security misconfigurations and bad
practices. It is designed to run with **nothing more than the AWS-managed
[`SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
policy** — no write access required.

The tool is organized as one module per service so coverage can grow over
time. The first module is **IAM**; S3, EC2, Lambda, GuardDuty, and access-key
modules are planned and plug into the same `Finding` / reporter contract.

## Requirements

- Python 3.9+
- `boto3` (`pip install -r requirements.txt`)
- AWS credentials for a principal with the **`SecurityAudit`** managed policy.

> Why `SecurityAudit` and not `ReadOnlyAccess`? `SecurityAudit` is the only
> AWS-managed read-only policy that includes `iam:GenerateCredentialReport`
> and policy simulation, and it is a much tighter least-privilege fit for an
> auditor than the very broad `ReadOnlyAccess`. `ViewOnlyAccess` is too narrow
> (it lacks `GetCredentialReport`).

## Install & run

```bash
# from the repo root
pip install -r requirements.txt

# scan every module against the default credential chain
python -m awssec

# only IAM, using a named profile and region
python -m awssec --module iam --profile audit --region us-east-1

# machine-readable output for pipelines / CI
python -m awssec --json > findings.json

# fail a CI job if any HIGH-or-worse finding exists
python -m awssec --fail-on HIGH
```

If you use [`uv`](https://docs.astral.sh/uv/) (no venv needed):

```bash
uv run --no-project --with-requirements requirements.txt python -m awssec
```

> If your profile authenticates via AWS SSO or the `aws login` (`login_session`)
> credential provider, you need the `botocore[crt]` extra — it's already listed
> in `requirements.txt`. Without it boto3 raises
> *"Using the login credential provider requires an additional dependency"*.

### Options

| Flag | Description |
|------|-------------|
| `--module NAME` | Limit to specific module(s); repeatable. Default: all. |
| `--profile NAME` | AWS named profile. |
| `--region NAME` | AWS region (defaults to profile/env region). |
| `--json` | Emit findings as JSON instead of the console report. |
| `--no-color` | Disable ANSI colors. |
| `--fail-on SEV` | Exit non-zero if any FAIL finding ≥ this severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |

## IAM checks (module: `iam`)

| check_id | What it flags | Severity | Reference |
|----------|---------------|----------|-----------|
| `iam_root_mfa_enabled` | Root user without MFA | CRITICAL | CIS 1.5/1.6 |
| `iam_root_access_keys` | Root user has access keys | CRITICAL | CIS 1.4 |
| `iam_full_admin_policy` | Customer-managed/inline policy allowing `Action:*` on `Resource:*` | HIGH/MEDIUM | CIS 1.16 |
| `iam_admin_access_attached` | Principal with the AWS-managed `AdministratorAccess` attached | HIGH | CIS 1.16 |
| `iam_access_key_age` | Active access key not rotated in > 90 days | MEDIUM | CIS 1.14 |
| `iam_user_console_no_mfa` | IAM user with a console password but no MFA (password-only sign-in) | HIGH | CIS 1.10 |
| `iam_passrole_wildcard` | `iam:PassRole` granted with `Resource:*` (privilege-escalation path) | HIGH | — |
| `iam_trust_wildcard_principal` | Role trust policy allowing a `*` principal (CRITICAL with no `Condition`, MEDIUM if conditioned) | CRITICAL/MEDIUM | — |
| `iam_guardduty_tamper` | Policy granting GuardDuty disable/archive/delete actions (detection evasion) | HIGH | — |

### How findings are produced

- **Credential-report checks** (`root`, key age, console-no-MFA) come from a
  single `generate_credential_report` / `get_credential_report` call.
- **Policy-pattern checks** (`full_admin`, `passrole`, `guardduty_tamper`)
  inspect the JSON of every customer-managed policy (default version) and
  every inline policy on users/roles/groups. They match dangerous patterns
  rather than resolving effective permissions.

### Known limitations (by design, for simplicity)

- Pattern checks **do not resolve effective permissions** — an SCP, permission
  boundary, or explicit `Deny` elsewhere could make a flagged statement moot.
- `NotAction` / `NotResource` statements are **not interpreted** and may be
  under-reported.
- The GuardDuty check looks at *who has the permission* in a policy document;
  it does not check whether GuardDuty is actually enabled (that will be a
  dedicated GuardDuty module).

## Project layout

```
awssec/
  cli.py            # argument parsing, orchestration, exit codes
  core/
    finding.py      # the Finding dataclass + Severity/Status (output contract)
    session.py      # boto3 session + ScanContext + access-denied helper
    policy.py       # policy-document helpers (wildcards, action matching)
    report.py       # console (ANSI) + JSON reporters
  modules/
    iam.py          # the IAM checks
```

Findings that cannot run (e.g. a missing permission) are reported as
`ERROR` status rather than crashing the scan, so partial-permission runs
still produce useful output.
