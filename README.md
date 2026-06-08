# aws-security-review (`awssec`)

A small, **read-only** scanner for common AWS security misconfigurations. It only
reads configuration and reports findings — it never changes your account.

Coverage is organized one module per service. **IAM** and **GuardDuty** ship
today; S3, EC2, Lambda, and access-key modules are planned and plug into the
same reporting contract.

## Quick start

Needs Python 3.9+ and AWS credentials for a principal with the AWS-managed
[`SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
policy.

```bash
pip install -r requirements.txt

python -m awssec                       # scan everything (default credentials)
python -m awssec --module iam          # one module
python -m awssec --profile audit       # a named profile
python -m awssec --json > findings.json  # machine-readable output
python -m awssec --fail-on HIGH        # exit non-zero for CI gating
```

Using [`uv`](https://docs.astral.sh/uv/) (no virtualenv needed):

```bash
uv run --no-project --with-requirements requirements.txt python -m awssec
```

> **Why `SecurityAudit`?** It's the only AWS-managed read-only policy that
> includes `iam:GenerateCredentialReport` and policy simulation, and it's a
> tighter least-privilege fit than the broad `ReadOnlyAccess`.
>
> **SSO / `aws login` users:** these auth providers need the `botocore[crt]`
> extra (already in `requirements.txt`). Without it you'll see *"Using the
> login credential provider requires an additional dependency."*

## Options

| Flag | Description |
|------|-------------|
| `--module NAME` | Limit to specific module(s); repeatable. Default: all. |
| `--profile NAME` | AWS named profile. |
| `--region NAME` | AWS region (defaults to profile/env region). |
| `--json` | Emit findings as JSON instead of the console report. |
| `--no-color` | Disable ANSI colors. |
| `--fail-on SEV` | Exit non-zero if any finding ≥ this severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |

## IAM checks

| check_id | Flags | Severity | CIS |
|----------|-------|----------|-----|
| `iam_root_mfa_enabled` | Root user without MFA | CRITICAL | 1.5/1.6 |
| `iam_root_access_keys` | Root user has access keys | CRITICAL | 1.4 |
| `iam_full_admin_policy` | Policy allowing `Action:*` on `Resource:*` | HIGH/MEDIUM | 1.16 |
| `iam_admin_access_attached` | Principal with `AdministratorAccess` attached | HIGH | 1.16 |
| `iam_access_key_age` | Active access key not rotated in > 90 days | MEDIUM | 1.14 |
| `iam_user_console_no_mfa` | Console password but no MFA | HIGH | 1.10 |
| `iam_passrole_wildcard` | `iam:PassRole` with `Resource:*` (privesc) | HIGH | — |
| `iam_trust_wildcard_principal` | Trust policy allowing a `*` principal | CRITICAL/MEDIUM | — |
| `iam_guardduty_tamper` | Policy that can disable/hide GuardDuty | HIGH | — |

**How it works:** credential-report checks (root, key age, console-no-MFA) come
from one `get_credential_report` call; policy checks scan the JSON of every
customer-managed and inline policy for dangerous patterns.

**Limitations (by design):** policy checks match patterns rather than resolving
*effective* permissions, so an SCP, permission boundary, or explicit `Deny`
could make a finding moot. `NotAction` / `NotResource` aren't interpreted. The
IAM `iam_guardduty_tamper` check flags who *can* tamper with GuardDuty; whether
GuardDuty is actually on is covered by the GuardDuty module below.

## GuardDuty checks

| check_id | Flags | Severity | CIS |
|----------|-------|----------|-----|
| `guardduty_enabled` | No GuardDuty detector, or a suspended/disabled one, in any enabled region | HIGH | 3.x |

GuardDuty is enabled per-region, so this module enumerates every region enabled
for the account (`ec2:DescribeRegions`) and reports one result per region. The
state of **every** region is shown: regions with a problem appear under
`FINDINGS`, and regions where GuardDuty is healthy are listed (compactly) under
`PASSED`. The `--json` output includes one entry per region with its status.

## Layout

```
awssec/
  cli.py            # arg parsing, orchestration, exit codes
  core/
    finding.py      # Finding dataclass + Severity/Status (output contract)
    session.py      # boto3 session + ScanContext + access-denied helper
    policy.py       # policy-document helpers (wildcards, action matching)
    report.py       # console (ANSI) + JSON reporters
  modules/
    iam.py          # the IAM checks
    guardduty.py    # GuardDuty enablement (all regions)
```

A check that can't run (e.g. missing permission) is reported as an `ERROR`
finding instead of crashing the scan.
