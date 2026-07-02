# aws-security-review (`awssec`)

A small, **read-only** scanner for common AWS security misconfigurations. It only
reads configuration and reports findings — it never changes your account.

Coverage is organized one module per service. **IAM**, **S3**, and
**GuardDuty** ship today; EC2 and Lambda modules are planned and plug into
the same reporting contract.

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

## S3 checks

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `s3_account_public_access_block` | Account-wide Block Public Access not fully on | HIGH | CIS 2.1.4 |
| `s3_bucket_public_access_block` | Bucket Block Public Access not fully on | HIGH | CIS 2.1.4 |
| `s3_bucket_public_policy` | Bucket policy makes the bucket public (AWS's own `GetBucketPolicyStatus` verdict) | CRITICAL | S3.2/S3.3 |
| `s3_bucket_public_acl` | ACL grants to AllUsers / AuthenticatedUsers | CRITICAL | S3.2/S3.3 |
| `s3_bucket_wildcard_principal` | Policy `Allow` with `Principal:*` that isn't outright public (condition-constrained) | HIGH/MEDIUM | — |
| `s3_bucket_tls_enforced` | No `Deny` of non-TLS requests (`aws:SecureTransport`) | MEDIUM | CIS 2.1.1 |
| `s3_bucket_ssec_blocked` | SSE-C uploads not blocked (2025 "Codefinger" ransomware vector) | MEDIUM | — |
| `s3_bucket_encryption` | No default encryption config (pre-2023 relic; SSE-S3 counts as a pass) | MEDIUM | — |
| `s3_bucket_versioning` | Versioning not enabled or suspended | MEDIUM | S3.14 |
| `s3_bucket_acls_disabled` | Legacy ACLs still enabled (Object Ownership not "bucket owner enforced") | MEDIUM | S3.12 |

**How it works:** one `ListBuckets` plus ~7 read calls per bucket (policy,
policy status, ACL, encryption, Block Public Access, versioning, ownership),
each issued against the bucket's own region. The account-wide Block Public
Access setting is read once via the `s3control` API.

Results are rendered as a **coverage table** — buckets as rows, checks as
columns — with `OK` / `FAIL` / `PUBLIC` / `-` / `ERR` cell tokens (the
Encrypt column shows the default-encryption algorithm instead: `S3` / `KMS` /
`DSSE`). The first row, `(account)`, carries the account-wide Block Public
Access result in the BPA column. Per-bucket pass/fail findings still drive
`--fail-on` and the JSON `findings` array.

**Limitations (by design):** bucket *configuration* only — object ACLs,
per-object encryption, and access points aren't inspected. Policy checks
pattern-match the bucket policy document, so an SCP/RCP elsewhere could
change the effective result (the headline "public" verdict, however, is
AWS's own analysis, not ours). A bucket whose policy denies reads to the
auditor shows as `ERR` cells plus one rolled-up ERROR finding.

## GuardDuty checks

| check_id | Flags | Severity |
|----------|-------|----------|
| `guardduty_enabled` | No GuardDuty detector, or a suspended/disabled one | HIGH |
| `guardduty_s3_protection` | S3 Protection disabled | MEDIUM |
| `guardduty_runtime_monitoring` | Runtime Monitoring (reported as status only, never a fail) | — |
| `guardduty_eks_protection` | EKS (audit log) Protection disabled | MEDIUM |
| `guardduty_rds_protection` | RDS (login) Protection disabled | MEDIUM |
| `guardduty_lambda_protection` | Lambda (network) Protection disabled | MEDIUM |

GuardDuty is enabled per-region, so this module enumerates every region enabled
for the account (`ec2:DescribeRegions`) and checks the detector plus its
protection features in each one (all from a single `get_detector` call per
region). Feature checks are only evaluated where a detector is actually enabled;
elsewhere they show as not-applicable (`-`).

Results are rendered as a **coverage table** — checks as rows, regions as
columns — on the console and in the `--json` output (`tables` array). Cell
tokens: `ON` (enabled), `OFF` (disabled), `SUSPENDED` (detector present but not
monitoring), `-` (not applicable), `ERR` (call failed). The underlying per-region
pass/fail findings are still in the JSON `findings` array and drive `--fail-on`.

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
    s3.py           # S3 bucket security (public access, TLS, SSE-C, ...)
    guardduty.py    # GuardDuty enablement (all regions)
```

A check that can't run (e.g. missing permission) is reported as an `ERROR`
finding instead of crashing the scan.
