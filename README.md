# aws-security-review (`awssec`)

A small, **read-only** scanner for common AWS security misconfigurations. It only
reads configuration and reports findings — it never changes your account.

Coverage is organized one module per service: **IAM**, **S3**, **EC2**,
**Lambda**, **ECS**, **EKS**, and **GuardDuty**. Results render as a colorized
console report, machine-readable **JSON** (`--json`), or a self-contained
**HTML** report for review (`--html`). New modules plug into the same reporting
contract.

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
python -m awssec --html report.html    # self-contained HTML report for review
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
| `--json` | Emit findings as JSON to stdout instead of the console report. |
| `--html [PATH]` | Write a self-contained HTML report to `PATH` (default `awssec-report.html`). Mutually exclusive with `--json`. |
| `--no-color` | Disable ANSI colors. |
| `--fail-on SEV` | Exit non-zero if any finding ≥ this severity (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`). |

While a scan runs interactively, a one-line live status (current module /
region / bucket / function) is shown and continuously overwritten on
**stderr** — so it never mixes into the report or `--json` output, and it
disappears entirely when stderr is redirected or the scan runs in CI.

## Output formats

Three ways to consume a scan; all cover the same findings and coverage tables:

- **Console** (default) — a colorized report: failures first (severity-sorted,
  with detail and fix), then passing checks, the module coverage tables, and
  any checks that errored out.
- **JSON** (`--json`) — the full findings array, per-run metadata, a severity
  rollup, and the coverage tables, printed to stdout for piping or CI.
- **HTML** (`--html [PATH]`) — a self-contained file (styles inlined, no
  external assets, opens offline) with a summary chip row, severity-grouped
  finding cards, colored coverage grids, and a collapsible list of passing
  checks. Handy for sharing a review or attaching it to a ticket.

Every finding carries a stable `check_id`, a severity, and a resource, so the
JSON output is easy to diff, suppress, or feed into other tooling. `--fail-on`
gates CI on severity regardless of the chosen format.

## Reference key

The last column of each check table links to the standard the check maps to:

- **CIS x.y** → the [CIS AWS Foundations Benchmark][cis] (control numbers; the
  benchmark itself is a free PDF download).
- **`S3.x` / `EC2.x` / `Lambda.x` / `ECS.x` / `EKS.x` / `GuardDuty.x`** → the
  matching [AWS Security Hub][sh-s3-1] Foundational Security Best Practices
  control.
- **`SECxx`** → the corresponding [AWS Well-Architected][wa-sec05] security-pillar
  question.

A "—" means the check maps to none of these (it's driven by a privilege-escalation
path, an AWS security bulletin, or the tool's own synthesis). The same references
appear in each finding's `references` field in the JSON/HTML output.

## IAM checks

| check_id | Flags | Severity | CIS |
|----------|-------|----------|-----|
| `iam_root_mfa_enabled` | Root user without MFA | CRITICAL | [1.5/1.6][cis] |
| `iam_root_access_keys` | Root user has access keys | CRITICAL | [1.4][cis] |
| `iam_full_admin_policy` | Policy allowing `Action:*` on `Resource:*` | HIGH/MEDIUM | [1.16][cis] |
| `iam_admin_access_attached` | Principal with `AdministratorAccess` attached | HIGH | [1.16][cis] |
| `iam_access_key_age` | Active access key not rotated in > 90 days | MEDIUM | [1.14][cis] |
| `iam_user_console_no_mfa` | Console password but no MFA | HIGH | [1.10][cis] |
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
| `s3_account_public_access_block` | Account-wide Block Public Access not fully on | HIGH | [CIS 2.1.4][cis], [S3.1][sh-s3-1] |
| `s3_bucket_public_access_block` | Bucket Block Public Access not fully on | HIGH | [CIS 2.1.4][cis], [S3.8][sh-s3-8] |
| `s3_bucket_public_policy` | Bucket policy makes the bucket public (AWS's own `GetBucketPolicyStatus` verdict) | CRITICAL | [S3.2][sh-s3-2]/[S3.3][sh-s3-3] |
| `s3_bucket_public_acl` | ACL grants to AllUsers / AuthenticatedUsers | CRITICAL | [S3.2][sh-s3-2]/[S3.3][sh-s3-3] |
| `s3_bucket_wildcard_principal` | Policy `Allow` with `Principal:*` that isn't outright public (condition-constrained) | HIGH/MEDIUM | — |
| `s3_bucket_tls_enforced` | No `Deny` of non-TLS requests (`aws:SecureTransport`) | MEDIUM | [CIS 2.1.1][cis], [S3.5][sh-s3-5] |
| `s3_bucket_ssec_blocked` | SSE-C uploads not blocked (2025 "Codefinger" ransomware vector) | MEDIUM | — |
| `s3_bucket_encryption` | No default encryption config (pre-2023 relic; SSE-S3 counts as a pass) | MEDIUM | [S3.17][sh-s3-17] |
| `s3_bucket_versioning` | Versioning not enabled or suspended | MEDIUM | [S3.14][sh-s3-14] |
| `s3_bucket_acls_disabled` | Legacy ACLs still enabled (Object Ownership not "bucket owner enforced") | MEDIUM | [S3.12][sh-s3-12] |

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

## EC2 checks

Big hitters from CIS, Security Hub, and the Well-Architected security pillar.
EC2 is regional, so **every enabled region is scanned**.

Region-level:

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `ec2_public_snapshots` | EBS snapshot restorable by *anyone* | CRITICAL | [EC2.1][sh-ec2-1], [SEC08][wa-sec08] |
| `ec2_public_amis` | AMI shared with all AWS accounts | HIGH | [SEC08][wa-sec08] |
| `ec2_sg_open_admin_ports` | Security group allows SSH/RDP (or all traffic) from `0.0.0.0/0` / `::/0` | HIGH (attached) / MEDIUM (dormant) | [CIS 5.2/5.3][cis], [EC2.13][sh-ec2-13]/[EC2.14][sh-ec2-14], [SEC05][wa-sec05] |
| `ec2_default_sg_restricts_traffic` | Default security group still has rules | MEDIUM (in use) / LOW | [CIS 5.4][cis], [EC2.2][sh-ec2-2] |
| `ec2_ebs_default_encryption` | EBS encryption-by-default off for the region | MEDIUM | [CIS 2.2.1][cis], [EC2.7][sh-ec2-7], [SEC08][wa-sec08] |

Per instance (stopped instances are checked too; terminated ones skipped):

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `ec2_imdsv2_required` | IMDSv1 still answers (`HttpTokens` ≠ `required`; disabled endpoint counts as a pass) | HIGH | [CIS 5.6][cis], [EC2.8][sh-ec2-8], [SEC06][wa-sec06] |
| `ec2_instance_public_ip` | Instance has a public IPv4 address | MEDIUM | [EC2.9][sh-ec2-9], [SEC05][wa-sec05] |
| `ec2_instance_ebs_encrypted` | An attached EBS volume is unencrypted | MEDIUM | [EC2.3][sh-ec2-3], [SEC08][wa-sec08] |
| `ec2_instance_exposed_admin_port` | Public IP **and** an attached SG opening admin ports — directly attackable (FAIL-only synthesis of the two) | HIGH | [SEC05][wa-sec05] |

**How it works:** ~6 bulk describe calls per region (instances, security
groups, network interfaces, volumes, snapshots, images) plus
`GetEbsEncryptionByDefault`. Public snapshots come from a single
`DescribeSnapshots RestorableByUserIds=all` call — no per-snapshot attribute
lookups. SG findings are attachment-aware: an offending group bound to a
network interface is HIGH, a dormant one MEDIUM.

Results are rendered as **two coverage tables**: a region-posture grid
(checks × regions, like GuardDuty) and an instance grid (instances × checks,
like S3). Tokens: `OK` / `FAIL` / `OPEN` / `ON` / `OFF` / `-` / `ERR`.

**Limitations (by design):** SG exposure is judged from SG rules only —
routing (private subnets), NACLs, and firewalls aren't consulted, which is
also why the attached+public-IP synthesis check exists. "Admin ports" means
22/3389 (or an all-traffic rule); intentionally public ports like 80/443 are
not judged.

## Lambda checks

Per function, in **every enabled region** (the module file is `lambda_.py`
only because `lambda` is a Python keyword — the CLI name is `lambda`):

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `lambda_function_public` | Resource policy `Allow` to principal `*` — unconditioned means anyone can invoke; condition-constrained is `COND` in the table | CRITICAL / MEDIUM | [Lambda.1][sh-lambda-1], [SEC03][wa-sec03] |
| `lambda_url_auth` | Function URL with `AuthType: NONE` (unauthenticated HTTPS endpoint) | HIGH | [SEC05][wa-sec05] |
| `lambda_runtime_supported` | Deprecated (end-of-life) runtime — no more AWS security patches | MEDIUM | [Lambda.2][sh-lambda-2] |
| `lambda_env_secrets` | Environment variable **names** matching credential patterns (`PASSWORD`, `SECRET`, `TOKEN`, ...) | MEDIUM | [SEC02][wa-sec02] |

**How it works:** one `ListFunctions` per region plus `GetPolicy` and
`ListFunctionUrlConfigs` per function. Rendered as a coverage table —
functions as rows; the Runtime column shows the runtime id itself (`EOL` when
deprecated, `-` for container-image functions whose runtime is invisible).

**Limitations (by design):** the env-var check is a name heuristic — values
are **never read or reported**, and pointer-style names (`*_ARN`, `*_NAME`,
`*_URL`, ...) are excluded as the recommended pattern. The deprecated-runtime
list is point-in-time (mid-2026). Service principals without
`aws:SourceAccount`/`aws:SourceArn` conditions (confused deputy) aren't judged.

## ECS checks

Big hitters from AWS Security Hub's ECS controls and the Well-Architected
security pillar. ECS is regional, so **every enabled region is scanned**. The
security-rich surface is the **task definition**; a task definition fails a
check if *any* of its containers does.

Per task definition (latest active revision of each family):

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `ecs_task_privileged` | A container runs `privileged: true` (host device access → escape = host root) | HIGH | [ECS.4][sh-ecs-4], [SEC06][wa-sec06] |
| `ecs_task_host_network` | `networkMode: host` (shares host network, bypasses awsvpc isolation) | HIGH | [ECS.17][sh-ecs-17], [SEC05][wa-sec05] |
| `ecs_task_host_pid` | `pidMode: host` (can see/signal every host process) | HIGH | [ECS.3][sh-ecs-3], [SEC06][wa-sec06] |
| `ecs_task_readonly_rootfs` | A container's root filesystem is writable | MEDIUM | [ECS.5][sh-ecs-5], [SEC06][wa-sec06] |
| `ecs_task_nonroot_user` | A container runs as root (or no `user` set) | MEDIUM | [ECS.20][sh-ecs-20], [SEC06][wa-sec06] |
| `ecs_task_env_secrets` | Plaintext env var **names** look like secrets (should use `secrets`/valueFrom) | HIGH | [ECS.8][sh-ecs-8], [SEC02][wa-sec02] |
| `ecs_task_logging` | A container has no `logConfiguration` | MEDIUM | [ECS.9][sh-ecs-9], [SEC04][wa-sec04] |

Per service:

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `ecs_service_public_ip` | `assignPublicIp: ENABLED` (tasks get a public IP) | MEDIUM | [ECS.2][sh-ecs-2], [SEC05][wa-sec05] |

**How it works:** per region, `ListTaskDefinitions` (newest-first, deduped to
the latest revision of each family) + `DescribeTaskDefinition` each, and
`ListClusters` → `ListServices` → `DescribeServices` (batched by 10). Rendered
as two tables — a task-definition grid (families × the 7 checks) and a service
grid (services × PublicIP, with Cluster/Launch as context columns).

**Limitations (by design):** only the latest active revision per family is
inspected (old revisions don't flood the report), and the task definition is
read — not the running image or its runtime behavior. Env-var **values are
never read or reported** (name heuristic only, shared with Lambda). Container
Insights and platform-version currency are out of scope (operational, not
security big-hitters).

## EKS checks

Control-plane security for every EKS cluster, in **every enabled region**
(one `DescribeCluster` per cluster):

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `eks_endpoint_public` | API endpoint public to `0.0.0.0/0` (FAIL). Public but CIDR-restricted is a PASS flagged `COND` for review | HIGH / MEDIUM | [EKS.1][sh-eks-1], [SEC05][wa-sec05] |
| `eks_version_supported` | Kubernetes version below the standard-support floor (1.33; point-in-time) | MEDIUM | [EKS.2][sh-eks-2] |
| `eks_secrets_encryption` | No `encryptionConfig` for `secrets` (no KMS envelope encryption) | MEDIUM | [EKS.3][sh-eks-3], [SEC08][wa-sec08] |
| `eks_audit_logging` | Control-plane `audit` log type not enabled | MEDIUM | [EKS.8][sh-eks-8], [SEC04][wa-sec04] |

Rendered as a coverage table — clusters as rows; the Version column shows the
version string itself (`EOL` when unsupported) and the Endpoint column shows
`OPEN` (internet-facing) / `COND` (restricted-public) / `OK` (private).

**Limitations (by design):** control-plane configuration only — node groups,
Fargate profiles, in-cluster RBAC, network policies, and add-ons are the
Kubernetes API's domain, not an AWS-config scanner's. The supported-version
floor is point-in-time — `_MIN_SUPPORTED_K8S` in `eks.py` tracks the Security
Hub `EKS.2` `oldestVersionSupported` value (1.33 as of mid-2026); refresh it
against the EKS version calendar.

## GuardDuty checks

| check_id | Flags | Severity | Ref |
|----------|-------|----------|-----|
| `guardduty_enabled` | No GuardDuty detector, or a suspended/disabled one | HIGH | [GuardDuty.1][sh-gd-1], [SEC04][wa-sec04] |
| `guardduty_s3_protection` | S3 Protection disabled | MEDIUM | [GuardDuty.10][sh-gd-10], [SEC04][wa-sec04] |
| `guardduty_runtime_monitoring` | Runtime Monitoring (reported as status only, never a fail) | — | [GuardDuty.11][sh-gd-11], [SEC04][wa-sec04] |
| `guardduty_eks_protection` | EKS (audit log) Protection disabled | MEDIUM | [GuardDuty.5][sh-gd-5], [SEC04][wa-sec04] |
| `guardduty_rds_protection` | RDS (login) Protection disabled | MEDIUM | [GuardDuty.9][sh-gd-9], [SEC04][wa-sec04] |
| `guardduty_lambda_protection` | Lambda (network) Protection disabled | MEDIUM | [GuardDuty.6][sh-gd-6], [SEC04][wa-sec04] |

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
    secrets.py      # shared secret-looking-name heuristic (Lambda + ECS)
    progress.py     # transient stderr status line for long scans
    report.py       # console (ANSI) + JSON + HTML reporters
  modules/
    iam.py          # the IAM checks
    s3.py           # S3 bucket security (public access, TLS, SSE-C, ...)
    ec2.py          # EC2 posture (IMDSv2, open SGs, public snapshots/AMIs, ...)
    lambda_.py      # Lambda function security (public policy, URLs, runtimes)
    ecs.py          # ECS task-definition + service security
    eks.py          # EKS control-plane security (endpoint, logging, encryption)
    guardduty.py    # GuardDuty enablement (all regions)
```

A check that can't run (e.g. missing permission) is reported as an `ERROR`
finding instead of crashing the scan.

<!-- Reference links for the check tables above. -->
[cis]: https://www.cisecurity.org/benchmark/amazon_web_services
[wa-sec02]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-02.html
[wa-sec03]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-03.html
[wa-sec04]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-04.html
[wa-sec05]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-05.html
[wa-sec06]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-06.html
[wa-sec08]: https://docs.aws.amazon.com/wellarchitected/latest/framework/sec-08.html
[sh-s3-1]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-1
[sh-s3-2]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-2
[sh-s3-3]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-3
[sh-s3-5]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-5
[sh-s3-8]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-8
[sh-s3-12]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-12
[sh-s3-14]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-14
[sh-s3-17]: https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html#s3-17
[sh-ec2-1]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-1
[sh-ec2-2]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-2
[sh-ec2-3]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-3
[sh-ec2-7]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-7
[sh-ec2-8]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-8
[sh-ec2-9]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-9
[sh-ec2-13]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-13
[sh-ec2-14]: https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html#ec2-14
[sh-lambda-1]: https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-1
[sh-lambda-2]: https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html#lambda-2
[sh-ecs-2]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-2
[sh-ecs-3]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-3
[sh-ecs-4]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-4
[sh-ecs-5]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-5
[sh-ecs-8]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-8
[sh-ecs-9]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-9
[sh-ecs-17]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-17
[sh-ecs-20]: https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html#ecs-20
[sh-eks-1]: https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-1
[sh-eks-2]: https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-2
[sh-eks-3]: https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-3
[sh-eks-8]: https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html#eks-8
[sh-gd-1]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-1
[sh-gd-5]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-5
[sh-gd-6]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-6
[sh-gd-9]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-9
[sh-gd-10]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-10
[sh-gd-11]: https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html#guardduty-11
