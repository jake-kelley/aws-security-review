"""awssec — a simple, read-only AWS security misconfiguration scanner.

Runs with the AWS-managed ``SecurityAudit`` policy and flags common
misconfigurations and bad practices across AWS services. IAM, S3, and
GuardDuty modules ship today; more services (EC2, Lambda, ...) plug in
the same way.
"""

__version__ = "0.2.0"
