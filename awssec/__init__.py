"""awssec — a simple, read-only AWS security misconfiguration scanner.

Runs with the AWS-managed ``SecurityAudit`` policy and flags common
misconfigurations and bad practices across AWS services. The first module
covers IAM; more services (S3, EC2, Lambda, GuardDuty, ...) plug in the
same way.
"""

__version__ = "0.1.0"
