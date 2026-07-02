"""boto3 session setup and small helpers shared by modules.

Centralizes two things every module needs: a configured boto3 session
(wrapped in :class:`ScanContext`) and a consistent way to recognize an
"access denied" error so a missing permission degrades gracefully instead
of aborting the scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

from .progress import Progress

# Error codes AWS returns when the caller lacks a permission. We treat these
# specially so a missing permission becomes a visible ERROR finding rather
# than crashing the whole scan.
ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}


@dataclass
class ScanContext:
    """Everything a module needs to talk to one AWS account."""

    session: boto3.Session
    account_id: str
    region: str
    profile: str | None = None
    # Progress sink for long scans. Disabled by default so modules can call
    # ``ctx.progress.update(...)`` unconditionally (and tests stay silent);
    # the CLI swaps in an auto-detecting one for real runs.
    progress: Progress = field(default_factory=lambda: Progress(enabled=False))
    # Cache for enabled_regions() (several modules need the same list).
    _regions: list[str] | None = field(default=None, init=False, repr=False)

    def client(self, service: str):
        """Return a boto3 client for ``service`` on this session."""
        return self.session.client(service, region_name=self.region)

    def enabled_regions(self) -> list[str]:
        """List the regions enabled for this account (sorted).

        Uses ``ec2:DescribeRegions``, which only returns regions the account
        has opted into, so disabled regions are never scanned. The result is
        cached because every all-regions module (EC2, Lambda, GuardDuty)
        needs it. Raises ``ClientError`` if the call fails; callers typically
        fall back to ``self.region`` and emit an ERROR finding.
        """
        if self._regions is None:
            resp = self.client("ec2").describe_regions()
            self._regions = sorted(r["RegionName"] for r in resp["Regions"])
        return self._regions


def build_context(profile: str | None = None, region: str | None = None) -> ScanContext:
    """Create a :class:`ScanContext`, resolving the account id via STS.

    Uses the standard boto3 credential chain (env vars, shared config,
    SSO, instance profile, ...). Raises if credentials are missing or the
    STS call fails, so the CLI can report a clear error.
    """
    session = boto3.Session(profile_name=profile, region_name=region)
    # get_caller_identity doubles as a credential check (it fails fast if the
    # session can't authenticate) and gives us the account id for reporting.
    sts = session.client("sts")
    ident = sts.get_caller_identity()
    # Fall back to us-east-1 only if neither the profile nor the flag set one;
    # IAM is global, so the exact region rarely matters for this tool.
    resolved_region = session.region_name or region or "us-east-1"
    return ScanContext(
        session=session,
        account_id=ident["Account"],
        region=resolved_region,
        profile=profile,
    )


def is_access_denied(error: ClientError) -> bool:
    """True if a botocore ClientError is a permissions problem."""
    return error.response.get("Error", {}).get("Code") in ACCESS_DENIED_CODES
