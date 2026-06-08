"""boto3 session setup and small helpers shared by modules."""

from __future__ import annotations

from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

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

    def client(self, service: str):
        """Return a boto3 client for ``service`` on this session."""
        return self.session.client(service, region_name=self.region)


def build_context(profile: str | None = None, region: str | None = None) -> ScanContext:
    """Create a :class:`ScanContext`, resolving the account id via STS.

    Uses the standard boto3 credential chain (env vars, shared config,
    SSO, instance profile, ...). Raises if credentials are missing or the
    STS call fails, so the CLI can report a clear error.
    """
    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client("sts")
    ident = sts.get_caller_identity()
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
