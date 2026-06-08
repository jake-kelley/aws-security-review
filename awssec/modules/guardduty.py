"""GuardDuty security checks.

A single check: **is GuardDuty actually on?** GuardDuty is Amazon's managed
threat-detection service, and it is enabled *per region* — each region has
its own "detector". A common blind spot is leaving it off in regions you
don't actively use, which is exactly where an attacker prefers to operate.

So this module enumerates every region enabled for the account and, for each
one, flags it when:

* there is no detector at all (GuardDuty never enabled there), or
* a detector exists but its status is not ``ENABLED`` (suspended/disabled).

All calls are read-only and covered by the AWS-managed ``SecurityAudit``
policy (``guardduty:ListDetectors`` / ``guardduty:GetDetector`` and
``ec2:DescribeRegions``).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core.finding import Finding, Severity, Status
from ..core.session import ScanContext

SERVICE = "guardduty"

# Severity when GuardDuty is missing/off: it's a core detection control, so a
# gap is serious but not directly exploitable on its own.
_SEVERITY = Severity.HIGH


def run(ctx: ScanContext) -> list[Finding]:
    """Entry point called by the CLI. Returns all GuardDuty findings."""
    return _GuardDutyScanner(ctx).scan()


class _GuardDutyScanner:
    """Checks GuardDuty enablement across every enabled region."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []

    # ---- orchestration -------------------------------------------------
    def scan(self) -> list[Finding]:
        """Check each region and return one finding per region."""
        for region in self._regions():
            self._check_region(region)
        return self.findings

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        """Append a Finding, stamping the service so callers don't repeat it."""
        self.findings.append(Finding(service=SERVICE, **kwargs))

    def _regions(self) -> list[str]:
        """List the regions enabled for this account.

        Uses EC2's ``describe_regions`` (rather than botocore's static region
        list) so we only check regions the account can actually use — opt-in
        regions that were never enabled are correctly skipped. Falls back to
        just the context region if the lookup fails.
        """
        try:
            ec2 = self.ctx.client("ec2")
            resp = ec2.describe_regions()  # default: only enabled regions
            return sorted(r["RegionName"] for r in resp["Regions"])
        except ClientError as err:
            self._add(
                check_id="guardduty_region_lookup",
                title="Could not list regions",
                severity=Severity.INFO,
                status=Status.ERROR,
                detail=f"ec2:DescribeRegions failed: "
                f"{err.response.get('Error', {}).get('Code', 'Unknown')}. "
                f"Falling back to {self.ctx.region} only.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return [self.ctx.region]

    # ---- the check -----------------------------------------------------
    def _check_region(self, region: str) -> None:
        """Emit a PASS/FAIL/ERROR finding for GuardDuty in one region."""
        # A region-specific client: GuardDuty state is per-region, so we must
        # ask each region individually rather than reuse the context client.
        gd = self.ctx.session.client("guardduty", region_name=region)

        try:
            detector_ids = gd.list_detectors().get("DetectorIds", [])
        except ClientError as err:
            self._add(
                check_id="guardduty_enabled",
                title="Could not check GuardDuty",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=region,
                detail=f"guardduty:ListDetectors failed in {region}: "
                f"{err.response.get('Error', {}).get('Code', 'Unknown')}.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return

        # No detector in this region => GuardDuty was never enabled here.
        if not detector_ids:
            self._add(
                check_id="guardduty_enabled",
                title="GuardDuty is not enabled",
                severity=_SEVERITY,
                status=Status.FAIL,
                resource=region,
                detail=f"No GuardDuty detector exists in {region}; threat detection is off "
                "in this region.",
                recommendation=f"Enable GuardDuty in {region} (enable it in every region you "
                "operate in, ideally all of them).",
                references=["CIS AWS Foundations Benchmark 3.x (GuardDuty)"],
            )
            return

        # A detector exists; confirm it is actually ENABLED (not suspended).
        # An account has at most one detector per region, so check the first.
        detector_id = detector_ids[0]
        try:
            status = gd.get_detector(DetectorId=detector_id).get("Status")
        except ClientError as err:
            self._add(
                check_id="guardduty_enabled",
                title="Could not check GuardDuty detector status",
                severity=Severity.INFO,
                status=Status.ERROR,
                resource=f"{region} ({detector_id})",
                detail=f"guardduty:GetDetector failed in {region}: "
                f"{err.response.get('Error', {}).get('Code', 'Unknown')}.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return

        if status == "ENABLED":
            self._add(
                check_id="guardduty_enabled",
                title="GuardDuty is enabled",
                severity=_SEVERITY,
                status=Status.PASS,
                resource=f"{region} ({detector_id})",
                detail=f"GuardDuty detector is ENABLED in {region}.",
            )
        else:
            # Detector present but suspended/disabled — effectively no detection.
            self._add(
                check_id="guardduty_enabled",
                title="GuardDuty detector is suspended/disabled",
                severity=_SEVERITY,
                status=Status.FAIL,
                resource=f"{region} ({detector_id})",
                detail=f"A GuardDuty detector exists in {region} but its status is "
                f"'{status}', so it is not actively monitoring.",
                recommendation=f"Re-enable the GuardDuty detector in {region}.",
                references=["CIS AWS Foundations Benchmark 3.x (GuardDuty)"],
            )
