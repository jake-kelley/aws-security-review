"""GuardDuty security checks.

GuardDuty is Amazon's managed threat-detection service. It is enabled *per
region* (each region has its own "detector"), and a detector can have several
optional **protection features** turned on or off. This module reports, for
every region enabled on the account:

* ``guardduty_enabled``      - is GuardDuty on at all? (pass/fail, HIGH)
* ``guardduty_s3_protection``      - S3 Protection            (pass/fail)
* ``guardduty_runtime_monitoring`` - Runtime Monitoring       (status only)
* ``guardduty_eks_protection``     - EKS audit-log Protection (pass/fail)
* ``guardduty_rds_protection``     - RDS login Protection     (pass/fail)
* ``guardduty_lambda_protection``  - Lambda network Protection(pass/fail)

The feature statuses all come from the single ``get_detector`` call we already
make per region (its ``Features`` list), so there are no extra API calls.

Output: alongside the per-region findings (which drive ``--fail-on`` and the
JSON ``findings`` array), the module builds a :class:`Table` — checks as rows,
regions as columns — that the reporter prints on the console and embeds in the
JSON ``tables`` array.

All calls are read-only and covered by the AWS-managed ``SecurityAudit`` policy
(``guardduty:ListDetectors`` / ``guardduty:GetDetector`` and
``ec2:DescribeRegions``).
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from ..core.finding import Finding, ScanResult, Severity, Status
from ..core.session import ScanContext
from ..core.table import Table, TableRow

SERVICE = "guardduty"

# GuardDuty being off entirely is serious (no detection); an individual feature
# being off is a coverage gap but lower severity.
_ENABLED_SEVERITY = Severity.HIGH
_FEATURE_SEVERITY = Severity.MEDIUM

# Short status tokens used in the table cells (colored by the reporter).
_ON, _OFF, _SUSPENDED, _NA, _ERR = "ON", "OFF", "SUSPENDED", "-", "ERR"

# The five feature rows. Each maps a check_id to:
#   (row label, GuardDuty Features API name, is it pass/fail?)
# Runtime Monitoring is status-only (status_only=True): it is shown in the
# table but never emitted as a pass/fail finding.
_FEATURES = [
    ("guardduty_s3_protection", "S3 Protection", "S3_DATA_EVENTS", False),
    ("guardduty_runtime_monitoring", "Runtime Monitoring", "RUNTIME_MONITORING", True),
    ("guardduty_eks_protection", "EKS Protection", "EKS_AUDIT_LOGS", False),
    ("guardduty_rds_protection", "RDS Protection", "RDS_LOGIN_EVENTS", False),
    ("guardduty_lambda_protection", "Lambda Protection", "LAMBDA_NETWORK_LOGS", False),
]

# Row order for the table: GuardDuty Enabled first, then the five features.
_ROW_ORDER = [("guardduty_enabled", "GuardDuty Enabled")] + [
    (check_id, label) for check_id, label, _, _ in _FEATURES
]

# AWS Security Hub FSBP control that each check maps to (all under the
# Well-Architected SEC04 "detection" pillar). Used to build finding references.
_FEATURE_CONTROL = {
    "guardduty_s3_protection": "GuardDuty.10",
    "guardduty_runtime_monitoring": "GuardDuty.11",
    "guardduty_eks_protection": "GuardDuty.5",
    "guardduty_rds_protection": "GuardDuty.9",
    "guardduty_lambda_protection": "GuardDuty.6",
}
_ENABLED_REFERENCES = ["Security Hub GuardDuty.1", "Well-Architected SEC04"]


def run(ctx: ScanContext) -> ScanResult:
    """Entry point called by the CLI. Returns findings plus the coverage table."""
    return _GuardDutyScanner(ctx).scan()


class _GuardDutyScanner:
    """Checks GuardDuty enablement and feature coverage across every region."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx
        self.findings: list[Finding] = []
        # region -> {check_id: token}; powers the table built at the end.
        self.cells: dict[str, dict[str, str]] = {}

    # ---- orchestration -------------------------------------------------
    def scan(self) -> ScanResult:
        """Check each region, then assemble the region x check coverage table."""
        regions = self._regions()
        for i, region in enumerate(regions, start=1):
            self.ctx.progress.update(f"guardduty: {region} ({i}/{len(regions)})")
            self._scan_region(region)
        table = self._build_table(regions)
        return ScanResult(findings=self.findings, tables=[table])

    # ---- helpers -------------------------------------------------------
    def _add(self, **kwargs) -> None:
        """Append a Finding, stamping the service so callers don't repeat it."""
        self.findings.append(Finding(service=SERVICE, **kwargs))

    @staticmethod
    def _code(err: ClientError) -> str:
        return err.response.get("Error", {}).get("Code", "Unknown")

    def _regions(self) -> list[str]:
        """List the regions enabled for this account (sorted).

        Uses the shared (cached) ``ScanContext.enabled_regions()`` helper so
        only regions the account actually uses are checked. Falls back to the
        context region if that fails.
        """
        try:
            return self.ctx.enabled_regions()
        except ClientError as err:
            self._add(
                check_id="guardduty_region_lookup",
                title="Could not list regions",
                severity=Severity.INFO,
                status=Status.ERROR,
                detail=f"ec2:DescribeRegions failed: {self._code(err)}. "
                f"Falling back to {self.ctx.region} only.",
                recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
            )
            return [self.ctx.region]

    # ---- per-region scan ----------------------------------------------
    def _scan_region(self, region: str) -> None:
        """Populate self.cells[region] and emit findings for one region."""
        cells: dict[str, str] = {}
        self.cells[region] = cells
        gd = self.ctx.session.client("guardduty", region_name=region)

        # 1) Is there a detector at all?
        try:
            detector_ids = gd.list_detectors().get("DetectorIds", [])
        except ClientError as err:
            self._region_error(region, cells, f"guardduty:ListDetectors failed: {self._code(err)}")
            return

        if not detector_ids:
            # GuardDuty was never enabled here; features are not applicable.
            cells["guardduty_enabled"] = _OFF
            self._mark_features_na(cells)
            self._add(
                check_id="guardduty_enabled",
                title="GuardDuty is not enabled",
                severity=_ENABLED_SEVERITY,
                status=Status.FAIL,
                resource=region,
                detail=f"No GuardDuty detector exists in {region}; threat detection is off here.",
                recommendation=f"Enable GuardDuty in {region} (ideally in every region).",
                references=_ENABLED_REFERENCES,
            )
            return

        detector_id = detector_ids[0]  # at most one detector per region

        # 2) Read the detector (status + feature list) in one call.
        try:
            detector = gd.get_detector(DetectorId=detector_id)
        except ClientError as err:
            self._region_error(region, cells, f"guardduty:GetDetector failed: {self._code(err)}")
            return

        if detector.get("Status") != "ENABLED":
            # Detector exists but is suspended/disabled => effectively off.
            cells["guardduty_enabled"] = _SUSPENDED
            self._mark_features_na(cells)
            self._add(
                check_id="guardduty_enabled",
                title="GuardDuty detector is suspended/disabled",
                severity=_ENABLED_SEVERITY,
                status=Status.FAIL,
                resource=region,
                detail=f"A GuardDuty detector exists in {region} but its status is "
                f"'{detector.get('Status')}', so it is not actively monitoring.",
                recommendation=f"Re-enable the GuardDuty detector in {region}.",
                references=_ENABLED_REFERENCES,
            )
            return

        # 3) Detector is ENABLED: record the pass and evaluate each feature.
        cells["guardduty_enabled"] = _ON
        self._add(
            check_id="guardduty_enabled",
            title="GuardDuty is enabled",
            severity=_ENABLED_SEVERITY,
            status=Status.PASS,
            resource=region,
            detail=f"GuardDuty detector is ENABLED in {region} ({detector_id}).",
            references=_ENABLED_REFERENCES,
        )

        feature_status = {f["Name"]: f.get("Status") for f in detector.get("Features", [])}
        for check_id, label, feature_name, status_only in _FEATURES:
            self._eval_feature(region, cells, check_id, label, feature_name, status_only,
                               feature_status)

    def _eval_feature(self, region, cells, check_id, label, feature_name, status_only,
                      feature_status) -> None:
        """Set the table cell for one feature and emit its finding (if pass/fail)."""
        status = feature_status.get(feature_name)
        if status is None:
            # Feature not reported for this region/account => not applicable.
            cells[check_id] = _NA
            return

        enabled = status == "ENABLED"
        cells[check_id] = _ON if enabled else _OFF

        # Runtime Monitoring is reported as a status only — never a pass/fail.
        if status_only:
            return

        self._add(
            check_id=check_id,
            title=f"GuardDuty {label} is {'enabled' if enabled else 'disabled'}",
            severity=_FEATURE_SEVERITY,
            status=Status.PASS if enabled else Status.FAIL,
            resource=region,
            detail=f"{label} ({feature_name}) is {status} in {region}.",
            recommendation="" if enabled else f"Enable {label} on the GuardDuty detector in {region}.",
            references=[f"Security Hub {_FEATURE_CONTROL[check_id]}", "Well-Architected SEC04"],
        )

    def _region_error(self, region: str, cells: dict, message: str) -> None:
        """Handle a region whose GuardDuty calls failed (mark ERR, emit finding)."""
        cells["guardduty_enabled"] = _ERR
        self._mark_features_na(cells)
        self._add(
            check_id="guardduty_enabled",
            title="Could not check GuardDuty",
            severity=Severity.INFO,
            status=Status.ERROR,
            resource=region,
            detail=f"{message} in {region}.",
            recommendation="Ensure the caller has the AWS-managed SecurityAudit policy.",
        )

    @staticmethod
    def _mark_features_na(cells: dict) -> None:
        """Mark all feature cells not-applicable (used when the detector is off)."""
        for check_id, _, _, _ in _FEATURES:
            cells[check_id] = _NA

    # ---- table ---------------------------------------------------------
    def _build_table(self, regions: list[str]) -> Table:
        """Pivot the collected cells into a checks-as-rows, regions-as-columns grid."""
        rows = [
            TableRow(
                label=label,
                key=check_id,
                # Fall back to ERR if a region somehow produced no cell.
                cells=[self.cells.get(region, {}).get(check_id, _ERR) for region in regions],
            )
            for check_id, label in _ROW_ORDER
        ]
        return Table(
            title="GuardDuty coverage by region",
            service=SERVICE,
            corner="Check",
            columns=regions,
            rows=rows,
        )
