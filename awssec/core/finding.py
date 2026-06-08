"""The output contract shared by all modules: the :class:`Finding`.

A module's job is simply to produce a list of ``Finding`` objects. The
reporter knows how to render them (console or JSON). Keeping every check
funnelled through this one shape is what lets new service modules drop in
without touching the CLI or the reporter.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered so we can sort most-urgent-first (higher value = worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # noqa: D105 - trivial
        return self.name


class Status(enum.Enum):
    """Outcome of a single check against a single resource."""

    FAIL = "FAIL"  # a real problem was found
    PASS = "PASS"  # the check ran and the resource is fine
    ERROR = "ERROR"  # the check could not run (e.g. AccessDenied)

    def __str__(self) -> str:  # noqa: D105 - trivial
        return self.value


@dataclass
class Finding:
    """One observation about one resource.

    ``check_id`` is a stable, machine-friendly identifier (e.g.
    ``iam_root_mfa_enabled``) so downstream tooling can suppress or track
    specific checks. ``references`` typically holds CIS control numbers and
    doc links.
    """

    check_id: str  # stable id, e.g. "iam_root_mfa_enabled"
    title: str  # short human-readable headline
    service: str  # owning module, e.g. "iam"
    severity: Severity  # how bad it is if FAIL
    status: Status  # FAIL / PASS / ERROR
    resource: str = "-"  # what it's about (ARN, user name, ...); "-" if N/A
    detail: str = ""  # one or two sentences of explanation
    recommendation: str = ""  # how to fix it
    references: list[str] = field(default_factory=list)  # CIS ids, doc links

    def to_dict(self) -> dict:
        """Plain dict for the ``--json`` output."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "service": self.service,
            "severity": str(self.severity),
            "status": str(self.status),
            "resource": self.resource,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "references": self.references,
        }
