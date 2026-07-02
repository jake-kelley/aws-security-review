"""Render findings to the terminal (colorized) or as JSON.

Zero extra dependencies: colors are plain ANSI escape codes, auto-disabled
when output is not a TTY, when ``NO_COLOR`` is set, or when ``--no-color``
is passed. On Windows we enable virtual-terminal processing so the codes
render in the standard console.
"""

from __future__ import annotations

import json
import os
import sys

from .finding import Finding, Severity, Status
from .table import Table

# ---------------------------------------------------------------------------
# ANSI color palette
# ---------------------------------------------------------------------------
# Raw escape sequences; "\033[" starts a code, the trailing "m" ends it.
# Every colored string is wrapped with _RESET so color never bleeds onward.
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

# Map each severity / status to the escape code used to highlight it.
_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[97;41m",  # white on red
    Severity.HIGH: "\033[91m",  # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[94m",  # blue
    Severity.INFO: "\033[90m",  # grey
}
_STATUS_COLOR = {
    Status.FAIL: "\033[91m",
    Status.PASS: "\033[92m",
    Status.ERROR: "\033[95m",
}

# Color for the short status tokens used inside tables (see table.py).
_TOKEN_COLOR = {
    "ON": "\033[92m",  # green  - enabled / pass
    "OK": "\033[92m",  # green  - check passed
    "OFF": "\033[91m",  # red    - disabled / fail
    "FAIL": "\033[91m",  # red    - check failed
    "PUBLIC": "\033[97;41m",  # white on red - bucket is publicly accessible
    "SUSPENDED": "\033[93m",  # yellow - detector present but not monitoring
    "ERR": "\033[95m",  # magenta- could not read
    "-": _DIM,  # grey   - not applicable
    "N/A": _DIM,
}


def _enable_windows_ansi() -> None:
    """Best-effort enable of ANSI escape handling on legacy Windows consoles."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # 0x0004 = ENABLE_VIRTUAL_TERMINAL_PROCESSING on the stdout handle (-11).
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _color_enabled(no_color: bool) -> bool:
    """Decide whether to emit color.

    Off if the user opted out (``--no-color`` or the ``NO_COLOR`` convention)
    or if stdout is redirected to a file/pipe (not a TTY) — that keeps
    ``--json`` output and piped reports free of escape codes.
    """
    if no_color or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


class Reporter:
    """Formats a finished scan for humans (console) or machines (JSON)."""

    def __init__(self, no_color: bool = False):
        self.use_color = _color_enabled(no_color)
        if self.use_color:
            _enable_windows_ansi()

    def _c(self, text: str, code: str) -> str:
        """Wrap ``text`` in a color code (or return it unchanged if color off)."""
        if not self.use_color:
            return text
        return f"{code}{text}{_RESET}"

    # ----- JSON ---------------------------------------------------------
    def to_json(
        self,
        findings: list[Finding],
        metadata: dict,
        tables: list[Table] | None = None,
    ) -> str:
        """Serialize findings + tables + run metadata + a rollup summary as JSON."""
        counts = self._counts(findings)
        payload = {
            "metadata": metadata,
            "summary": {
                "total": len(findings),
                "by_status": {str(k): v for k, v in counts["status"].items()},
                "by_severity": {str(k): v for k, v in counts["severity"].items()},
            },
            "findings": [f.to_dict() for f in findings],
            "tables": [t.to_dict() for t in (tables or [])],
        }
        return json.dumps(payload, indent=2, default=str)

    # ----- Console ------------------------------------------------------
    def to_console(
        self,
        findings: list[Finding],
        metadata: dict,
        tables: list[Table] | None = None,
    ) -> str:
        """Build the human-readable report as a single string.

        Layout: a header (which account/region/profile), the failures
        (severity-sorted, full detail), the passing checks (compact, one line
        each so per-resource state stays visible), any module tables, any
        checks that errored out, then a one-line summary.

        Findings whose service is represented by a table are *not* listed
        individually (the table is the clearer view) — but they still count in
        the summary and appear in the JSON output.
        """
        tables = tables or []
        lines: list[str] = []
        title = self._c("AWS Security Review", _BOLD)
        lines.append(f"\n{title}")
        lines.append(
            self._c(
                f"account={metadata.get('account_id')} "
                f"region={metadata.get('region')} "
                f"profile={metadata.get('profile') or 'default'}",
                _DIM,
            )
        )
        lines.append("")

        # A finding whose service has a table is shown via that table instead of
        # as an individual line, to avoid duplicating (and flooding) the output.
        tabled_services = {t.service for t in tables}
        listed = [f for f in findings if f.service not in tabled_services]
        fails = [f for f in listed if f.status is Status.FAIL]
        errors = [f for f in listed if f.status is Status.ERROR]
        passes = [f for f in listed if f.status is Status.PASS]

        # Failures first, most severe at the top, with full detail.
        if fails:
            lines.append(self._c("FINDINGS", _BOLD))
            for f in sorted(fails, key=lambda x: x.severity, reverse=True):
                lines.extend(self._render_finding(f))
            lines.append("")

        # Passing checks, listed compactly (sorted by resource) so per-resource
        # state is shown, not just a count.
        if passes:
            lines.append(self._c(f"PASSED ({len(passes)})", _BOLD))
            for f in sorted(passes, key=lambda x: x.resource):
                lines.append(self._compact_line(f, "PASS", _STATUS_COLOR[Status.PASS]))
            lines.append("")

        # Module tables (e.g. GuardDuty coverage by region).
        for table in tables:
            lines.extend(self._render_table(table))

        # Errors (usually missing permissions) so they aren't mistaken for passes.
        if errors:
            lines.append(self._c("COULD NOT CHECK (errors / missing permissions)", _BOLD))
            for f in sorted(errors, key=lambda x: x.resource):
                lines.append(self._compact_line(f, "ERROR", _STATUS_COLOR[Status.ERROR]))
            lines.append("")

        lines.append(self._summary_line(findings))
        return "\n".join(lines)

    def _render_table(self, t: Table) -> list[str]:
        """Render a Table as aligned, colored columns.

        Column widths are computed from the *visible* text (headers and cell
        tokens), then color codes are added afterwards so the ANSI escapes
        don't throw off the alignment.
        """
        # Width of the row-label column, and of each data column.
        label_w = max([len(t.corner)] + [len(r.label) for r in t.rows])
        col_w = [
            max([len(col)] + [len(r.cells[i]) for r in t.rows])
            for i, col in enumerate(t.columns)
        ]

        lines = [self._c(t.title, _BOLD)]

        # Header row (corner label + column headers).
        header = t.corner.ljust(label_w)
        for i, col in enumerate(t.columns):
            header += "  " + col.ljust(col_w[i])
        lines.append(self._c(header, _BOLD))

        # One line per row; pad to the visible width, then colorize the token.
        for r in t.rows:
            row = r.label.ljust(label_w)
            for i, cell in enumerate(r.cells):
                pad = " " * (col_w[i] - len(cell))
                color = _TOKEN_COLOR.get(cell)
                token = self._c(cell, color) if color else cell
                row += "  " + token + pad
            lines.append(row)
        lines.append("")
        return lines

    def _compact_line(self, f: Finding, label: str, color: str) -> str:
        """One-line rendering used for PASS / ERROR findings.

        Shows the badge, check id, resource, and detail, e.g.::

            PASS  [guardduty_enabled] us-east-1 (det-123) - detector is ENABLED.
        """
        badge = self._c(f" {label} ", color)
        resource = f" {f.resource}" if f.resource and f.resource != "-" else ""
        detail = f" - {f.detail}" if f.detail else ""
        return f"  {badge} [{f.check_id}]{resource}{detail}"

    def _render_finding(self, f: Finding) -> list[str]:
        """Render one FAIL finding as a colored block of lines.

        Optional fields (detail/fix/refs) are only shown when present, so
        sparse findings stay compact.
        """
        sev = self._c(f" {str(f.severity):<8} ", _SEVERITY_COLOR[f.severity])
        head = f"  {sev} {self._c(f.title, _BOLD)}"
        out = [head, f"      resource:  {f.resource}"]
        if f.detail:
            out.append(f"      detail:    {f.detail}")
        if f.recommendation:
            out.append(f"      fix:       {f.recommendation}")
        if f.references:
            out.append(self._c(f"      refs:      {', '.join(f.references)}", _DIM))
        out.append(self._c(f"      check_id:  {f.check_id}", _DIM))
        out.append("")
        return out

    def _summary_line(self, findings: list[Finding]) -> str:
        """One-line tally, e.g. ``SUMMARY: 3 findings  (1 CRITICAL  2 HIGH)``."""
        counts = self._counts(findings)["severity"]
        fail_total = sum(
            1 for f in findings if f.status is Status.FAIL
        )
        # Build the per-severity breakdown, skipping severities with a zero count.
        parts = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            n = counts.get(sev, 0)
            if n:
                parts.append(self._c(f"{n} {sev}", _SEVERITY_COLOR[sev]))
        detail = "  ".join(parts) if parts else self._c("none", _STATUS_COLOR[Status.PASS])
        return self._c("SUMMARY: ", _BOLD) + f"{fail_total} findings  ({detail})"

    @staticmethod
    def _counts(findings: list[Finding]) -> dict:
        """Tally findings by status, and (for FAILs only) by severity.

        Severity is only meaningful for failures, so PASS/ERROR findings are
        deliberately excluded from the severity breakdown.
        """
        status: dict[Status, int] = {}
        severity: dict[Severity, int] = {}
        for f in findings:
            status[f.status] = status.get(f.status, 0) + 1
            if f.status is Status.FAIL:
                severity[f.severity] = severity.get(f.severity, 0) + 1
        return {"status": status, "severity": severity}
