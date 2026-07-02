"""Render findings to the terminal (colorized) or as JSON.

Zero extra dependencies: colors are plain ANSI escape codes, auto-disabled
when output is not a TTY, when ``NO_COLOR`` is set, or when ``--no-color``
is passed. On Windows we enable virtual-terminal processing so the codes
render in the standard console.
"""

from __future__ import annotations

import html
import json
import os
import sys
from datetime import datetime, timezone

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
    "PUBLIC": "\033[97;41m",  # white on red - resource is publicly accessible
    "OPEN": "\033[91m",  # red    - exposed to the internet (SG rule / no-auth URL)
    "EOL": "\033[91m",  # red    - deprecated (end-of-life) Lambda runtime
    "COND": "\033[93m",  # yellow - wildcard principal saved only by a Condition
    "SUSPENDED": "\033[93m",  # yellow - detector present but not monitoring
    "ERR": "\033[95m",  # magenta- could not read
    "-": _DIM,  # grey   - not applicable
    "N/A": _DIM,
}

# ---------------------------------------------------------------------------
# HTML report styling
# ---------------------------------------------------------------------------
# Table cell tokens -> CSS class. Any token not listed (a version string,
# region, algorithm, ...) renders as plain informational text.
_HTML_TOKEN_CLASS = {
    "OK": "ok", "ON": "ok",
    "FAIL": "bad", "OFF": "bad", "OPEN": "bad", "EOL": "bad",
    "PUBLIC": "public",
    "COND": "warn", "SUSPENDED": "warn",
    "ERR": "err",
    "-": "na", "N/A": "na",
}

# Severity -> CSS class for badges and finding cards.
_HTML_SEV_CLASS = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "info",
}

# Self-contained stylesheet (no external fonts/CDNs, so the file works offline).
_HTML_CSS = """
:root {
  --bg: #f6f7f9; --card: #ffffff; --ink: #1c2530; --muted: #667085;
  --line: #e3e7ec; --accent: #2563eb;
  --critical: #b3001b; --high: #d64545; --medium: #c77700;
  --low: #2563eb; --info: #6b7280;
  --ok: #1a7f4b; --bad: #c0392b; --warn: #c77700; --err: #8e44ad; --na: #9aa4b2;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }
header.top { border-bottom: 1px solid var(--line); padding-bottom: 20px; margin-bottom: 24px; }
header.top h1 { margin: 0 0 6px; font-size: 24px; letter-spacing: -0.01em; }
.meta { color: var(--muted); font-size: 13px; }
.meta code { background: #eef1f5; padding: 1px 6px; border-radius: 4px; }
.chips { display: flex; flex-wrap: wrap; gap: 10px; margin: 22px 0 8px; }
.chip {
  display: inline-flex; align-items: baseline; gap: 7px; background: var(--card);
  border: 1px solid var(--line); border-radius: 999px; padding: 6px 14px; font-size: 13px;
}
.chip b { font-size: 15px; }
.chip.zero { opacity: 0.5; }
.chip .dot { width: 9px; height: 9px; border-radius: 50%; display: inline-block; }
.dot.critical { background: var(--critical); } .dot.high { background: var(--high); }
.dot.medium { background: var(--medium); } .dot.low { background: var(--low); }
.dot.info { background: var(--info); }
h2 { font-size: 17px; margin: 34px 0 14px; padding-bottom: 6px; border-bottom: 1px solid var(--line); }
.finding {
  background: var(--card); border: 1px solid var(--line); border-left-width: 5px;
  border-radius: 8px; padding: 14px 16px; margin: 12px 0;
}
.finding.critical { border-left-color: var(--critical); }
.finding.high { border-left-color: var(--high); }
.finding.medium { border-left-color: var(--medium); }
.finding.low { border-left-color: var(--low); }
.finding.info { border-left-color: var(--info); }
.finding-head { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
.finding-title { font-weight: 600; }
.badge {
  font-size: 11px; font-weight: 700; letter-spacing: 0.04em; color: #fff;
  padding: 2px 8px; border-radius: 5px; text-transform: uppercase;
}
.badge.critical { background: var(--critical); } .badge.high { background: var(--high); }
.badge.medium { background: var(--medium); } .badge.low { background: var(--low); }
.badge.info { background: var(--info); }
dl { display: grid; grid-template-columns: 96px 1fr; gap: 4px 14px; margin: 0; }
dt { color: var(--muted); font-size: 13px; }
dd { margin: 0; }
dd.mono, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }
table.grid { border-collapse: collapse; width: 100%; margin: 6px 0 4px; font-size: 13px; }
table.grid caption { text-align: left; color: var(--muted); font-size: 13px; padding-bottom: 6px; }
table.grid th, table.grid td { border: 1px solid var(--line); padding: 6px 10px; text-align: center; }
table.grid thead th { background: #eef1f5; font-weight: 600; }
table.grid tbody th { text-align: left; font-weight: 600; background: #fbfcfd; white-space: nowrap; }
.tok { font-weight: 700; font-size: 12px; }
.tok.ok { color: var(--ok); } .tok.bad { color: var(--bad); } .tok.warn { color: var(--warn); }
.tok.err { color: var(--err); } .tok.na { color: var(--na); font-weight: 400; }
.tok.public { background: var(--critical); color: #fff; padding: 1px 7px; border-radius: 4px; }
table.list { border-collapse: collapse; width: 100%; font-size: 13px; }
table.list th, table.list td { border-bottom: 1px solid var(--line); padding: 7px 10px; text-align: left; vertical-align: top; }
table.list thead th { color: var(--muted); font-weight: 600; }
table.list td.status-pass { color: var(--ok); font-weight: 700; }
table.list td.status-error { color: var(--err); font-weight: 700; }
details { margin: 12px 0; }
summary { cursor: pointer; font-weight: 600; }
.legend { color: var(--muted); font-size: 12px; margin: 8px 0 0; }
.empty { color: var(--muted); font-style: italic; }
footer { margin-top: 40px; color: var(--muted); font-size: 12px; text-align: center; }
"""


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

    # ----- HTML ---------------------------------------------------------
    def to_html(
        self,
        findings: list[Finding],
        metadata: dict,
        tables: list[Table] | None = None,
    ) -> str:
        """Render a self-contained HTML report for human review.

        Everything (styles included) is inlined so the file opens offline
        with no dependencies. Unlike the console view, failures are shown in
        full detail *and* the coverage tables are rendered — the two are
        complementary in a document you scroll rather than a terminal you
        flood: the cards carry the fix, the grids carry per-resource state.
        """
        tables = tables or []
        fails = [f for f in findings if f.status is Status.FAIL]
        passes = [f for f in findings if f.status is Status.PASS]
        errors = [f for f in findings if f.status is Status.ERROR]

        body: list[str] = []
        body.append(self._html_header(metadata))
        body.append(self._html_summary(findings))

        # Failures, grouped by severity (most urgent first), rendered in full.
        body.append('<section><h2>Findings</h2>')
        if fails:
            for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
                group = [f for f in fails if f.severity is sev]
                if not group:
                    continue
                body.append(f"<h2>{sev} <span class='meta'>({len(group)})</span></h2>")
                body.extend(self._html_finding(f) for f in group)
        else:
            body.append('<p class="empty">No failing checks. 🎉</p>')
        body.append("</section>")

        # Coverage grids (per-resource / per-region state at a glance).
        if tables:
            body.append("<section><h2>Coverage</h2>")
            body.extend(self._html_table(t) for t in tables)
            body.append(
                '<p class="legend"><span class="tok ok">OK/ON</span> pass &nbsp; '
                '<span class="tok bad">FAIL/OFF/OPEN/EOL</span> issue &nbsp; '
                '<span class="tok public">PUBLIC</span> public &nbsp; '
                '<span class="tok warn">COND</span> review &nbsp; '
                '<span class="tok err">ERR</span> unreadable &nbsp; '
                '<span class="tok na">-</span> n/a</p>'
            )
            body.append("</section>")

        # Errors kept visible (missing permissions shouldn't read as passes).
        if errors:
            body.append(f"<section><h2>Could not check <span class='meta'>({len(errors)})</span></h2>")
            body.append(self._html_list(errors, "status-error"))
            body.append("</section>")

        # Passes collapsed so per-resource proof is available without clutter.
        if passes:
            body.append(
                f'<details><summary>Passed checks ({len(passes)})</summary>'
                + self._html_list(passes, "status-pass")
                + "</details>"
            )

        body.append(
            '<footer>Generated by awssec — read-only AWS security review. '
            "Pattern-matching checks may be affected by SCPs / boundaries not visible here.</footer>"
        )

        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return (
            "<!doctype html>\n"
            '<html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f"<title>awssec report — {html.escape(str(metadata.get('account_id', '')))}</title>"
            f"<style>{_HTML_CSS}</style></head>\n"
            f'<body><div class="wrap" data-generated="{generated}">\n'
            + "\n".join(body)
            + "\n</div></body></html>\n"
        )

    def _html_header(self, metadata: dict) -> str:
        """The title bar with account / region / profile context."""
        esc = html.escape
        generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        modules = ", ".join(metadata.get("modules") or []) or "all"
        return (
            '<header class="top"><h1>AWS Security Review</h1>'
            '<div class="meta">'
            f"account <code>{esc(str(metadata.get('account_id', '?')))}</code> · "
            f"region <code>{esc(str(metadata.get('region', '?')))}</code> · "
            f"profile <code>{esc(str(metadata.get('profile') or 'default'))}</code> · "
            f"modules <code>{esc(modules)}</code> · "
            f"generated {generated}</div></header>"
        )

    def _html_summary(self, findings: list[Finding]) -> str:
        """A row of chips: per-severity failure counts plus pass/error totals."""
        counts = self._counts(findings)
        sev_counts = counts["severity"]
        status_counts = counts["status"]
        chips = []
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
            n = sev_counts.get(sev, 0)
            cls = _HTML_SEV_CLASS[sev]
            zero = "" if n else " zero"
            chips.append(
                f'<span class="chip{zero}"><span class="dot {cls}"></span>'
                f"<b>{n}</b> {sev}</span>"
            )
        chips.append(
            f'<span class="chip"><b>{status_counts.get(Status.PASS, 0)}</b> passed</span>'
        )
        n_err = status_counts.get(Status.ERROR, 0)
        chips.append(
            f'<span class="chip{"" if n_err else " zero"}">'
            f"<b>{n_err}</b> errors</span>"
        )
        return '<div class="chips">' + "".join(chips) + "</div>"

    def _html_finding(self, f: Finding) -> str:
        """One failure rendered as a detailed card."""
        esc = html.escape
        cls = _HTML_SEV_CLASS[f.severity]
        rows = [f"<dt>Resource</dt><dd class='mono'>{esc(f.resource)}</dd>"]
        if f.detail:
            rows.append(f"<dt>Detail</dt><dd>{esc(f.detail)}</dd>")
        if f.recommendation:
            rows.append(f"<dt>Fix</dt><dd>{esc(f.recommendation)}</dd>")
        if f.references:
            rows.append(f"<dt>References</dt><dd>{esc(', '.join(f.references))}</dd>")
        rows.append(
            f"<dt>Check</dt><dd class='mono'>{esc(f.check_id)} · {esc(f.service)}</dd>"
        )
        return (
            f'<div class="finding {cls}"><div class="finding-head">'
            f'<span class="badge {cls}">{f.severity}</span>'
            f'<span class="finding-title">{esc(f.title)}</span></div>'
            f"<dl>{''.join(rows)}</dl></div>"
        )

    def _html_table(self, t: Table) -> str:
        """One module Table rendered as an HTML grid with colored tokens."""
        esc = html.escape
        head = "".join(f"<th>{esc(c)}</th>" for c in t.columns)
        rows = []
        for r in t.rows:
            cells = []
            for cell in r.cells:
                cls = _HTML_TOKEN_CLASS.get(cell)
                if cls:
                    cells.append(f'<td><span class="tok {cls}">{esc(cell)}</span></td>')
                else:
                    cells.append(f'<td class="mono">{esc(cell)}</td>')
            rows.append(
                f'<tr><th scope="row" class="mono">{esc(r.label)}</th>{"".join(cells)}</tr>'
            )
        return (
            f'<table class="grid"><caption>{esc(t.title)}</caption>'
            f'<thead><tr><th>{esc(t.corner)}</th>{head}</tr></thead>'
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    def _html_list(self, findings: list[Finding], status_class: str) -> str:
        """A compact table for PASS / ERROR findings (service, check, resource)."""
        esc = html.escape
        label = "PASS" if status_class == "status-pass" else "ERROR"
        rows = []
        for f in sorted(findings, key=lambda x: (x.service, x.resource)):
            rows.append(
                f'<tr><td class="{status_class}">{label}</td>'
                f'<td class="mono">{esc(f.service)}</td>'
                f'<td class="mono">{esc(f.check_id)}</td>'
                f'<td class="mono">{esc(f.resource)}</td>'
                f"<td>{esc(f.detail)}</td></tr>"
            )
        return (
            '<table class="list"><thead><tr><th>Status</th><th>Service</th>'
            "<th>Check</th><th>Resource</th><th>Detail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

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
