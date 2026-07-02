"""Command-line interface: wire credentials -> modules -> reporter.

Usage examples::

    python -m awssec                      # scan all modules, console output
    python -m awssec --module iam         # only the IAM module
    python -m awssec --json > out.json    # machine-readable output
    python -m awssec --profile audit --region us-east-1
"""

from __future__ import annotations

import argparse
import sys

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from . import __version__
from .core.finding import Severity, Status
from .core.progress import Progress
from .core.report import Reporter
from .core.session import build_context
from .modules import MODULES


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Define and parse the command-line flags.

    ``argv`` is accepted (instead of always reading ``sys.argv``) so the
    parser can be exercised directly from tests.
    """
    parser = argparse.ArgumentParser(
        prog="awssec",
        description="Read-only scanner for common AWS security misconfigurations "
        "(runs under the AWS-managed SecurityAudit policy).",
    )
    parser.add_argument(
        "--module",
        action="append",
        choices=sorted(MODULES),
        help="Limit the scan to specific module(s). Repeatable. Default: all.",
    )
    parser.add_argument("--profile", help="AWS named profile to use.")
    parser.add_argument("--region", help="AWS region (default: profile/env region).")
    # Output format: console (default), JSON to stdout, or an HTML file.
    # Mutually exclusive so the intent is unambiguous.
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="Emit findings as JSON to stdout.")
    output.add_argument(
        "--html",
        nargs="?",
        const="awssec-report.html",
        default=None,
        metavar="PATH",
        help="Write a self-contained HTML report to PATH "
        "(default: awssec-report.html).",
    )
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument(
        "--fail-on",
        choices=[str(s) for s in Severity if s is not Severity.INFO],
        help="Exit non-zero if any FAIL finding meets or exceeds this severity "
        "(useful in CI). Default: exit 0 regardless of findings.",
    )
    parser.add_argument("--version", action="version", version=f"awssec {__version__}")
    return parser.parse_args(argv)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Run the scan and return a process exit code.

    Flow: parse args -> build an AWS session -> run each selected module ->
    render the collected findings -> compute the exit code.
    """
    args = _parse_args(argv)

    # Establish one AWS session up front (shared by every module). Any
    # credential/permission problem here is fatal and reported clearly, since
    # without a session there is nothing to scan.
    try:
        ctx = build_context(profile=args.profile, region=args.region)
    except (NoCredentialsError, ClientError, BotoCoreError) as err:
        print(f"error: could not establish an AWS session: {err}", file=sys.stderr)
        print(
            "hint: configure credentials (profile / env / SSO) for a principal with "
            "the AWS-managed SecurityAudit policy.",
            file=sys.stderr,
        )
        return 2  # distinct from the --fail-on exit code (1) so CI can tell them apart

    # Live progress on stderr while the scan runs (auto-silent when stderr is
    # not an interactive terminal, so CI logs and redirects stay clean).
    # Modules refine it with their own per-region / per-resource updates.
    progress = Progress()
    ctx.progress = progress

    # Run the requested modules (default: all). Each returns a ScanResult; we
    # concatenate the findings into one flat list and collect any module tables.
    selected = args.module or list(MODULES)
    findings = []
    tables = []
    for i, name in enumerate(selected, start=1):
        progress.update(f"[{i}/{len(selected)}] {name}: scanning...")
        result = MODULES[name].run(ctx)
        findings.extend(result.findings)
        tables.extend(result.tables)
    progress.clear()  # erase the status line before the real report prints

    # Context echoed in both output formats so a saved report is self-describing.
    metadata = {
        "tool": "awssec",
        "version": __version__,
        "account_id": ctx.account_id,
        "region": ctx.region,
        "profile": args.profile,
        "modules": selected,
    }

    # Output modes; all consume the same findings list and module tables.
    reporter = Reporter(no_color=args.no_color)
    if args.json:
        print(reporter.to_json(findings, metadata, tables))
    elif args.html is not None:
        document = reporter.to_html(findings, metadata, tables)
        try:
            with open(args.html, "w", encoding="utf-8") as fh:
                fh.write(document)
        except OSError as err:
            print(f"error: could not write HTML report to {args.html}: {err}", file=sys.stderr)
            return 2
        print(f"HTML report written to {args.html}")
    else:
        print(reporter.to_console(findings, metadata, tables))

    return _exit_code(findings, args.fail_on)


def _exit_code(findings, fail_on: str | None) -> int:
    """Translate findings into an exit code for CI gating.

    Returns 0 normally. With ``--fail-on SEV`` set, returns 1 if any FAIL
    finding is at least that severity (e.g. ``--fail-on HIGH`` fails the build
    on HIGH or CRITICAL findings, but not MEDIUM/LOW).
    """
    if not fail_on:
        return 0
    threshold = Severity[fail_on]  # name -> enum member; ordered so >= works
    worst = [
        f for f in findings if f.status is Status.FAIL and f.severity >= threshold
    ]
    return 1 if worst else 0


if __name__ == "__main__":
    raise SystemExit(main())
