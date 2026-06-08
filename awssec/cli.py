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
from .core.report import Reporter
from .core.session import build_context
from .modules import MODULES


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
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
    parser.add_argument("--json", action="store_true", help="Emit findings as JSON.")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    parser.add_argument(
        "--fail-on",
        choices=[str(s) for s in Severity if s is not Severity.INFO],
        help="Exit non-zero if any FAIL finding meets or exceeds this severity "
        "(useful in CI). Default: exit 0 regardless of findings.",
    )
    parser.add_argument("--version", action="version", version=f"awssec {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        ctx = build_context(profile=args.profile, region=args.region)
    except (NoCredentialsError, ClientError, BotoCoreError) as err:
        print(f"error: could not establish an AWS session: {err}", file=sys.stderr)
        print(
            "hint: configure credentials (profile / env / SSO) for a principal with "
            "the AWS-managed SecurityAudit policy.",
            file=sys.stderr,
        )
        return 2

    selected = args.module or list(MODULES)
    findings = []
    for name in selected:
        findings.extend(MODULES[name].run(ctx))

    metadata = {
        "tool": "awssec",
        "version": __version__,
        "account_id": ctx.account_id,
        "region": ctx.region,
        "profile": args.profile,
        "modules": selected,
    }

    reporter = Reporter(no_color=args.no_color)
    if args.json:
        print(reporter.to_json(findings, metadata))
    else:
        print(reporter.to_console(findings, metadata))

    return _exit_code(findings, args.fail_on)


def _exit_code(findings, fail_on: str | None) -> int:
    """0 normally; 1 if --fail-on threshold met by any FAIL finding."""
    if not fail_on:
        return 0
    threshold = Severity[fail_on]
    worst = [
        f for f in findings if f.status is Status.FAIL and f.severity >= threshold
    ]
    return 1 if worst else 0


if __name__ == "__main__":
    raise SystemExit(main())
