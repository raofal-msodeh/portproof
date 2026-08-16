"""
PortProof CLI: deterministic port and service verification with JSON evidence.

Usage:
    portproof <target> [<target> ...] [options]
    portproof localhost:8000 127.0.0.1:443 --tls --format json
    portproof db.local:5432 --wait --deadline 30 --report proof.json

Exit codes:
    0  All checks passed (per --fail-mode)
    1  One or more checks failed
    2  Invalid input or configuration
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime

from portproof.engine import ClockSockets, verify_batch
from portproof.errors import (
    DeadlineExceededError,
    InputError,
    PortProofError,
    ProbeTimeoutError,
    ReportWriteError,
)
from portproof.models import (
    FailMode,
    PortStatus,
    ProbeConfig,
    ProbeResult,
    Protocol,
    Report,
    Target,
    ValidationError,
)

__all__ = ["build_parser", "main", "run"]

VERSION = "1.0.0"

# Exit-code mapping, fixed and documented:
EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_INPUT = 2


def _write_report(report: Report, path: str) -> None:
    try:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(report.as_dict(), handle, indent=2, sort_keys=False)
            handle.write("\n")
    except OSError as exc:
        raise ReportWriteError(f"cannot write report to {path}: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portproof",
        description="Deterministic port and service verification with JSON evidence.",
        epilog=(
            "Exit codes: 0 = checks passed, 1 = one or more checks failed, "
            "2 = invalid input or configuration."
        ),
    )
    parser.add_argument("targets", nargs="+", help="target as host:port (IPv6: [::1]:port)")
    parser.add_argument(
        "-P",
        "--protocol",
        choices=["tcp", "tls", "http"],
        default="tcp",
        help="verification method (default: tcp)",
    )
    parser.add_argument(
        "--tls-ca",
        default="",
        help="PEM file of trusted CAs for TLS verification",
    )
    parser.add_argument(
        "--http-path",
        default="/",
        help="HTTP request path for --protocol http (default: /)",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="per-target connection timeout in seconds (default: 5)",
    )
    parser.add_argument(
        "-d",
        "--deadline",
        type=float,
        default=0.0,
        help="total run deadline in seconds; required with --wait (default: none)",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        default=False,
        help="loop until the first target opens or the deadline elapses",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between wait-loop attempts (default: 1)",
    )
    parser.add_argument(
        "--attempts",
        type=int,
        default=0,
        help="maximum wait-loop attempts; 0 means unlimited within deadline",
    )
    parser.add_argument(
        "--fail-mode",
        choices=["all", "any"],
        default="all",
        help="exit-0 condition: all targets open, or any target open (default: all)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="output format (default: text)",
    )
    parser.add_argument(
        "--report",
        default="",
        help="write JSON evidence report to this file",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help="suppress text output; only the report file and exit code",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"portproof {VERSION}",
    )
    return parser


def _parse_targets(specs: list[str]) -> list[Target]:
    targets: list[Target] = []
    seen: set[tuple[str, int]] = set()
    for spec in specs:
        try:
            target = Target.from_spec(spec)
        except ValidationError as exc:
            raise InputError(f"invalid target '{spec}': {exc}") from exc
        key = (target.host, target.port)
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)
    return targets


def run(argv: list[str] | None = None, io: ClockSockets | None = None) -> int:
    """Run the CLI and return the exit code (testable without sys.exit)."""
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        protocol = Protocol(args.protocol)
    except ValueError:
        return EXIT_INPUT

    try:
        if args.timeout <= 0:
            raise InputError("timeout must be greater than 0")
        if args.wait and not args.deadline > 0:
            raise InputError("--wait requires --deadline greater than 0")
        if args.interval <= 0:
            raise InputError("wait interval must be greater than 0")
        targets = _parse_targets(args.targets)
        if not targets:
            raise InputError("no targets provided")
        config = ProbeConfig(
            timeout=args.timeout,
            total_deadline=args.deadline,
            wait=args.wait,
            wait_interval=args.interval,
            wait_attempts=args.attempts,
            protocol=protocol,
            tls_ca=args.tls_ca,
            http_path=args.http_path,
            fail_mode=FailMode(args.fail_mode),
        )
    except (InputError, ValidationError) as exc:
        print(f"portproof: input error: {exc}", file=sys.stderr)
        return EXIT_INPUT

    results = []

    def _record(result: ProbeResult) -> None:  # pragma: no cover - stdout side effect
        if args.format == "text" and not args.quiet:
            marker = "OPEN  " if result.status is PortStatus.OPEN else result.status.value.upper()
            print(f"[{marker}] {result.target} ({result.protocol.value}) {result.reason}")

    try:
        results = verify_batch(targets, config, io=io, reporter=_record)
    except (ProbeTimeoutError, DeadlineExceededError, PortProofError) as exc:
        print(f"portproof: {exc}", file=sys.stderr)
        return EXIT_FAIL

    report = Report(
        targets=results,
        deadline_iso=datetime.now(UTC).isoformat(timespec="seconds"),
        fail_mode=config.fail_mode,
    )

    if args.report:
        try:
            _write_report(report, args.report)
            if args.format == "text" and not args.quiet:
                print(f"report written to {args.report}")
        except ReportWriteError as exc:
            print(f"portproof: {exc}", file=sys.stderr)
            return EXIT_FAIL

    if args.format == "json":
        print(json.dumps(report.as_dict(), indent=2))

    return EXIT_PASS if report.passed else EXIT_FAIL


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
