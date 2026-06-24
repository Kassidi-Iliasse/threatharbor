"""CLI entry point for the vulnerability scanner.

Usage:
    python main.py --url https://example.com
    python main.py --url https://example.com --output myreport.html
    python main.py --url https://example.com --verbose
    python main.py --url https://example.com --unsafe   # enables XSS probe
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

import reporter
import reporter_json
from scanner import run_scan


def _valid_url(value: str) -> str:
    """Reject inputs that aren't plausibly absolute http(s) URLs."""
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            f"--url must be an absolute http(s) URL, got {value!r}"
        )
    return value


def _bounded_timeout(value: str) -> float:
    """Cap user-supplied timeouts to a sensible range (0 < t <= 10)."""
    try:
        t = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"timeout must be a number: {exc}") from exc
    if t <= 0 or t > 10:
        raise argparse.ArgumentTypeError("timeout must be > 0 and <= 10 seconds")
    return t


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser. Factored out so it's testable."""
    p = argparse.ArgumentParser(
        prog="vuln-scanner",
        description="Scan a URL for common web-security issues and emit an HTML report.",
    )
    p.add_argument("--url", required=True, type=_valid_url, help="target URL (http or https)")
    p.add_argument("--output", default="report.html", help="path to write the HTML report (default: report.html)")
    p.add_argument(
        "--format",
        choices=("html", "json", "both"),
        default="html",
        help="report format(s) to write (default: html). JSON is written next "
             "to --output with a .json suffix.",
    )
    p.add_argument("--verbose", action="store_true", help="log findings to stdout as they are produced")
    p.add_argument(
        "--unsafe",
        action="store_true",
        help="enable active checks that submit data (e.g. XSS probe). Only use on authorized targets.",
    )
    p.add_argument("--timeout", default=5.0, type=_bounded_timeout, help="per-request timeout in seconds (default: 5, max: 10)")
    return p


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the scan, write the report, print a summary."""
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )

    result = run_scan(
        url=args.url,
        timeout=args.timeout,
        safe_mode=not args.unsafe,
        verbose=args.verbose,
    )

    if result.errors and not result.findings:
        print(f"Scan aborted: {result.errors[0]}", file=sys.stderr)
        return 2

    outputs: list[str] = []
    if args.format in ("html", "both"):
        outputs.append(reporter.render(result, args.output))
    if args.format in ("json", "both"):
        json_path = str(Path(args.output).with_suffix(".json"))
        outputs.append(reporter_json.render(result, json_path))

    summary = result.summary()
    print(f"Scanned: {result.target}")
    for path in outputs:
        print(f"Report:  {path}")
    print(
        f"Findings: High={summary['High']}  Medium={summary['Medium']}  "
        f"Low={summary['Low']}  Info={summary['Info']}"
    )
    if result.errors:
        print(f"Warnings: {len(result.errors)} check(s) errored (see report).")
    # Exit non-zero if any High findings, so CI pipelines can fail fast.
    return 1 if summary["High"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
