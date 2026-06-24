"""Scanner orchestration: runs every check module against a target URL and
collects their findings into a single list for the reporter."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Optional

import requests

log = logging.getLogger(__name__)

Severity = str  # "High" | "Medium" | "Low" | "Info"


@dataclass
class Finding:
    """A single security issue discovered by a check module.

    Attributes:
        title: Short human-readable name of the issue.
        description: Explanation of what the issue is and why it matters.
        severity: One of "High", "Medium", "Low", "Info".
        evidence: Raw data supporting the finding (header value, URL, snippet).
        check: Name of the check module that produced the finding.
    """

    title: str
    description: str
    severity: Severity
    evidence: str = ""
    check: str = ""


@dataclass
class ScanResult:
    """Aggregate result of a scan run against a single target URL."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        """Return a count of findings grouped by severity."""
        counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


CheckFn = Callable[[str, requests.Response, requests.Session], list[Finding]]


def run_scan(
    url: str,
    timeout: float = 5.0,
    safe_mode: bool = True,
    verbose: bool = False,
) -> ScanResult:
    """Run every check module against ``url`` and return aggregated results.

    Args:
        url: Target URL to scan.
        timeout: Per-request timeout in seconds (capped at 10 by CLI).
        safe_mode: When True, checks that submit data (e.g. XSS) are skipped.
        verbose: When True, findings are logged as they are produced.

    Returns:
        A ``ScanResult`` containing all findings and any per-check errors.
    """
    # Lazy import: each check module imports Finding from this file, so
    # importing them at module top causes a circular import.
    from checks import cookies, forms, headers, redirects, tls, xss

    result = ScanResult(target=url)
    session = requests.Session()
    session.headers.update({"User-Agent": "vuln-scanner/1.0 (portfolio)"})

    try:
        response = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        result.errors.append(f"Could not fetch {url}: {exc}")
        return result

    check_modules: list[tuple[str, CheckFn]] = [
        ("headers", headers.run),
        ("tls", tls.run),
        ("cookies", cookies.run),
        ("redirects", redirects.run),
        ("forms", forms.run),
    ]
    if not safe_mode:
        check_modules.append(("xss", xss.run))

    for name, fn in check_modules:
        try:
            found = fn(url, response, session)
            for f in found:
                f.check = name
                if verbose:
                    log.info("[%s] %s - %s", f.severity, f.title, f.evidence[:80])
            result.findings.extend(found)
        except Exception as exc:  # noqa: BLE001
            msg = f"check '{name}' failed: {exc}"
            log.warning(msg)
            result.errors.append(msg)

    return result
