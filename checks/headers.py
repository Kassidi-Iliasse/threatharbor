"""HTTP security-header check.

Inspects the response headers from the target and flags missing or
informational headers that are commonly required for a hardened web app.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

from scanner import Finding

# (header name, severity, description)
EXPECTED_HEADERS: list[tuple[str, str, str]] = [
    ("X-Frame-Options", "Medium",
     "Missing X-Frame-Options allows the page to be framed by other sites, "
     "enabling clickjacking attacks."),
    ("X-Content-Type-Options", "Low",
     "Missing X-Content-Type-Options lets browsers MIME-sniff responses, "
     "which can lead to drive-by script execution."),
    ("Content-Security-Policy", "Medium",
     "No Content-Security-Policy is set; CSP is the strongest defense "
     "against reflected and stored XSS."),
    ("Strict-Transport-Security", "Medium",
     "Missing HSTS header — clients can be downgraded to plain HTTP via "
     "active-attacker MITM."),
    ("Referrer-Policy", "Low",
     "Missing Referrer-Policy leaks the full referring URL to third "
     "parties on outbound links."),
]


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Check the response's headers for missing/leaky security headers."""
    findings: list[Finding] = []
    headers = response.headers

    for name, severity, description in EXPECTED_HEADERS:
        if name not in headers:
            findings.append(Finding(
                title=f"Missing {name} header",
                description=description,
                severity=severity,
                evidence=f"Header '{name}' not present in response from {url}",
            ))

    server = headers.get("Server")
    if server:
        findings.append(Finding(
            title="Server header exposes software",
            description=(
                "The Server response header reveals the underlying web server "
                "(and sometimes its version), which helps attackers target "
                "known CVEs."
            ),
            severity="Info",
            evidence=f"Server: {server}",
        ))

    powered = headers.get("X-Powered-By")
    if powered:
        findings.append(Finding(
            title="X-Powered-By header exposes stack",
            description=(
                "X-Powered-By reveals the application framework/language "
                "version — useful reconnaissance for an attacker."
            ),
            severity="Info",
            evidence=f"X-Powered-By: {powered}",
        ))

    return findings
