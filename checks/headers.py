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
    ("Permissions-Policy", "Low",
     "Missing Permissions-Policy means powerful browser features (camera, "
     "microphone, geolocation, etc.) are not explicitly restricted."),
    ("Cross-Origin-Opener-Policy", "Low",
     "Missing Cross-Origin-Opener-Policy leaves the page sharing a browsing "
     "context group with cross-origin openers, weakening isolation against "
     "side-channel and tab-nabbing attacks."),
]

# Minimum HSTS lifetime we consider acceptable (~180 days), matching common
# preload-list guidance.
HSTS_MIN_MAX_AGE = 15_552_000


def _hsts_max_age(value: str) -> "int | None":
    """Extract the ``max-age`` directive from an HSTS header value."""
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None


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

    # Present-but-weak: a header can exist yet still be misconfigured.
    csp = headers.get("Content-Security-Policy")
    if csp:
        unsafe = [kw for kw in ("'unsafe-inline'", "'unsafe-eval'") if kw in csp.lower()]
        if unsafe:
            findings.append(Finding(
                title="Content-Security-Policy allows unsafe directives",
                description=(
                    "The CSP is present but permits "
                    f"{' and '.join(kw.strip(chr(39)) for kw in unsafe)}, which "
                    "largely defeats CSP's protection against injected scripts."
                ),
                severity="Low",
                evidence=f"Content-Security-Policy: {csp[:160]}",
            ))

    hsts = headers.get("Strict-Transport-Security")
    if hsts:
        max_age = _hsts_max_age(hsts)
        if max_age is not None and max_age < HSTS_MIN_MAX_AGE:
            findings.append(Finding(
                title="HSTS max-age is short",
                description=(
                    "Strict-Transport-Security is set but its max-age is below "
                    "~180 days. A short window leaves users exposed to "
                    "downgrade attacks once the policy lapses."
                ),
                severity="Low",
                evidence=f"Strict-Transport-Security: {hsts}",
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
