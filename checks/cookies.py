"""Cookie-flag check.

Inspects every Set-Cookie issued by the target and flags cookies that lack
HttpOnly, Secure, or SameSite — the three flags most often missing on
authentication and session cookies.
"""

from __future__ import annotations

from http.cookies import SimpleCookie
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

from scanner import Finding


def _parse_set_cookies(raw_headers: list[str]) -> list[SimpleCookie]:
    """Parse each raw Set-Cookie header into its own SimpleCookie.

    We parse one header at a time so attributes from one cookie don't bleed
    into another (a known footgun of feeding multiple cookies into a single
    SimpleCookie instance).
    """
    parsed: list[SimpleCookie] = []
    for raw in raw_headers:
        c: SimpleCookie = SimpleCookie()
        try:
            c.load(raw)
        except Exception:  # noqa: BLE001
            continue
        parsed.append(c)
    return parsed


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Flag cookies in the response that are missing HttpOnly/Secure/SameSite."""
    findings: list[Finding] = []

    # requests collapses repeated Set-Cookie headers; use raw_headers to get
    # each one individually.
    raw = response.raw.headers.getlist("Set-Cookie") if response.raw else []
    if not raw:
        # fall back to the single (possibly merged) header
        single = response.headers.get("Set-Cookie")
        raw = [single] if single else []

    for cookie in _parse_set_cookies(raw):
        for name, morsel in cookie.items():
            attrs = {k.lower(): v for k, v in morsel.items()}

            if not attrs.get("httponly"):
                findings.append(Finding(
                    title=f"Cookie '{name}' missing HttpOnly",
                    description=(
                        "Without HttpOnly, the cookie is readable from "
                        "JavaScript — any XSS becomes a session-theft bug."
                    ),
                    severity="Medium",
                    evidence=morsel.OutputString(),
                ))
            if not attrs.get("secure"):
                findings.append(Finding(
                    title=f"Cookie '{name}' missing Secure",
                    description=(
                        "Without the Secure flag, the cookie can be sent "
                        "over plain HTTP and intercepted on the wire."
                    ),
                    severity="Medium",
                    evidence=morsel.OutputString(),
                ))
            if not attrs.get("samesite"):
                findings.append(Finding(
                    title=f"Cookie '{name}' missing SameSite",
                    description=(
                        "No SameSite attribute means the cookie is sent on "
                        "cross-site requests, enabling CSRF on state-changing "
                        "endpoints."
                    ),
                    severity="Low",
                    evidence=morsel.OutputString(),
                ))

    return findings
