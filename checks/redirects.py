"""Redirect-behavior check.

Two things are inspected:

1. If the user supplied an ``http://`` URL, does the server upgrade them
   to HTTPS? A site that serves the same content on plain HTTP without
   redirecting is vulnerable to passive eavesdropping.

2. Does the redirect chain ever leave the original host? A redirect that
   jumps to an arbitrary domain is an "open redirect" and is commonly
   chained into phishing or OAuth-bypass attacks.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import requests

from scanner import Finding


def _host(url: str) -> str:
    """Return the lowercase hostname of a URL, or '' if it cannot be parsed."""
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Flag missing HTTPS upgrade and any cross-host redirects."""
    findings: list[Finding] = []
    parsed = urlparse(url)

    if parsed.scheme == "http":
        final = response.url
        if urlparse(final).scheme != "https":
            findings.append(Finding(
                title="No HTTPS redirect",
                description=(
                    "The server responded to plain HTTP without redirecting "
                    "to HTTPS. All traffic — including any cookies — is sent "
                    "in cleartext."
                ),
                severity="Medium",
                evidence=f"Final URL after following redirects: {final}",
            ))

    origin_host = _host(url)
    for hop in response.history:
        target = hop.headers.get("Location", "")
        if not target:
            continue
        target_host = _host(target) or origin_host
        if target_host and target_host != origin_host:
            findings.append(Finding(
                title="Redirect leaves original host",
                description=(
                    "A redirect in the chain sent the client to a different "
                    "host. If the redirect destination is attacker-controlled "
                    "(e.g. via a URL parameter) this is an open-redirect bug."
                ),
                severity="Low",
                evidence=f"{hop.url}  →  {target}",
            ))

    return findings
