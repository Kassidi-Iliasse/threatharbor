"""Form-surface check.

Parses the page with BeautifulSoup, lists every <form>, and flags two
classes of problem:

* Forms that submit over plain HTTP (regardless of how the page itself
  was loaded).
* POST forms that do not appear to carry any CSRF token. This is a
  heuristic — see ``_looks_like_csrf_token`` — and is reported as Info
  rather than a hard finding because real apps use many different
  protection schemes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    import requests

from scanner import Finding

# Substrings that, when present in a hidden input's name, strongly suggest
# an anti-CSRF token. The check is intentionally generous to avoid
# false-positive screaming on every login form on the internet.
CSRF_HINTS = ("csrf", "token", "nonce", "authenticity", "xsrf", "_token")


def _looks_like_csrf_token(name: str) -> bool:
    """Heuristic: does a hidden input's ``name`` look like a CSRF token?"""
    lowered = name.lower()
    return any(hint in lowered for hint in CSRF_HINTS)


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Inspect every <form> on the page and flag insecure submissions."""
    findings: list[Finding] = []
    soup = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        action_raw = (form.get("action") or "").strip()
        action = urljoin(response.url, action_raw) if action_raw else response.url
        method = (form.get("method") or "GET").upper()

        if urlparse(action).scheme == "http":
            findings.append(Finding(
                title="Form submits over HTTP",
                description=(
                    "Form data — possibly including credentials — is posted "
                    "to a non-HTTPS endpoint and travels in cleartext."
                ),
                severity="Medium",
                evidence=f"action={action} method={method}",
            ))

        if method == "POST":
            hidden_inputs = form.find_all("input", attrs={"type": "hidden"})
            has_token = any(
                _looks_like_csrf_token(i.get("name") or "")
                for i in hidden_inputs
            )
            if not has_token:
                findings.append(Finding(
                    title="POST form has no obvious CSRF token",
                    description=(
                        "No hidden input on this POST form has a name that "
                        "looks like a CSRF token. The site may still be "
                        "protected via cookies (double-submit), custom "
                        "headers, or SameSite — verify manually."
                    ),
                    severity="Info",
                    evidence=f"action={action} hidden_inputs={[i.get('name') for i in hidden_inputs]}",
                ))

    return findings
