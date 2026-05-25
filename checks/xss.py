"""Reflected-XSS smoke test.

This is intentionally a *basic* reflection check, not a real XSS scanner.
It looks for raw, unescaped reflection of a probe payload's angle
brackets in the response body — a strong signal that the input is
written into HTML without escaping.

Limitations (covered honestly in the README):

* Only finds reflections in HTML body context. Misses attribute / JS /
  URL contexts where real-world XSS often lives.
* Does not handle WAFs, charset quirks, or content sniffing.
* Submits one payload per form text input; no DOM or stored testing.

This check submits data and is therefore only invoked when the user
passes ``--unsafe`` on the CLI.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    import requests

from scanner import Finding

log = logging.getLogger(__name__)

# Two probes: the classic <script> tag and an attribute-breakout vector.
# We check whether the raw "<" / ">" survive into the response body, which
# is more reliable than matching the full payload string.
PAYLOADS: list[tuple[str, str]] = [
    ("<script>alert('xss-probe')</script>", "xss-probe"),
    ("\"><svg/onload=1>vulnscan", "vulnscan"),
]

TEXT_INPUT_TYPES = {"text", "search", "url", "email", "tel", ""}


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Submit a probe through each form input and look for raw reflection."""
    findings: list[Finding] = []
    soup = BeautifulSoup(response.text, "html.parser")

    for form in soup.find_all("form"):
        action_raw = (form.get("action") or "").strip()
        action = urljoin(response.url, action_raw) if action_raw else response.url
        method = (form.get("method") or "GET").upper()

        inputs = form.find_all(["input", "textarea"])
        text_fields = [
            i for i in inputs
            if (i.get("type") or "text").lower() in TEXT_INPUT_TYPES
            and i.get("name")
        ]
        if not text_fields:
            continue

        for payload, marker in PAYLOADS:
            data = {}
            for i in inputs:
                name = i.get("name")
                if not name:
                    continue
                if i in text_fields:
                    data[name] = payload
                else:
                    data[name] = i.get("value", "")

            try:
                if method == "POST":
                    r = session.post(action, data=data, timeout=5, allow_redirects=True)
                else:
                    r = session.get(action, params=data, timeout=5, allow_redirects=True)
            except Exception as exc:  # noqa: BLE001
                log.warning("xss probe failed for %s: %s", action, exc)
                continue

            body = r.text
            # A reflection only counts if the raw angle brackets survive
            # together with our unique marker — that means the payload was
            # written into HTML without entity-encoding.
            if marker in body and "<" in payload and "<" in _surrounding(body, marker):
                findings.append(Finding(
                    title="Reflected XSS suspected",
                    description=(
                        "A probe payload was reflected into the response body "
                        "with its angle brackets intact, suggesting the input "
                        "is rendered into HTML without escaping. Manual "
                        "verification recommended."
                    ),
                    severity="High",
                    evidence=f"action={action} payload={payload}",
                ))
                # one finding per form is enough — break out of payloads
                break

    return findings


def _surrounding(body: str, marker: str, window: int = 40) -> str:
    """Return ``window`` chars on either side of ``marker`` in ``body``."""
    idx = body.find(marker)
    if idx < 0:
        return ""
    return body[max(0, idx - window): idx + len(marker) + window]
