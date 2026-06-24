"""TLS / certificate check.

Opens a fresh TLS connection to the target host and inspects the
certificate and negotiated protocol. Unlike the other checks, this does
not reuse the shared HTTP response — a certificate is a property of the
transport, so it needs its own handshake.

What it flags:

* An expired certificate, or one expiring within two weeks.
* A certificate that fails validation (untrusted issuer, hostname
  mismatch) — a strong man-in-the-middle / misconfiguration signal.
* A connection negotiated over a legacy protocol (TLS 1.0 / 1.1).

Plain-HTTP targets are skipped here; the redirects check is responsible
for the "no HTTPS" story.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    import requests

from scanner import Finding

log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 5
EXPIRY_WARN_DAYS = 14
LEGACY_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def run(url: str, response: "requests.Response", session: "requests.Session") -> list[Finding]:
    """Inspect the target's TLS certificate and negotiated protocol."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []  # nothing to inspect on plain HTTP

    host = parsed.hostname
    if not host:
        return []
    port = parsed.port or 443

    # First attempt: a verifying handshake. A failure here is itself a
    # finding (untrusted issuer, expired, hostname mismatch, etc.).
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version() or "unknown"
    except ssl.SSLCertVerificationError as exc:
        return [Finding(
            title="TLS certificate failed validation",
            description=(
                "The server's certificate could not be validated against the "
                "system trust store. This can mean an expired or self-signed "
                "certificate, an untrusted issuer, or a hostname mismatch — "
                "any of which undermines the protection HTTPS is meant to give."
            ),
            severity="High",
            evidence=f"{host}:{port} — {exc.reason if hasattr(exc, 'reason') else exc}",
        )]
    except (socket.timeout, OSError) as exc:
        # Connectivity hiccup unrelated to security posture; don't invent a
        # finding (the HTTP fetch already succeeded for the shared response).
        log.warning("tls check could not connect to %s:%s: %s", host, port, exc)
        return []

    findings: list[Finding] = []

    if protocol in LEGACY_PROTOCOLS:
        findings.append(Finding(
            title="Legacy TLS protocol negotiated",
            description=(
                f"The connection was negotiated over {protocol}, which is "
                "deprecated and known to be weak. Modern servers should "
                "require TLS 1.2 or higher."
            ),
            severity="Medium",
            evidence=f"{host}:{port} negotiated {protocol}",
        ))

    not_after = _parse_cert_time(cert.get("notAfter")) if cert else None
    if not_after is not None:
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(Finding(
                title="TLS certificate has expired",
                description=(
                    "The certificate's validity period has ended. Browsers "
                    "will refuse the connection or warn users, and the site "
                    "is effectively unprotected."
                ),
                severity="High",
                evidence=f"notAfter={cert.get('notAfter')} ({-days_left} day(s) ago)",
            ))
        elif days_left <= EXPIRY_WARN_DAYS:
            findings.append(Finding(
                title="TLS certificate expiring soon",
                description=(
                    "The certificate expires within two weeks. Renew it before "
                    "it lapses to avoid an outage and browser warnings."
                ),
                severity="Medium",
                evidence=f"notAfter={cert.get('notAfter')} (in {days_left} day(s))",
            ))

    # An informational summary so the report shows the check actually ran.
    expiry_note = (
        f", cert valid until {cert.get('notAfter')}" if cert and cert.get("notAfter") else ""
    )
    findings.append(Finding(
        title="TLS connection details",
        description="Negotiated transport security for the target host.",
        severity="Info",
        evidence=f"{host}:{port} — {protocol}{expiry_note}",
    ))

    return findings


def _parse_cert_time(value: str | None) -> "datetime | None":
    """Parse an OpenSSL ``notAfter`` string into a tz-aware UTC datetime."""
    if not value:
        return None
    try:
        # Format is e.g. "Jun  1 12:00:00 2026 GMT"
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        log.warning("could not parse certificate notAfter: %r", value)
        return None
