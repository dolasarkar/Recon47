"""
SSL/TLS Certificate Inspection module.

Retrieves the server certificate for a domain and reports expiry,
subject, issuer, SANs, and protocol version.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from recon47.utils.output import info, success, warning, error, section

_CONNECT_TIMEOUT = 5


def _get_cert_info(hostname: str, port: int = 443) -> dict[str, Any]:
    """Connect via TLS and return parsed certificate details."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Enforce TLS 1.2 minimum for secure connections; servers using TLS 1.0/1.1
    # will fail to connect, which we record as an error rather than downgrading.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        with socket.create_connection((hostname, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher_name, _, cipher_bits = ssock.cipher()
                return {
                    "cert": cert,
                    "protocol": protocol,
                    "cipher": cipher_name,
                    "cipher_bits": cipher_bits,
                }
    except (ssl.SSLError, socket.error, OSError) as exc:
        return {"error": str(exc)}


def _parse_subject(cert: dict) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in cert.get("subject", []):
        for k, v in entry:
            result[k] = v
    return result


def _parse_san(cert: dict) -> list[str]:
    sans: list[str] = []
    for entry in cert.get("subjectAltName", []):
        tag, value = entry
        if tag.lower() == "dns":
            sans.append(value)
    return sans


def run(target: str, port: int = 443) -> dict[str, Any]:
    """
    Inspect the SSL/TLS certificate served by *target*:*port*.

    Returns
    -------
    dict
        Certificate details and any warnings about expiry or weak protocols.
    """
    section("SSL/TLS Certificate Inspection")
    results: dict[str, Any] = {"target": target, "port": port}

    data = _get_cert_info(target, port)
    if "error" in data:
        error(f"Could not retrieve certificate: {data['error']}")
        results["error"] = data["error"]
        return results

    cert = data["cert"]
    results["protocol"] = data["protocol"]
    results["cipher"] = data["cipher"]
    results["cipher_bits"] = data["cipher_bits"]

    info(f"Protocol    : {data['protocol']}")
    info(f"Cipher      : {data['cipher']} ({data['cipher_bits']} bits)")

    # Protocol version warnings
    weak_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    if data["protocol"] in weak_protocols:
        warning(f"Weak protocol in use: {data['protocol']}")
        results["weak_protocol"] = True
    else:
        results["weak_protocol"] = False

    # Subject
    subject = _parse_subject(cert)
    results["subject"] = subject
    cn = subject.get("commonName", "")
    if cn:
        info(f"Common Name : {cn}")

    # Issuer
    issuer: dict[str, str] = {}
    for entry in cert.get("issuer", []):
        for k, v in entry:
            issuer[k] = v
    results["issuer"] = issuer
    issuer_org = issuer.get("organizationName", issuer.get("commonName", ""))
    if issuer_org:
        info(f"Issuer      : {issuer_org}")

    # Validity dates
    not_before_str = cert.get("notBefore", "")
    not_after_str = cert.get("notAfter", "")
    results["not_before"] = not_before_str
    results["not_after"] = not_after_str

    if not_after_str:
        expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(tz=timezone.utc)
        days_left = (expiry - now).days
        results["days_until_expiry"] = days_left

        if days_left < 0:
            error(f"Certificate EXPIRED {abs(days_left)} day(s) ago!")
            results["expired"] = True
        elif days_left < 30:
            warning(f"Certificate expires in {days_left} day(s) — renew soon!")
            results["expired"] = False
        else:
            success(f"Certificate valid for {days_left} more day(s)")
            results["expired"] = False

    # Subject Alternative Names
    sans = _parse_san(cert)
    results["san"] = sans
    if sans:
        info(f"SANs        : {', '.join(sans[:5])}{'…' if len(sans) > 5 else ''}")

    # Self-signed check
    is_self_signed = subject == issuer
    results["self_signed"] = is_self_signed
    if is_self_signed:
        warning("Certificate appears to be self-signed.")

    return results
