"""
DNS Reconnaissance module.

Queries common DNS record types and attempts a lightweight subdomain
brute-force using a built-in wordlist.
"""

from __future__ import annotations

import socket
from typing import Any

try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _DNS_AVAILABLE = False

from recon47.utils.output import info, success, warning, error, section

# Common subdomain prefixes to probe
_SUBDOMAIN_WORDLIST: list[str] = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail",
    "dev", "staging", "test", "api", "cdn", "static", "assets",
    "admin", "portal", "vpn", "remote", "blog", "shop", "store",
    "m", "mobile", "app", "beta", "alpha", "secure", "login",
    "auth", "support", "help", "docs", "wiki", "forum", "news",
    "upload", "download", "media", "img", "images", "video",
    "chat", "dashboard", "panel", "manage", "status", "monitor",
    "git", "gitlab", "jenkins", "ci", "jira", "confluence",
    "ns1", "ns2", "mx1", "mx2",
]

_RECORD_TYPES: list[str] = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def run(target: str, bruteforce: bool = True) -> dict[str, Any]:
    """
    Perform DNS reconnaissance on *target*.

    Parameters
    ----------
    target:
        Domain name (e.g. ``example.com``).
    bruteforce:
        When ``True`` (default) also probe common sub-domains.

    Returns
    -------
    dict
        Keys: ``records``, ``subdomains``.
    """
    section("DNS Reconnaissance")
    results: dict[str, Any] = {"records": {}, "subdomains": []}

    # --- Standard record queries ---
    if _DNS_AVAILABLE:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5
        for rtype in _RECORD_TYPES:
            try:
                answers = resolver.resolve(target, rtype)
                values = [str(r) for r in answers]
                results["records"][rtype] = values
                success(f"{rtype:6s} → {', '.join(values)}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except dns.exception.DNSException as exc:
                warning(f"{rtype}: {exc}")
    else:
        # Fallback: only A records via socket
        warning("dnspython not installed — falling back to socket A-record lookup")
        try:
            ip = socket.gethostbyname(target)
            results["records"]["A"] = [ip]
            success(f"A      → {ip}")
        except socket.gaierror as exc:
            error(f"A record lookup failed: {exc}")

    # --- Subdomain brute-force ---
    if bruteforce:
        info(f"Probing {len(_SUBDOMAIN_WORDLIST)} common subdomains…")
        found: list[str] = []
        for prefix in _SUBDOMAIN_WORDLIST:
            fqdn = f"{prefix}.{target}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append(fqdn)
                success(f"  Subdomain found: {fqdn} → {ip}")
            except socket.gaierror:
                pass
        results["subdomains"] = found
        if not found:
            info("No additional subdomains discovered via brute-force.")

    return results
