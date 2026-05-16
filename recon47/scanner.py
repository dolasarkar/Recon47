"""
Scanner orchestrator.

Coordinates all reconnaissance modules and aggregates their results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from recon47.modules import dns_recon, http_recon, port_scan, ssl_check, tech_detect, vuln_check
from recon47.utils.output import info, section


def run_scan(
    target: str,
    *,
    modules: list[str] | None = None,
    subdomain_bruteforce: bool = True,
    ports: list[int] | None = None,
) -> dict[str, Any]:
    """
    Run a full (or selective) reconnaissance scan against *target*.

    Parameters
    ----------
    target:
        Hostname or URL to scan (scheme is optional).
    modules:
        List of module names to run.  Pass ``None`` to run all modules.
        Valid names: ``dns``, ``http``, ``ports``, ``ssl``, ``tech``, ``vulns``.
    subdomain_bruteforce:
        Whether to brute-force subdomains in the DNS module.
    ports:
        Custom port list for the port scanner.  ``None`` uses defaults.

    Returns
    -------
    dict
        Aggregated results keyed by module name plus ``target`` and ``scan_time``.
    """
    # Strip scheme for modules that need raw hostname
    hostname = (
        target
        .removeprefix("https://")
        .removeprefix("http://")
        .split("/")[0]
        .split(":")[0]
    )

    all_modules = {"dns", "http", "ports", "ssl", "tech", "vulns"}
    enabled = set(modules) if modules else all_modules

    results: dict[str, Any] = {
        "target": hostname,
        "scan_time": datetime.now(tz=timezone.utc).isoformat(),
    }

    if "dns" in enabled:
        results["dns"] = dns_recon.run(hostname, bruteforce=subdomain_bruteforce)

    if "http" in enabled:
        results["http"] = http_recon.run(hostname)

    if "ports" in enabled:
        results["ports"] = port_scan.run(hostname, ports=ports)

    if "ssl" in enabled:
        results["ssl"] = ssl_check.run(hostname)

    if "tech" in enabled:
        results["tech"] = tech_detect.run(hostname)

    if "vulns" in enabled:
        results["vulns"] = vuln_check.run(hostname)

    return results
