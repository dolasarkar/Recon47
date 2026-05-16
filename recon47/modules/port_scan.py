"""
Port Scanning module.

Performs a TCP connect scan against a configurable list of common ports.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from recon47.utils.output import info, success, section

# Well-known and commonly targeted ports with friendly names
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "HTTP Dev",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

_CONNECT_TIMEOUT = 2


def _probe(host: str, port: int) -> tuple[int, bool, str]:
    """Return *(port, open, banner)* for a single TCP probe."""
    banner = ""
    try:
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            sock.settimeout(1)
            try:
                raw = sock.recv(256)
                banner = raw.decode("utf-8", errors="replace").strip()
            except (socket.timeout, OSError):
                pass
            return port, True, banner
    except (ConnectionRefusedError, socket.timeout, OSError):
        return port, False, ""


def run(target: str, ports: list[int] | None = None, max_workers: int = 50) -> dict[str, Any]:
    """
    Scan TCP ports on *target*.

    Parameters
    ----------
    target:
        Hostname or IP address.
    ports:
        List of port numbers to probe.  Defaults to :data:`COMMON_PORTS`.
    max_workers:
        Thread-pool concurrency (default 50).

    Returns
    -------
    dict
        Keys: ``open_ports``, ``closed_ports``, ``total_scanned``.
    """
    section("Port Scanning")

    # Resolve to IP once
    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        host = target  # try anyway

    port_list = ports if ports is not None else list(COMMON_PORTS.keys())
    info(f"Scanning {len(port_list)} ports on {target} ({host}) …")

    open_ports: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_probe, host, p): p for p in port_list}
        for future in as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "unknown")
                entry: dict[str, Any] = {
                    "port": port,
                    "service": service,
                    "banner": banner,
                }
                open_ports.append(entry)
                banner_str = f" — {banner[:60]}" if banner else ""
                success(f"  {port:5d}/tcp  OPEN  {service}{banner_str}")

    open_ports.sort(key=lambda e: e["port"])

    if not open_ports:
        info("No open ports found in the scanned range.")

    return {
        "open_ports": open_ports,
        "total_scanned": len(port_list),
    }
