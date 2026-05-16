"""
Recon47 CLI entry point.

Usage examples
--------------
# Full scan
recon47 scan example.com

# Quick scan (no subdomain bruteforce)
recon47 scan example.com --no-bruteforce

# Specific modules only
recon47 scan example.com --modules dns,http,ssl

# Save JSON report
recon47 scan example.com --output report --format json

# Save text report
recon47 scan example.com --output report --format txt

# Custom ports
recon47 scan example.com --ports 80,443,8080,8443
"""

from __future__ import annotations

import sys

import click

from recon47 import __version__
from recon47.scanner import run_scan
from recon47.utils.output import banner, error, info, save_report, success

_VALID_MODULES = {"dns", "http", "ports", "ssl", "tech", "vulns"}


def _parse_modules(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [m.strip().lower() for m in value.split(",") if m.strip()]
    invalid = set(parts) - _VALID_MODULES
    if invalid:
        raise click.BadParameter(
            f"Unknown module(s): {', '.join(sorted(invalid))}. "
            f"Valid choices: {', '.join(sorted(_VALID_MODULES))}."
        )
    return parts


def _parse_ports(value: str | None) -> list[int] | None:
    if not value:
        return None
    try:
        return [int(p.strip()) for p in value.split(",") if p.strip()]
    except ValueError as exc:
        raise click.BadParameter(f"Invalid port specification: {exc}") from exc


@click.group()
@click.version_option(version=__version__, prog_name="recon47")
def cli() -> None:
    """Recon47 — Automated Web Reconnaissance & Vulnerability Scanner."""


@cli.command("scan")
@click.argument("target")
@click.option(
    "--modules", "-m",
    default=None,
    metavar="dns,http,ports,ssl,tech,vulns",
    help="Comma-separated list of modules to run (default: all).",
)
@click.option(
    "--no-bruteforce",
    is_flag=True,
    default=False,
    help="Skip subdomain brute-force in the DNS module.",
)
@click.option(
    "--ports",
    default=None,
    metavar="PORT[,PORT…]",
    help="Comma-separated list of TCP ports to scan (default: common ports).",
)
@click.option(
    "--output", "-o",
    default=None,
    metavar="FILE",
    help="Output file path (without extension). Saved as <FILE>.json or <FILE>.txt.",
)
@click.option(
    "--format", "-f",
    "fmt",
    type=click.Choice(["json", "txt"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Report output format.",
)
def scan_cmd(
    target: str,
    modules: str | None,
    no_bruteforce: bool,
    ports: str | None,
    output: str | None,
    fmt: str,
) -> None:
    """Run a full reconnaissance scan against TARGET (hostname or URL)."""
    banner()

    try:
        module_list = _parse_modules(modules)
        port_list = _parse_ports(ports)
    except click.BadParameter as exc:
        error(str(exc))
        sys.exit(1)

    info(f"Target   : {target}")
    if module_list:
        info(f"Modules  : {', '.join(module_list)}")
    else:
        info("Modules  : all")

    results = run_scan(
        target,
        modules=module_list,
        subdomain_bruteforce=not no_bruteforce,
        ports=port_list,
    )

    success("\nScan complete.")

    if output:
        save_report(results, output, fmt=fmt)


@cli.command("modules")
def modules_cmd() -> None:
    """List available reconnaissance modules."""
    click.echo("\nAvailable modules:\n")
    module_info = {
        "dns":   "DNS Reconnaissance — records, subdomain brute-force",
        "http":  "HTTP Reconnaissance — headers, cookies, redirects",
        "ports": "Port Scanning — TCP connect scan on common ports",
        "ssl":   "SSL/TLS Inspection — certificate details and expiry",
        "tech":  "Technology Detection — server, CMS, frameworks, CDN",
        "vulns": "Vulnerability Checks — misconfigs, open redirect, CORS",
    }
    for name, description in module_info.items():
        click.echo(f"  {name:<8} {description}")
    click.echo()


def main() -> None:
    """Package entry-point."""
    cli()


if __name__ == "__main__":
    main()
