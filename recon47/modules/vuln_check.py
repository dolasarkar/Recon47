"""
Vulnerability Checks module.

Performs lightweight, non-intrusive checks for common web misconfigurations
and vulnerability indicators without exploiting them.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import urllib3

from recon47.utils.output import info, success, warning, error, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_REQUEST_TIMEOUT = 10

# ---------------------------------------------------------------------------
# Sensitive path probes
# ---------------------------------------------------------------------------

_SENSITIVE_PATHS: list[dict[str, str]] = [
    {"path": "/.git/HEAD",              "label": "Git repository exposed"},
    {"path": "/.env",                   "label": ".env file exposed"},
    {"path": "/wp-login.php",           "label": "WordPress admin login"},
    {"path": "/phpinfo.php",            "label": "phpinfo() page exposed"},
    {"path": "/server-status",          "label": "Apache server-status"},
    {"path": "/server-info",            "label": "Apache server-info"},
    {"path": "/robots.txt",             "label": "robots.txt present"},
    {"path": "/sitemap.xml",            "label": "sitemap.xml present"},
    {"path": "/crossdomain.xml",        "label": "crossdomain.xml (Flash policy)"},
    {"path": "/.htaccess",              "label": ".htaccess file"},
    {"path": "/web.config",             "label": "web.config exposed"},
    {"path": "/config.php",             "label": "config.php exposed"},
    {"path": "/backup.zip",             "label": "Backup archive exposed"},
    {"path": "/backup.sql",             "label": "SQL dump exposed"},
    {"path": "/admin/",                 "label": "Admin panel"},
    {"path": "/administrator/",         "label": "Administrator panel"},
    {"path": "/phpmyadmin/",            "label": "phpMyAdmin exposed"},
    {"path": "/adminer.php",            "label": "Adminer DB tool exposed"},
    {"path": "/actuator",               "label": "Spring Boot Actuator"},
    {"path": "/actuator/health",        "label": "Spring Boot health endpoint"},
    {"path": "/actuator/env",           "label": "Spring Boot env endpoint"},
    {"path": "/.well-known/security.txt","label": "security.txt present"},
    {"path": "/security.txt",           "label": "security.txt (root)"},
    {"path": "/api/swagger.json",       "label": "Swagger API docs exposed"},
    {"path": "/swagger-ui.html",        "label": "Swagger UI exposed"},
    {"path": "/api-docs",               "label": "API docs exposed"},
    {"path": "/graphql",                "label": "GraphQL endpoint"},
    {"path": "/console",                "label": "Web console (e.g. Rails/Padrino)"},
    {"path": "/debug",                  "label": "Debug endpoint"},
]

# Informational paths — present but not necessarily a vulnerability
_INFORMATIONAL_PATHS: set[str] = {
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
}


def _check_open_redirect(base_url: str) -> dict[str, Any]:
    """Check for a basic open-redirect indicator in query-param payloads."""
    result: dict[str, Any] = {"vulnerable": False, "details": ""}
    test_payloads = [
        "?url=https://evil.example.com",
        "?redirect=https://evil.example.com",
        "?next=https://evil.example.com",
        "?return=https://evil.example.com",
    ]
    for payload in test_payloads:
        try:
            resp = requests.get(
                base_url + payload,
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            location = resp.headers.get("Location", "")
            parsed = urlparse(location)
            if parsed.scheme == "https" and parsed.netloc == "evil.example.com":
                result["vulnerable"] = True
                result["details"] = f"Open redirect via {payload}"
                warning(f"  Potential open redirect: {payload} → {location}")
                break
        except requests.exceptions.RequestException:
            pass
    return result


def _check_clickjacking(headers: dict[str, str]) -> bool:
    """Return True if the response is missing clickjacking protection headers."""
    xfo = headers.get("X-Frame-Options", "")
    csp = headers.get("Content-Security-Policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        return True
    return False


def _check_cors_misconfiguration(base_url: str) -> dict[str, Any]:
    """Send an Origin header and check whether ACAO reflects it or uses wildcard."""
    result: dict[str, Any] = {"misconfigured": False, "details": ""}
    origin = "https://evil.example.com"
    try:
        resp = requests.get(
            base_url,
            headers={"Origin": origin},
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        if acao == "*":
            result["misconfigured"] = True
            result["details"] = "Wildcard ACAO header"
            warning("  CORS: Access-Control-Allow-Origin: * (wildcard)")
        elif acao == origin:
            result["misconfigured"] = True
            detail = "Origin reflected"
            if acac.lower() == "true":
                detail += " + Allow-Credentials: true (high risk)"
            result["details"] = detail
            warning(f"  CORS: Origin reflected — {detail}")
        else:
            success("  CORS: no obvious misconfiguration")
    except requests.exceptions.RequestException:
        pass
    return result


def run(target: str) -> dict[str, Any]:
    """
    Run non-intrusive vulnerability checks against *target*.

    Returns
    -------
    dict
        Keys: ``sensitive_paths``, ``open_redirect``,
        ``clickjacking``, ``cors``.
    """
    section("Vulnerability Checks")

    if not target.startswith(("http://", "https://")):
        base_url = f"https://{target}"
    else:
        base_url = target

    results: dict[str, Any] = {
        "sensitive_paths": [],
        "open_redirect": {},
        "clickjacking": False,
        "cors": {},
    }

    # --- Sensitive path probe ---
    info(f"Probing {len(_SENSITIVE_PATHS)} sensitive paths…")
    found_paths: list[dict[str, Any]] = []
    for probe in _SENSITIVE_PATHS:
        url = urljoin(base_url + "/", probe["path"].lstrip("/"))
        try:
            resp = requests.get(
                url,
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            if resp.status_code in (200, 403):
                is_info = probe["path"] in _INFORMATIONAL_PATHS
                entry = {
                    "path": probe["path"],
                    "label": probe["label"],
                    "status": resp.status_code,
                    "informational": is_info,
                }
                found_paths.append(entry)
                if is_info:
                    info(f"  [{resp.status_code}] {probe['path']} — {probe['label']}")
                else:
                    warning(f"  [{resp.status_code}] {probe['path']} — {probe['label']}")
        except requests.exceptions.RequestException:
            pass
    results["sensitive_paths"] = found_paths

    if not found_paths:
        info("No sensitive paths found.")

    # --- Fetch base headers for header-based checks ---
    base_headers: dict[str, str] = {}
    try:
        resp = requests.get(
            base_url,
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
        base_headers = dict(resp.headers)
    except requests.exceptions.RequestException:
        pass

    # --- Clickjacking check ---
    info("Checking clickjacking protection…")
    clickjacking_vuln = _check_clickjacking(base_headers)
    results["clickjacking"] = clickjacking_vuln
    if clickjacking_vuln:
        warning("  Missing X-Frame-Options / CSP frame-ancestors — clickjacking risk")
    else:
        success("  Clickjacking protection is present")

    # --- CORS check ---
    info("Checking CORS configuration…")
    results["cors"] = _check_cors_misconfiguration(base_url)

    # --- Open redirect check ---
    info("Checking for open redirect indicators…")
    results["open_redirect"] = _check_open_redirect(base_url)
    if not results["open_redirect"]["vulnerable"]:
        success("  No open redirect detected with common payloads")

    return results
