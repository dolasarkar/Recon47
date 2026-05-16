"""
HTTP Reconnaissance module.

Analyses HTTP/HTTPS responses: status, redirect chain, server info,
security headers, and cookie flags.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

from recon47.utils.output import info, success, warning, error, section

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Security headers and their expected presence
_SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "HSTS enforced",
    "Content-Security-Policy": "CSP defined",
    "X-Content-Type-Options": "MIME-sniffing disabled",
    "X-Frame-Options": "Clickjacking protection present",
    "X-XSS-Protection": "XSS filter header present",
    "Referrer-Policy": "Referrer policy defined",
    "Permissions-Policy": "Permissions policy defined",
    "Cache-Control": "Cache-Control header present",
}

_REQUEST_TIMEOUT = 10


def _normalise_url(target: str) -> str:
    """Ensure *target* has an HTTP scheme."""
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def run(target: str) -> dict[str, Any]:
    """
    Perform HTTP reconnaissance on *target*.

    Returns
    -------
    dict
        Keys: ``url``, ``status_code``, ``server``, ``headers``,
        ``security_headers``, ``missing_security_headers``,
        ``cookies``, ``redirect_chain``.
    """
    section("HTTP Reconnaissance")

    url = _normalise_url(target)
    results: dict[str, Any] = {
        "url": url,
        "status_code": None,
        "server": None,
        "headers": {},
        "security_headers": {},
        "missing_security_headers": [],
        "cookies": [],
        "redirect_chain": [],
        "https": url.startswith("https://"),
    }

    try:
        response = requests.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
    except requests.exceptions.SSLError:
        warning("HTTPS failed — retrying over HTTP")
        url = url.replace("https://", "http://", 1)
        results["url"] = url
        results["https"] = False
        try:
            response = requests.get(
                url,
                timeout=_REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
        except requests.exceptions.RequestException as exc:
            error(f"HTTP request failed: {exc}")
            return results
    except requests.exceptions.RequestException as exc:
        error(f"HTTP request failed: {exc}")
        return results

    # --- Basic info ---
    results["status_code"] = response.status_code
    success(f"Status code : {response.status_code}")

    server = response.headers.get("Server", "")
    if server:
        results["server"] = server
        info(f"Server      : {server}")

    powered_by = response.headers.get("X-Powered-By", "")
    if powered_by:
        results["x_powered_by"] = powered_by
        info(f"X-Powered-By: {powered_by}")

    # --- All response headers ---
    results["headers"] = dict(response.headers)

    # --- Redirect chain ---
    if response.history:
        chain = [r.url for r in response.history] + [response.url]
        results["redirect_chain"] = chain
        info(f"Redirect chain ({len(response.history)} hop(s)):")
        for hop in chain:
            info(f"  → {hop}")

    # --- Security headers ---
    present: dict[str, str] = {}
    missing: list[str] = []
    for header, description in _SECURITY_HEADERS.items():
        value = response.headers.get(header, "")
        if value:
            present[header] = value
            success(f"  ✔ {header}")
        else:
            missing.append(header)
            warning(f"  ✘ Missing: {header}")
    results["security_headers"] = present
    results["missing_security_headers"] = missing

    # --- Cookies ---
    cookie_details: list[dict[str, Any]] = []
    for cookie in response.cookies:
        details: dict[str, Any] = {
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "samesite": cookie.get_nonstandard_attr("SameSite", ""),
            "domain": cookie.domain,
            "path": cookie.path,
        }
        cookie_details.append(details)
        flags: list[str] = []
        if cookie.secure:
            flags.append("Secure")
        if details["httponly"]:
            flags.append("HttpOnly")
        if details["samesite"]:
            flags.append(f"SameSite={details['samesite']}")
        flag_str = ", ".join(flags) if flags else "no flags"
        info(f"  Cookie: {cookie.name} [{flag_str}]")
    results["cookies"] = cookie_details

    return results
