"""
Technology Detection module.

Fingerprints web technologies (server, language, frameworks, CMS, CDN …)
from HTTP response headers and body patterns.
"""

from __future__ import annotations

import re
from typing import Any

import requests
import urllib3

from recon47.utils.output import info, success, section, warning

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_REQUEST_TIMEOUT = 10

# ---------------------------------------------------------------------------
# Fingerprint database
# ---------------------------------------------------------------------------

# Each entry: pattern (regex) matched against the named source
_FINGERPRINTS: list[dict[str, str]] = [
    # --- Server / platform ---
    {"category": "Web Server",  "name": "Apache",       "source": "header:Server",      "pattern": r"Apache"},
    {"category": "Web Server",  "name": "Nginx",        "source": "header:Server",      "pattern": r"nginx"},
    {"category": "Web Server",  "name": "IIS",          "source": "header:Server",      "pattern": r"Microsoft-IIS"},
    {"category": "Web Server",  "name": "LiteSpeed",    "source": "header:Server",      "pattern": r"LiteSpeed"},
    {"category": "Web Server",  "name": "Caddy",        "source": "header:Server",      "pattern": r"Caddy"},
    # --- Languages / runtimes ---
    {"category": "Language",    "name": "PHP",          "source": "header:X-Powered-By","pattern": r"PHP"},
    {"category": "Language",    "name": "ASP.NET",      "source": "header:X-Powered-By","pattern": r"ASP\.NET"},
    {"category": "Language",    "name": "Python",       "source": "header:X-Powered-By","pattern": r"Python"},
    {"category": "Language",    "name": "Node.js",      "source": "header:X-Powered-By","pattern": r"Express|Node"},
    {"category": "Language",    "name": "Ruby on Rails","source": "header:X-Powered-By","pattern": r"Phusion Passenger|Rails"},
    # --- CMS ---
    {"category": "CMS",         "name": "WordPress",    "source": "body",               "pattern": r"/wp-content/|wp-json"},
    {"category": "CMS",         "name": "Joomla",       "source": "body",               "pattern": r"Joomla!|/components/com_"},
    {"category": "CMS",         "name": "Drupal",       "source": "body",               "pattern": r"Drupal|drupal\.js"},
    {"category": "CMS",         "name": "Magento",      "source": "body",               "pattern": r"Mage\.Cookies|/skin/frontend/"},
    {"category": "CMS",         "name": "Shopify",      "source": "body",               "pattern": r"cdn\.shopify\.com|Shopify\.theme"},
    {"category": "CMS",         "name": "Ghost",        "source": "header:X-Ghost-Cache-Status", "pattern": r".*"},
    # --- Frameworks ---
    {"category": "Framework",   "name": "Django",       "source": "header:Server",      "pattern": r"WSGIServer"},
    {"category": "Framework",   "name": "Laravel",      "source": "header:Set-Cookie",  "pattern": r"laravel_session"},
    {"category": "Framework",   "name": "React",        "source": "body",               "pattern": r"__reactFiber|react-root|data-reactroot"},
    {"category": "Framework",   "name": "Angular",      "source": "body",               "pattern": r"ng-version|angular\.min\.js"},
    {"category": "Framework",   "name": "Vue.js",       "source": "body",               "pattern": r"vue\.min\.js|__vue__"},
    # --- CDN / infrastructure ---
    {"category": "CDN",         "name": "Cloudflare",   "source": "header:CF-RAY",      "pattern": r".*"},
    {"category": "CDN",         "name": "Cloudflare",   "source": "header:Server",      "pattern": r"cloudflare"},
    {"category": "CDN",         "name": "Fastly",       "source": "header:X-Served-By", "pattern": r"cache-"},
    {"category": "CDN",         "name": "AWS CloudFront","source": "header:X-Cache",    "pattern": r"CloudFront"},
    {"category": "CDN",         "name": "Akamai",       "source": "header:X-Check-Cacheable","pattern": r".*"},
    # --- Analytics / marketing ---
    {"category": "Analytics",   "name": "Google Analytics","source": "body",            "pattern": r"google-analytics\.com|gtag\("},
    {"category": "Analytics",   "name": "Hotjar",       "source": "body",               "pattern": r"hotjar\.com"},
    # --- Security ---
    {"category": "WAF",         "name": "ModSecurity",  "source": "header:Server",      "pattern": r"mod_security"},
    {"category": "WAF",         "name": "Sucuri",       "source": "header:X-Sucuri-ID", "pattern": r".*"},
    {"category": "WAF",         "name": "Imperva",      "source": "header:X-CDN",       "pattern": r"Imperva"},
]


def _match_fingerprints(
    headers: dict[str, str],
    body: str,
) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    for fp in _FINGERPRINTS:
        source = fp["source"]
        pattern = fp["pattern"]
        key = f"{fp['category']}:{fp['name']}"
        if key in seen:
            continue

        if source.startswith("header:"):
            header_name = source[len("header:"):]
            value = headers.get(header_name, "") or headers.get(header_name.lower(), "")
            if value and re.search(pattern, value, re.IGNORECASE):
                seen.add(key)
                found.append({"category": fp["category"], "name": fp["name"], "evidence": f"{header_name}: {value[:80]}"})
        elif source == "body":
            if re.search(pattern, body, re.IGNORECASE):
                seen.add(key)
                found.append({"category": fp["category"], "name": fp["name"], "evidence": "body match"})

    return found


def run(target: str) -> dict[str, Any]:
    """
    Detect technologies used by *target*.

    Returns
    -------
    dict
        Keys: ``technologies`` (list of dicts with ``category``, ``name``,
        ``evidence``).
    """
    section("Technology Detection")
    results: dict[str, Any] = {"technologies": []}

    if not target.startswith(("http://", "https://")):
        url = f"https://{target}"
    else:
        url = target

    try:
        response = requests.get(
            url,
            timeout=_REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
    except requests.exceptions.RequestException as exc:
        warning(f"Technology detection request failed: {exc}")
        return results

    # Build a normalised header map (lowercase keys)
    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    # Also keep original-case for the matcher
    headers_orig = dict(response.headers)
    combined_headers = {**headers_lower, **headers_orig}

    body = response.text[:50_000]  # limit body to first 50 KB

    technologies = _match_fingerprints(combined_headers, body)
    results["technologies"] = technologies

    if technologies:
        for tech in technologies:
            success(f"  [{tech['category']}] {tech['name']}  ({tech['evidence']})")
    else:
        info("No technologies fingerprinted.")

    return results
