"""
Unit tests for the vulnerability checks module.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from recon47.modules import vuln_check


def _make_response(status_code=200, headers=None, url="https://example.com"):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.url = url
    return resp


class TestVulnCheck:
    def test_returns_expected_keys(self):
        with patch("requests.get", return_value=_make_response(status_code=404)):
            result = vuln_check.run("example.com")
        assert "sensitive_paths" in result
        assert "open_redirect" in result
        assert "clickjacking" in result
        assert "cors" in result

    def test_sensitive_path_found_on_200(self):
        def fake_get(url, **kwargs):
            if ".git/HEAD" in url:
                return _make_response(status_code=200, url=url)
            return _make_response(status_code=404, url=url)

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check.run("example.com")
        paths = [p["path"] for p in result["sensitive_paths"]]
        assert "/.git/HEAD" in paths

    def test_sensitive_path_found_on_403(self):
        def fake_get(url, **kwargs):
            if ".env" in url:
                return _make_response(status_code=403, url=url)
            return _make_response(status_code=404, url=url)

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check.run("example.com")
        paths = [p["path"] for p in result["sensitive_paths"]]
        assert "/.env" in paths

    def test_clickjacking_vulnerable_without_headers(self):
        headers = {}
        assert vuln_check._check_clickjacking(headers) is True

    def test_clickjacking_protected_by_xfo(self):
        headers = {"X-Frame-Options": "DENY"}
        assert vuln_check._check_clickjacking(headers) is False

    def test_clickjacking_protected_by_csp_frame_ancestors(self):
        headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
        assert vuln_check._check_clickjacking(headers) is False

    def test_cors_wildcard_detected(self):
        def fake_get(url, **kwargs):
            return _make_response(
                headers={"Access-Control-Allow-Origin": "*"},
                url=url,
            )

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check._check_cors_misconfiguration("https://example.com")
        assert result["misconfigured"] is True
        assert "wildcard" in result["details"].lower()

    def test_cors_origin_reflection_detected(self):
        def fake_get(url, **kwargs):
            return _make_response(
                headers={
                    "Access-Control-Allow-Origin": "https://evil.example.com",
                    "Access-Control-Allow-Credentials": "true",
                },
                url=url,
            )

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check._check_cors_misconfiguration("https://example.com")
        assert result["misconfigured"] is True
        assert "reflected" in result["details"].lower()

    def test_cors_clean(self):
        def fake_get(url, **kwargs):
            return _make_response(headers={}, url=url)

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check._check_cors_misconfiguration("https://example.com")
        assert result["misconfigured"] is False

    def test_open_redirect_detected(self):
        def fake_get(url, **kwargs):
            if "url=https://evil.example.com" in url:
                return _make_response(
                    status_code=302,
                    headers={"Location": "https://evil.example.com"},
                    url=url,
                )
            return _make_response(status_code=200, url=url)

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check._check_open_redirect("https://example.com")
        assert result["vulnerable"] is True

    def test_open_redirect_not_vulnerable(self):
        with patch("requests.get", return_value=_make_response(status_code=200)):
            result = vuln_check._check_open_redirect("https://example.com")
        assert result["vulnerable"] is False

    def test_request_exception_in_sensitive_paths(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = vuln_check.run("example.com")
        # Should not raise, just return empty sensitive_paths
        assert isinstance(result["sensitive_paths"], list)

    def test_informational_paths_flagged_correctly(self):
        def fake_get(url, **kwargs):
            if "robots.txt" in url:
                return _make_response(status_code=200, url=url)
            return _make_response(status_code=404, url=url)

        with patch("requests.get", side_effect=fake_get):
            result = vuln_check.run("example.com")
        for entry in result["sensitive_paths"]:
            if entry["path"] == "/robots.txt":
                assert entry["informational"] is True
                break
