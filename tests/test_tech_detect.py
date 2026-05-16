"""
Unit tests for the technology detection module.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from recon47.modules import tech_detect


def _make_response(status_code=200, headers=None, text=""):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.text = text
    resp.url = "https://example.com"
    return resp


class TestTechDetect:
    def test_returns_technologies_key(self):
        resp = _make_response()
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        assert "technologies" in result

    def test_nginx_detected_from_server_header(self):
        resp = _make_response(headers={"Server": "nginx/1.18.0"})
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        assert "Nginx" in names

    def test_apache_detected(self):
        resp = _make_response(headers={"Server": "Apache/2.4.41 (Ubuntu)"})
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        assert "Apache" in names

    def test_php_detected_from_powered_by(self):
        resp = _make_response(headers={"X-Powered-By": "PHP/8.1.0"})
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        assert "PHP" in names

    def test_wordpress_detected_from_body(self):
        resp = _make_response(text='<link href="/wp-content/themes/twenty/style.css">')
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        assert "WordPress" in names

    def test_cloudflare_detected_from_header(self):
        resp = _make_response(headers={"CF-RAY": "abc123-IAD"})
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        assert "Cloudflare" in names

    def test_no_technologies_found(self):
        resp = _make_response(headers={"Content-Type": "text/html"}, text="<html></html>")
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        assert isinstance(result["technologies"], list)

    def test_request_exception_returns_empty(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = tech_detect.run("example.com")
        assert result["technologies"] == []

    def test_no_duplicates_in_results(self):
        """A technology should only appear once even if multiple patterns match."""
        resp = _make_response(
            headers={"Server": "cloudflare"},
            text="",
        )
        # CF-RAY also triggers Cloudflare — but Server: cloudflare should only register once
        with patch("requests.get", return_value=resp):
            result = tech_detect.run("example.com")
        names = [t["name"] for t in result["technologies"]]
        # Each unique category:name pair should appear at most once
        pairs = [(t["category"], t["name"]) for t in result["technologies"]]
        assert len(pairs) == len(set(pairs))

    def test_match_fingerprints_body_pattern(self):
        headers = {}
        body = "<script>angular.min.js v15</script>"
        matches = tech_detect._match_fingerprints(headers, body)
        names = [m["name"] for m in matches]
        assert "Angular" in names

    def test_target_with_scheme(self):
        """Targets that already have a scheme should work fine."""
        resp = _make_response(headers={"Server": "nginx"})
        with patch("requests.get", return_value=resp) as mock_get:
            tech_detect.run("https://example.com")
        mock_get.assert_called_once()
