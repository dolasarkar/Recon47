"""
Unit tests for the HTTP reconnaissance module.
"""
from unittest.mock import MagicMock, patch

import pytest
import requests

from recon47.modules import http_recon


def _make_response(
    status_code=200,
    headers=None,
    cookies=None,
    history=None,
    url="https://example.com",
):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.cookies = cookies or []
    resp.history = history or []
    resp.url = url
    return resp


class TestHttpRecon:
    def test_basic_response(self):
        mock_resp = _make_response(
            headers={"Server": "nginx/1.18", "Content-Type": "text/html"},
        )
        with patch("requests.get", return_value=mock_resp):
            result = http_recon.run("example.com")
        assert result["status_code"] == 200
        assert result["server"] == "nginx/1.18"

    def test_security_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Cache-Control": "no-cache",
        }
        mock_resp = _make_response(headers=headers)
        with patch("requests.get", return_value=mock_resp):
            result = http_recon.run("example.com")
        assert result["missing_security_headers"] == []
        assert "Strict-Transport-Security" in result["security_headers"]

    def test_missing_security_headers(self):
        mock_resp = _make_response(headers={})
        with patch("requests.get", return_value=mock_resp):
            result = http_recon.run("example.com")
        assert len(result["missing_security_headers"]) == len(http_recon._SECURITY_HEADERS)

    def test_redirect_chain(self):
        hop1 = MagicMock()
        hop1.url = "http://example.com"
        mock_resp = _make_response(
            history=[hop1],
            url="https://example.com",
        )
        with patch("requests.get", return_value=mock_resp):
            result = http_recon.run("example.com")
        assert len(result["redirect_chain"]) == 2
        assert "http://example.com" in result["redirect_chain"]

    def test_request_exception_returns_partial(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            result = http_recon.run("unreachable.invalid")
        assert result["status_code"] is None

    def test_ssl_error_retries_http(self):
        ok_resp = _make_response(status_code=200, url="http://example.com")
        with patch("requests.get", side_effect=[
            requests.exceptions.SSLError("ssl error"),
            ok_resp,
        ]):
            result = http_recon.run("example.com")
        assert result["status_code"] == 200
        assert result["https"] is False

    def test_normalise_url_no_scheme(self):
        assert http_recon._normalise_url("example.com") == "https://example.com"

    def test_normalise_url_with_scheme(self):
        assert http_recon._normalise_url("http://example.com") == "http://example.com"

    def test_cookies_parsed(self):
        cookie = MagicMock()
        cookie.name = "session"
        cookie.secure = True
        cookie.has_nonstandard_attr.return_value = True
        cookie.get_nonstandard_attr.return_value = "Strict"
        cookie.domain = "example.com"
        cookie.path = "/"
        mock_resp = _make_response(cookies=[cookie])
        with patch("requests.get", return_value=mock_resp):
            result = http_recon.run("example.com")
        assert result["cookies"][0]["name"] == "session"
        assert result["cookies"][0]["secure"] is True
