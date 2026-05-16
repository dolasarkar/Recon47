"""
Unit tests for the SSL/TLS inspection module.
"""
import ssl
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch, call

import pytest

from recon47.modules import ssl_check


def _make_valid_cert(days_until_expiry=90):
    """Build a fake parsed certificate dict."""
    future = datetime.now(tz=timezone.utc) + timedelta(days=days_until_expiry)
    not_after = future.strftime("%b %d %H:%M:%S %Y GMT")
    past = datetime.now(tz=timezone.utc) - timedelta(days=365)
    not_before = past.strftime("%b %d %H:%M:%S %Y GMT")
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R3"),)),
        "notBefore": not_before,
        "notAfter": not_after,
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }


def _patch_ssl(cert, protocol="TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
    """Return a context-manager patch for _get_cert_info."""
    return {
        "cert": cert,
        "protocol": protocol,
        "cipher": cipher[0],
        "cipher_bits": cipher[2],
    }


class TestSslCheck:
    def test_valid_cert_returns_expected_keys(self):
        cert = _make_valid_cert(days_until_expiry=90)
        data = _patch_ssl(cert)
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert "protocol" in result
        assert "cipher" in result
        assert "subject" in result
        assert "issuer" in result
        assert "san" in result
        assert result["expired"] is False

    def test_expired_cert(self):
        cert = _make_valid_cert(days_until_expiry=-1)
        data = _patch_ssl(cert)
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert result["expired"] is True

    def test_near_expiry_cert(self):
        cert = _make_valid_cert(days_until_expiry=15)
        data = _patch_ssl(cert)
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert result["expired"] is False
        assert result["days_until_expiry"] < 30

    def test_weak_protocol_flagged(self):
        cert = _make_valid_cert()
        data = _patch_ssl(cert, protocol="TLSv1")
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert result["weak_protocol"] is True

    def test_strong_protocol_not_flagged(self):
        cert = _make_valid_cert()
        data = _patch_ssl(cert, protocol="TLSv1.3")
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert result["weak_protocol"] is False

    def test_san_parsed(self):
        cert = _make_valid_cert()
        data = _patch_ssl(cert)
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert "example.com" in result["san"]
        assert "www.example.com" in result["san"]

    def test_self_signed_detection(self):
        cert = {
            "subject": ((("commonName", "self.signed"),),),
            "issuer": ((("commonName", "self.signed"),),),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Jan  1 00:00:00 2099 GMT",
            "subjectAltName": (),
        }
        data = _patch_ssl(cert)
        with patch("recon47.modules.ssl_check._get_cert_info", return_value=data):
            result = ssl_check.run("example.com")
        assert result["self_signed"] is True

    def test_error_case(self):
        with patch(
            "recon47.modules.ssl_check._get_cert_info",
            return_value={"error": "connection refused"},
        ):
            result = ssl_check.run("example.com")
        assert "error" in result
        assert result["error"] == "connection refused"

    def test_parse_subject(self):
        cert = {"subject": ((("commonName", "test.com"), ("organizationName", "Acme")),)}
        parsed = ssl_check._parse_subject(cert)
        assert parsed["commonName"] == "test.com"
        assert parsed["organizationName"] == "Acme"

    def test_parse_san_filters_dns(self):
        cert = {
            "subjectAltName": (
                ("DNS", "example.com"),
                ("IP Address", "1.2.3.4"),
                ("DNS", "www.example.com"),
            )
        }
        sans = ssl_check._parse_san(cert)
        assert sans == ["example.com", "www.example.com"]
