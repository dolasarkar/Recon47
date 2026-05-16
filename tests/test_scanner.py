"""
Unit tests for the scanner orchestrator.
"""
from unittest.mock import patch, MagicMock

import pytest

from recon47.scanner import run_scan


class TestRunScan:
    def _patch_all(self):
        """Return a dict of module patches."""
        dummy_dns = {"records": {"A": ["1.2.3.4"]}, "subdomains": []}
        dummy_http = {"status_code": 200, "server": "nginx"}
        dummy_ports = {"open_ports": [], "total_scanned": 26}
        dummy_ssl = {"protocol": "TLSv1.3", "expired": False}
        dummy_tech = {"technologies": []}
        dummy_vulns = {"sensitive_paths": [], "clickjacking": False}
        return {
            "recon47.scanner.dns_recon.run": dummy_dns,
            "recon47.scanner.http_recon.run": dummy_http,
            "recon47.scanner.port_scan.run": dummy_ports,
            "recon47.scanner.ssl_check.run": dummy_ssl,
            "recon47.scanner.tech_detect.run": dummy_tech,
            "recon47.scanner.vuln_check.run": dummy_vulns,
        }

    def test_full_scan_returns_all_modules(self):
        patches = self._patch_all()
        with (
            patch("recon47.scanner.dns_recon.run", return_value=patches["recon47.scanner.dns_recon.run"]),
            patch("recon47.scanner.http_recon.run", return_value=patches["recon47.scanner.http_recon.run"]),
            patch("recon47.scanner.port_scan.run", return_value=patches["recon47.scanner.port_scan.run"]),
            patch("recon47.scanner.ssl_check.run", return_value=patches["recon47.scanner.ssl_check.run"]),
            patch("recon47.scanner.tech_detect.run", return_value=patches["recon47.scanner.tech_detect.run"]),
            patch("recon47.scanner.vuln_check.run", return_value=patches["recon47.scanner.vuln_check.run"]),
        ):
            result = run_scan("example.com")

        assert result["target"] == "example.com"
        assert "scan_time" in result
        assert "dns" in result
        assert "http" in result
        assert "ports" in result
        assert "ssl" in result
        assert "tech" in result
        assert "vulns" in result

    def test_selective_modules(self):
        patches = self._patch_all()
        with (
            patch("recon47.scanner.dns_recon.run", return_value=patches["recon47.scanner.dns_recon.run"]) as dns_mock,
            patch("recon47.scanner.http_recon.run", return_value=patches["recon47.scanner.http_recon.run"]) as http_mock,
            patch("recon47.scanner.port_scan.run", return_value=patches["recon47.scanner.port_scan.run"]) as port_mock,
            patch("recon47.scanner.ssl_check.run", return_value=patches["recon47.scanner.ssl_check.run"]) as ssl_mock,
            patch("recon47.scanner.tech_detect.run", return_value=patches["recon47.scanner.tech_detect.run"]) as tech_mock,
            patch("recon47.scanner.vuln_check.run", return_value=patches["recon47.scanner.vuln_check.run"]) as vulns_mock,
        ):
            result = run_scan("example.com", modules=["dns", "ssl"])

        assert "dns" in result
        assert "ssl" in result
        assert "http" not in result
        assert "ports" not in result
        http_mock.assert_not_called()
        port_mock.assert_not_called()

    def test_hostname_strips_scheme(self):
        patches = self._patch_all()
        with (
            patch("recon47.scanner.dns_recon.run", return_value=patches["recon47.scanner.dns_recon.run"]) as dns_mock,
            patch("recon47.scanner.http_recon.run", return_value=patches["recon47.scanner.http_recon.run"]),
            patch("recon47.scanner.port_scan.run", return_value=patches["recon47.scanner.port_scan.run"]),
            patch("recon47.scanner.ssl_check.run", return_value=patches["recon47.scanner.ssl_check.run"]),
            patch("recon47.scanner.tech_detect.run", return_value=patches["recon47.scanner.tech_detect.run"]),
            patch("recon47.scanner.vuln_check.run", return_value=patches["recon47.scanner.vuln_check.run"]),
        ):
            result = run_scan("https://example.com/path?q=1")

        assert result["target"] == "example.com"
        dns_mock.assert_called_once_with("example.com", bruteforce=True)

    def test_no_bruteforce_propagates(self):
        patches = self._patch_all()
        with (
            patch("recon47.scanner.dns_recon.run", return_value=patches["recon47.scanner.dns_recon.run"]) as dns_mock,
            patch("recon47.scanner.http_recon.run", return_value=patches["recon47.scanner.http_recon.run"]),
            patch("recon47.scanner.port_scan.run", return_value=patches["recon47.scanner.port_scan.run"]),
            patch("recon47.scanner.ssl_check.run", return_value=patches["recon47.scanner.ssl_check.run"]),
            patch("recon47.scanner.tech_detect.run", return_value=patches["recon47.scanner.tech_detect.run"]),
            patch("recon47.scanner.vuln_check.run", return_value=patches["recon47.scanner.vuln_check.run"]),
        ):
            run_scan("example.com", subdomain_bruteforce=False)

        dns_mock.assert_called_once_with("example.com", bruteforce=False)

    def test_custom_ports_propagate(self):
        patches = self._patch_all()
        with (
            patch("recon47.scanner.dns_recon.run", return_value=patches["recon47.scanner.dns_recon.run"]),
            patch("recon47.scanner.http_recon.run", return_value=patches["recon47.scanner.http_recon.run"]),
            patch("recon47.scanner.port_scan.run", return_value=patches["recon47.scanner.port_scan.run"]) as port_mock,
            patch("recon47.scanner.ssl_check.run", return_value=patches["recon47.scanner.ssl_check.run"]),
            patch("recon47.scanner.tech_detect.run", return_value=patches["recon47.scanner.tech_detect.run"]),
            patch("recon47.scanner.vuln_check.run", return_value=patches["recon47.scanner.vuln_check.run"]),
        ):
            run_scan("example.com", ports=[80, 443])

        port_mock.assert_called_once_with("example.com", ports=[80, 443])
