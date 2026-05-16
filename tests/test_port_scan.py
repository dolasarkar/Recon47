"""
Unit tests for the port scanning module.
"""
import socket
from unittest.mock import MagicMock, patch

import pytest

from recon47.modules import port_scan


class TestPortScan:
    def test_returns_expected_keys(self):
        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", side_effect=ConnectionRefusedError),
        ):
            result = port_scan.run("example.com", ports=[80, 443])
        assert "open_ports" in result
        assert "total_scanned" in result

    def test_total_scanned_matches_input(self):
        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", side_effect=ConnectionRefusedError),
        ):
            result = port_scan.run("example.com", ports=[80, 443, 8080])
        assert result["total_scanned"] == 3

    def test_open_port_detected(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH"

        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", return_value=mock_sock),
        ):
            result = port_scan.run("example.com", ports=[22], max_workers=1)
        assert len(result["open_ports"]) == 1
        assert result["open_ports"][0]["port"] == 22
        assert result["open_ports"][0]["service"] == "SSH"

    def test_all_ports_closed(self):
        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", side_effect=ConnectionRefusedError),
        ):
            result = port_scan.run("example.com", ports=[80, 443])
        assert result["open_ports"] == []

    def test_hostname_resolution_failure_continues(self):
        """If hostname resolution fails, we fall back to the raw target string."""
        with (
            patch("socket.gethostbyname", side_effect=socket.gaierror("nxdomain")),
            patch("socket.create_connection", side_effect=ConnectionRefusedError),
        ):
            result = port_scan.run("nonexistent.invalid", ports=[80])
        assert result["total_scanned"] == 1

    def test_open_ports_sorted(self):
        def fake_connect(addr, timeout):
            port = addr[1]
            sock = MagicMock()
            sock.__enter__ = MagicMock(return_value=sock)
            sock.__exit__ = MagicMock(return_value=False)
            sock.recv.side_effect = socket.timeout
            return sock

        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", side_effect=fake_connect),
        ):
            result = port_scan.run("example.com", ports=[443, 80, 22], max_workers=1)
        ports = [e["port"] for e in result["open_ports"]]
        assert ports == sorted(ports)

    def test_banner_captured(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"220 mail.example.com ESMTP"

        with (
            patch("socket.gethostbyname", return_value="1.2.3.4"),
            patch("socket.create_connection", return_value=mock_sock),
        ):
            result = port_scan.run("example.com", ports=[25], max_workers=1)
        assert "220 mail.example.com" in result["open_ports"][0]["banner"]

    def test_probe_helper_open(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"welcome"

        with patch("socket.create_connection", return_value=mock_sock):
            port, is_open, banner = port_scan._probe("1.2.3.4", 80)
        assert is_open is True
        assert port == 80
        assert "welcome" in banner

    def test_probe_helper_closed(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError):
            port, is_open, banner = port_scan._probe("1.2.3.4", 9999)
        assert is_open is False
        assert banner == ""
