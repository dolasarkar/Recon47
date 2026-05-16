"""
Unit tests for the CLI commands.
"""
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from recon47.cli import cli, _parse_modules, _parse_ports
import click


class TestParsers:
    def test_parse_modules_none(self):
        assert _parse_modules(None) is None

    def test_parse_modules_valid(self):
        result = _parse_modules("dns,http,ssl")
        assert set(result) == {"dns", "http", "ssl"}

    def test_parse_modules_invalid(self):
        with pytest.raises(click.BadParameter):
            _parse_modules("dns,invalid_module")

    def test_parse_modules_whitespace_stripped(self):
        result = _parse_modules("dns , http , ssl")
        assert set(result) == {"dns", "http", "ssl"}

    def test_parse_ports_none(self):
        assert _parse_ports(None) is None

    def test_parse_ports_valid(self):
        result = _parse_ports("80,443,8080")
        assert result == [80, 443, 8080]

    def test_parse_ports_invalid(self):
        with pytest.raises(click.BadParameter):
            _parse_ports("80,abc,443")


class TestCliCommands:
    def setup_method(self):
        self.runner = CliRunner()

    def test_version(self):
        result = self.runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_modules_command(self):
        result = self.runner.invoke(cli, ["modules"])
        assert result.exit_code == 0
        for module in ("dns", "http", "ports", "ssl", "tech", "vulns"):
            assert module in result.output

    def test_scan_command_invokes_run_scan(self):
        mock_results = {
            "target": "example.com",
            "scan_time": "2024-01-01T00:00:00+00:00",
        }
        with patch("recon47.cli.run_scan", return_value=mock_results) as mock_scan:
            result = self.runner.invoke(cli, ["scan", "example.com"])
        assert result.exit_code == 0
        mock_scan.assert_called_once_with(
            "example.com",
            modules=None,
            subdomain_bruteforce=True,
            ports=None,
        )

    def test_scan_with_modules_flag(self):
        mock_results = {"target": "example.com", "scan_time": "now"}
        with patch("recon47.cli.run_scan", return_value=mock_results) as mock_scan:
            result = self.runner.invoke(cli, ["scan", "example.com", "--modules", "dns,ssl"])
        assert result.exit_code == 0
        call_kwargs = mock_scan.call_args
        assert set(call_kwargs.kwargs["modules"]) == {"dns", "ssl"}

    def test_scan_no_bruteforce_flag(self):
        mock_results = {"target": "example.com", "scan_time": "now"}
        with patch("recon47.cli.run_scan", return_value=mock_results) as mock_scan:
            result = self.runner.invoke(cli, ["scan", "example.com", "--no-bruteforce"])
        assert result.exit_code == 0
        assert mock_scan.call_args.kwargs["subdomain_bruteforce"] is False

    def test_scan_with_ports_flag(self):
        mock_results = {"target": "example.com", "scan_time": "now"}
        with patch("recon47.cli.run_scan", return_value=mock_results) as mock_scan:
            result = self.runner.invoke(cli, ["scan", "example.com", "--ports", "80,443"])
        assert result.exit_code == 0
        assert mock_scan.call_args.kwargs["ports"] == [80, 443]

    def test_scan_saves_json_report(self, tmp_path):
        mock_results = {"target": "example.com", "scan_time": "now"}
        out = str(tmp_path / "output")
        with patch("recon47.cli.run_scan", return_value=mock_results):
            result = self.runner.invoke(cli, ["scan", "example.com", "--output", out])
        assert result.exit_code == 0
        import os
        assert os.path.exists(out + ".json")

    def test_scan_saves_txt_report(self, tmp_path):
        mock_results = {"target": "example.com", "scan_time": "now"}
        out = str(tmp_path / "output")
        with patch("recon47.cli.run_scan", return_value=mock_results):
            result = self.runner.invoke(
                cli, ["scan", "example.com", "--output", out, "--format", "txt"]
            )
        assert result.exit_code == 0
        import os
        assert os.path.exists(out + ".txt")

    def test_scan_invalid_modules_exits_nonzero(self):
        result = self.runner.invoke(cli, ["scan", "example.com", "--modules", "invalid"])
        assert result.exit_code != 0

    def test_scan_invalid_ports_exits_nonzero(self):
        result = self.runner.invoke(cli, ["scan", "example.com", "--ports", "abc"])
        assert result.exit_code != 0

    def test_help(self):
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output
