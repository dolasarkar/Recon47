"""
Unit tests for the output utilities module.
"""
import json
import os
import tempfile
from unittest.mock import patch

import pytest

from recon47.utils import output


def test_info_prints(capsys):
    output.info("hello info")
    captured = capsys.readouterr()
    assert "hello info" in captured.out


def test_success_prints(capsys):
    output.success("all good")
    captured = capsys.readouterr()
    assert "all good" in captured.out


def test_warning_prints(capsys):
    output.warning("watch out")
    captured = capsys.readouterr()
    assert "watch out" in captured.out


def test_error_prints_to_stderr(capsys):
    output.error("something bad")
    captured = capsys.readouterr()
    assert "something bad" in captured.err


def test_section_prints(capsys):
    output.section("DNS Recon")
    captured = capsys.readouterr()
    assert "DNS Recon" in captured.out


def test_banner_prints(capsys):
    output.banner()
    captured = capsys.readouterr()
    assert "Recon47" in captured.out or len(captured.out) > 0


class TestSaveReport:
    def test_save_json(self, tmp_path):
        data = {"target": "example.com", "scan_time": "2024-01-01", "dns": {"records": {}}}
        out = str(tmp_path / "report")
        output.save_report(data, out, fmt="json")
        assert os.path.exists(out + ".json")
        with open(out + ".json") as f:
            loaded = json.load(f)
        assert loaded["target"] == "example.com"

    def test_save_txt(self, tmp_path):
        data = {"target": "example.com", "scan_time": "2024-01-01", "dns": {"records": {"A": ["1.2.3.4"]}}}
        out = str(tmp_path / "report")
        output.save_report(data, out, fmt="txt")
        assert os.path.exists(out + ".txt")
        with open(out + ".txt") as f:
            content = f.read()
        assert "example.com" in content
        assert "DNS" in content

    def test_save_json_appends_extension(self, tmp_path):
        data = {"target": "t.com", "scan_time": "now"}
        out = str(tmp_path / "myreport")
        output.save_report(data, out, fmt="json")
        assert os.path.exists(out + ".json")

    def test_save_txt_appends_extension(self, tmp_path):
        data = {"target": "t.com", "scan_time": "now"}
        out = str(tmp_path / "myreport")
        output.save_report(data, out, fmt="txt")
        assert os.path.exists(out + ".txt")

    def test_results_to_text_with_list(self, tmp_path):
        data = {"target": "t.com", "scan_time": "now", "items": ["a", "b", "c"]}
        out = str(tmp_path / "rep")
        output.save_report(data, out, fmt="txt")
        with open(out + ".txt") as f:
            content = f.read()
        assert "- a" in content
        assert "- b" in content
