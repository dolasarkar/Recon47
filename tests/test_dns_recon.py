"""
Unit tests for the DNS reconnaissance module.
"""
from unittest.mock import MagicMock, patch

import pytest

from recon47.modules import dns_recon


class TestDnsRecon:
    def test_returns_dict_with_expected_keys(self):
        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", False),
            patch("socket.gethostbyname", return_value="93.184.216.34"),
        ):
            result = dns_recon.run("example.com", bruteforce=False)
        assert "records" in result
        assert "subdomains" in result

    def test_fallback_a_record(self):
        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", False),
            patch("socket.gethostbyname", return_value="1.2.3.4"),
        ):
            result = dns_recon.run("example.com", bruteforce=False)
        assert result["records"]["A"] == ["1.2.3.4"]

    def test_fallback_a_record_failure(self):
        import socket as _socket
        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", False),
            patch("socket.gethostbyname", side_effect=_socket.gaierror("not found")),
        ):
            result = dns_recon.run("nonexistent.invalid", bruteforce=False)
        assert result["records"] == {}

    def test_bruteforce_finds_subdomain(self):
        import socket as _socket

        def fake_gethostbyname(host):
            if host == "www.example.com":
                return "1.2.3.4"
            raise _socket.gaierror("not found")

        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", False),
            patch("socket.gethostbyname", side_effect=fake_gethostbyname),
        ):
            result = dns_recon.run("example.com", bruteforce=True)
        assert "www.example.com" in result["subdomains"]

    def test_no_bruteforce(self):
        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", False),
            patch("socket.gethostbyname", return_value="1.2.3.4"),
        ):
            result = dns_recon.run("example.com", bruteforce=False)
        assert result["subdomains"] == []

    def test_dnspython_records(self):
        """Test with dnspython available and returning results."""
        mock_resolver_class = MagicMock()
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver

        mock_answer_a = MagicMock()
        mock_answer_a.__iter__ = MagicMock(return_value=iter([MagicMock(__str__=lambda s: "1.2.3.4")]))

        import dns.exception
        import dns.resolver

        def resolve_side_effect(domain, rtype):
            if rtype == "A":
                a_record = MagicMock()
                a_record.__str__ = MagicMock(return_value="1.2.3.4")
                answer = [a_record]
                return answer
            raise dns.resolver.NoAnswer()

        mock_resolver.resolve.side_effect = resolve_side_effect

        with (
            patch("recon47.modules.dns_recon._DNS_AVAILABLE", True),
            patch("recon47.modules.dns_recon.dns") as mock_dns_module,
        ):
            mock_dns_module.resolver.Resolver.return_value = mock_resolver
            mock_dns_module.resolver.NoAnswer = dns.resolver.NoAnswer
            mock_dns_module.resolver.NXDOMAIN = dns.resolver.NXDOMAIN
            mock_dns_module.exception.DNSException = dns.exception.DNSException
            result = dns_recon.run("example.com", bruteforce=False)

        assert "records" in result
