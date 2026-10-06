import socket
import unittest
from unittest.mock import patch

from url2ip.core import (
    ResolutionError,
    TargetError,
    _scan_one,
    extract_hostname,
    parse_ports,
    resolve_hostname,
    scan_ports,
)


class ExtractHostnameTests(unittest.TestCase):
    def test_extracts_hostname_from_url_and_bare_host(self):
        self.assertEqual(extract_hostname("https://Example.com/a?b=c"), "example.com")
        self.assertEqual(extract_hostname("example.com:8443/path"), "example.com")
        self.assertEqual(extract_hostname("http://[::1]:8080/"), "::1")

    def test_rejects_invalid_urls(self):
        for target in ("", "https://", "ftp://example.com", "https://user:pass@example.com"):
            with self.subTest(target=target), self.assertRaises(TargetError):
                extract_hostname(target)

    def test_rejects_invalid_port_in_url(self):
        with self.assertRaises(TargetError):
            extract_hostname("https://example.com:70000")


class PortParsingTests(unittest.TestCase):
    def test_parses_ports_and_deduplicates_ranges(self):
        self.assertEqual(parse_ports("80, 22-24,23"), [80, 22, 23, 24])

    def test_rejects_invalid_or_oversized_input(self):
        for ports in ("", "0", "80-22", "1-257", "80,,443", "abc", "65536"):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                parse_ports(ports)


class ResolutionTests(unittest.TestCase):
    @patch("url2ip.core.socket.getaddrinfo")
    def test_returns_unique_addresses_in_resolution_order(self, getaddrinfo):
        getaddrinfo.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0)),
        ]
        self.assertEqual(
            resolve_hostname("example.com"),
            ["192.0.2.1", "2001:db8::1"],
        )

    @patch("url2ip.core.socket.getaddrinfo", side_effect=socket.gaierror("not found"))
    def test_surfaces_dns_failures(self, _getaddrinfo):
        with self.assertRaises(ResolutionError):
            resolve_hostname("missing.invalid")


class ScanningTests(unittest.TestCase):
    @patch("url2ip.core.socket.create_connection")
    def test_reports_open_port_and_latency(self, create_connection):
        create_connection.return_value.__enter__.return_value = object()
        with patch("url2ip.core.time.monotonic", side_effect=[1.0, 1.025]):
            result = _scan_one("127.0.0.1", 443, 0.5)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.latency_ms, 25.0)

    @patch("url2ip.core.socket.create_connection", side_effect=ConnectionRefusedError)
    def test_reports_unavailable_port_without_crashing(self, _create_connection):
        result = _scan_one("127.0.0.1", 1, 0.5)
        self.assertEqual(result.state, "closed_or_filtered")

    def test_scan_rejects_unbounded_configuration(self):
        with self.assertRaises(ValueError):
            scan_ports(["127.0.0.1"], [80], workers=65)

    def test_scan_caps_total_address_port_checks(self):
        with self.assertRaises(ValueError):
            scan_ports(
                ["192.0.2.1", "192.0.2.2", "192.0.2.3"],
                list(range(1, 257)),
            )

    def test_connects_to_a_local_listening_port(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            port = listener.getsockname()[1]
            result = scan_ports(["127.0.0.1"], [port], timeout=0.5)
        self.assertEqual(result[0].state, "open")


if __name__ == "__main__":
    unittest.main()
