"""Diagnósticos e relatórios: testes isolados, sem acesso à Internet."""

import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import toolkit  # noqa: E402


def run_cli(arguments):
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = toolkit.main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class IPAnalysisTests(unittest.TestCase):
    def test_ipv4_loopback_flags_and_reverse_pointer_without_dns(self):
        with mock.patch("toolkit.socket.getaddrinfo") as forward, \
             mock.patch("toolkit.socket.gethostbyaddr") as reverse:
            result = toolkit.analyze_ip("127.0.0.1")
        self.assertEqual(result["address"], "127.0.0.1")
        self.assertEqual(result["version"], 4)
        self.assertEqual(result["expanded"], "127.0.0.1")
        self.assertEqual(result["reverse_pointer"], "1.0.0.127.in-addr.arpa")
        self.assertTrue(result["is_loopback"])
        self.assertTrue(result["is_private"])
        self.assertFalse(result["is_global"])
        self.assertFalse(result["is_multicast"])
        forward.assert_not_called()
        reverse.assert_not_called()

    def test_ipv6_compresses_and_expands_address(self):
        result = toolkit.analyze_ip("2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(result["address"], "2001:db8::1")
        self.assertEqual(result["compressed"], "2001:db8::1")
        self.assertEqual(result["expanded"], "2001:0db8:0000:0000:0000:0000:0000:0001")
        self.assertEqual(result["version"], 6)
        self.assertFalse(result["is_loopback"])

    def test_ipv6_reverse_pointer_is_nibble_order(self):
        result = toolkit.analyze_ip("::1")
        self.assertEqual(result["reverse_pointer"], "1." + "0." * 31 + "ip6.arpa")
        self.assertTrue(result["is_loopback"])
        self.assertFalse(result["is_unspecified"])

    def test_ipv6_zone_is_preserved_without_changing_address_bits(self):
        result = toolkit.analyze_ip("fe80::1%eth0")
        self.assertEqual(result["scope_id"], "eth0")
        self.assertEqual(result["expanded"], "fe80:0000:0000:0000:0000:0000:0000:0001")
        self.assertEqual(result["reverse_pointer"], "1." + "0." * 27 + "0.8.e.f.ip6.arpa")
        self.assertTrue(result["is_link_local"])

    def test_special_address_classifications(self):
        for address, flag in (("192.168.1.5", "is_private"),
                              ("169.254.10.5", "is_link_local"),
                              ("fe80::1", "is_link_local"),
                              ("224.0.0.1", "is_multicast"),
                              ("ff02::1", "is_multicast"),
                              ("0.0.0.0", "is_unspecified"),
                              ("::", "is_unspecified")):
            with self.subTest(address=address):
                result = toolkit.analyze_ip(address)
                self.assertTrue(result[flag])
                for name, value in result.items():
                    if name.startswith("is_"):
                        self.assertIsInstance(value, bool)

    def test_ip_cli_json(self):
        status, stdout, stderr = run_cli(["ip", "::1", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "ip")
        self.assertEqual(result["data"]["version"], 6)
        self.assertTrue(result["data"]["is_loopback"])


class DiagnosticArgumentsTests(unittest.TestCase):
    def test_invalid_ip_urls_and_hops_fail_before_network_access(self):
        urls = [
            "example.com", "ftp://example.com/", "file:///tmp/test",
            "http://", "http://user:password@example.com/", "http://user@example.com/",
            "https://example.com:0/", "https://example.com:65536/",
            "https://example.com:not-a-port/", "http://[::1/", "http://bad host/",
            "http://example.com/with\nnewline",
        ]
        cases = [["http", url, "--json"] for url in urls]
        cases.extend([["ip", "localhost"], ["ip", "999.0.0.1"], ["ip", "::xyz"],
                      ["ip", "192.0.2.0/24"]])
        cases.extend(["traceroute", "localhost", "--max-hops", hops]
                     for hops in ("0", "65", "1.5", "abc"))
        with mock.patch("toolkit.check_http") as http, \
             mock.patch("toolkit.trace_route") as trace, \
             mock.patch("toolkit.socket.getaddrinfo") as resolve:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    stderr = io.StringIO()
                    with contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as error:
                            toolkit.main(arguments)
                    self.assertEqual(error.exception.code, 2)
                    self.assertIn("usage:", stderr.getvalue())
            http.assert_not_called()
            trace.assert_not_called()
            resolve.assert_not_called()

    def test_valid_http_ipv6_and_hop_limits(self):
        parser = toolkit.build_parser()
        arguments = parser.parse_args(["http", "http://[::1]:8000/", "--timeout", "0.5"])
        self.assertEqual(arguments.url, "http://[::1]:8000/")
        self.assertEqual(arguments.timeout, 0.5)
        for hops in ("1", "64"):
            with self.subTest(hops=hops):
                arguments = parser.parse_args(["traceroute", "localhost", "--max-hops", hops])
                self.assertEqual(arguments.max_hops, int(hops))


class LabHTTPHandler(BaseHTTPRequestHandler):
    """Servidor só para os testes: respostas pequenas e sem arquivos de usuário."""

    def do_GET(self):
        if self.path == "/ok":
            self.send_response(200)
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
        elif self.path == "/unsafe-redirect":
            self.send_response(302)
            self.send_header("Location", "http://user:password@example.invalid/")
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *arguments):
        pass


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Usa porta efêmera e exclui somente loopback dos proxies durante o teste.
        cls.proxy_settings = mock.patch.dict(os.environ, {
            "NO_PROXY": "127.0.0.1", "no_proxy": "127.0.0.1",
        })
        cls.proxy_settings.start()
        cls.addClassCleanup(cls.proxy_settings.stop)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), LabHTTPHandler)
        cls.addClassCleanup(cls.server.server_close)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      kwargs={"poll_interval": 0.01}, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls._stop_server)
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def _stop_server(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=3)
        if cls.thread.is_alive():
            raise AssertionError("a thread do servidor HTTP não encerrou")

    def test_real_http_success(self):
        result = toolkit.check_http(self.base_url + "/ok", 2)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["reason"], "OK")
        self.assertEqual(result["url"], self.base_url + "/ok")
        self.assertEqual(result["final_url"], result["url"])
        self.assertGreaterEqual(result["duration_ms"], 0)

    def test_real_http_redirect_records_final_url(self):
        result = toolkit.check_http(self.base_url + "/redirect", 2)
        self.assertEqual(result["status"], 200)
        self.assertEqual(result["url"], self.base_url + "/redirect")
        self.assertEqual(result["final_url"], self.base_url + "/ok")

    def test_real_http_404_is_diagnostic_failure(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            toolkit.check_http(self.base_url + "/missing", 2)
        self.assertEqual(error.exception.code, 404)
        error.exception.close()

    def test_http_404_cli_json_returns_one(self):
        status, stdout, stderr = run_cli(["http", self.base_url + "/missing", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertFalse(result["ok"])
        self.assertEqual(result["command"], "http")
        self.assertIn("404", result["error"])

    def test_redirect_with_credentials_is_rejected_before_outbound_request(self):
        with self.assertRaisesRegex(OSError, "redirecionamento inválido"):
            toolkit.check_http(self.base_url + "/unsafe-redirect", 2)


class ReportTests(unittest.TestCase):
    def test_export_json_writes_utf8_and_valid_json(self):
        result = {"ok": False, "command": "dns", "error": "falha de resolução"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "relatorio.json"
            toolkit.export_json(path, result)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), result)
            self.assertIn("resolução", path.read_text(encoding="utf-8"))

    def test_success_export_and_json_stdout_are_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            status, stdout, stderr = run_cli([
                "ip", "127.0.0.1", "--json", "--output", str(path),
            ])
            self.assertEqual(json.loads(stdout), json.loads(path.read_text(encoding="utf-8")))
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(json.loads(stdout)["ok"])

    def test_diagnostic_error_is_exported_with_failure_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "failure.json"
            with mock.patch("toolkit.resolve_dns", side_effect=socket.gaierror("nome indisponível")):
                status, stdout, stderr = run_cli([
                    "dns", "lab.example", "--json", "--output", str(path),
                ])
            saved = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(saved, json.loads(stdout))
        self.assertFalse(saved["ok"])
        self.assertEqual(saved["error"], "nome indisponível")

    def test_existing_file_is_preserved_and_diagnostic_remains_available(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.json"
            original = b"previous report\x00\xff\n"
            path.write_bytes(original)
            status, stdout, stderr = run_cli([
                "ip", "127.0.0.1", "--output", str(path), "--json",
            ])
            self.assertEqual(path.read_bytes(), original)
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertFalse(result["ok"])
        self.assertIn("exportar JSON", result["error"])
        self.assertEqual(result["data"]["address"], "127.0.0.1")

    def test_missing_directory_fails_without_creating_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing" / "report.json"
            status, stdout, stderr = run_cli([
                "subnet", "192.0.2.0/24", "--output", str(path), "--json",
            ])
            self.assertFalse(path.parent.exists())
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertFalse(result["ok"])
        self.assertIn("exportar JSON", result["error"])
        self.assertEqual(result["data"]["network"], "192.0.2.0/24")


class TracerouteCLITests(unittest.TestCase):
    def trace_result(self, completed):
        return {
            "host": "lab.example", "destination": "192.0.2.20", "method": "traceroute",
            "completed": completed, "timed_out": False, "max_hops": 2,
            "timeout_seconds": 0.5, "raw_output": "route example", "warnings": "",
            "hops": [
                {"ttl": 1, "address": "192.0.2.1", "rtt_ms": 0.2, "timeout": False},
                {"ttl": 2, "address": "192.0.2.20" if completed else None,
                 "rtt_ms": 0.3 if completed else None, "timeout": not completed},
            ],
        }

    def test_completed_traceroute_json_returns_success(self):
        data = self.trace_result(True)
        with mock.patch("toolkit.trace_route", return_value=data) as trace:
            status, stdout, stderr = run_cli([
                "traceroute", "lab.example", "--max-hops", "2", "--timeout", "0.5", "--json",
            ])
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        result = json.loads(stdout)
        self.assertTrue(result["ok"])
        self.assertEqual(result["data"], data)
        trace.assert_called_once_with("lab.example", 2, 0.5)

    def test_incomplete_traceroute_returns_failure_preserving_hops_and_export(self):
        data = self.trace_result(False)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "route.json"
            with mock.patch("toolkit.trace_route", return_value=data):
                status, stdout, stderr = run_cli([
                    "traceroute", "lab.example", "--json", "--output", str(path),
                ])
            saved = json.loads(path.read_text(encoding="utf-8"))
        result = json.loads(stdout)
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        self.assertFalse(result["ok"])
        self.assertIn("rota incompleta", result["error"])
        self.assertEqual(result["data"]["hops"], data["hops"])
        self.assertEqual(result["data"]["raw_output"], "route example")
        self.assertEqual(saved, result)

    def test_incomplete_text_output_shows_hops_and_stderr(self):
        with mock.patch("toolkit.trace_route", return_value=self.trace_result(False)):
            status, stdout, stderr = run_cli(["traceroute", "lab.example"])
        self.assertEqual(status, 1)
        self.assertIn("192.0.2.1", stdout)
        self.assertIn("*", stdout)
        self.assertIn("Rota incompleta", stdout)
        self.assertIn("rota incompleta", stderr)

    def test_text_route_preserves_upper_bound_and_unreachable_annotation(self):
        data = self.trace_result(False)
        data["hops"][0].update(rtt_ms=1.0, rtt_is_upper_bound=True, annotation="!H")
        with mock.patch("toolkit.trace_route", return_value=data):
            status, stdout, stderr = run_cli(["traceroute", "lab.example"])
        self.assertEqual(status, 1)
        self.assertIn("<1.000 ms !H", stdout)
        self.assertIn("rota incompleta", stderr)


if __name__ == "__main__":
    unittest.main()
