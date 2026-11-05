"""Testes locais: nenhum caso depende de Internet ou de serviços externos."""

import contextlib
import io
import ipaddress
import json
from pathlib import Path
import socket
import subprocess
import sys
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import toolkit  # noqa: E402


def invoke_main(arguments):
    """Executa a CLI no processo atual e captura seus dois canais de saída."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        status = toolkit.main(arguments)
    return status, stdout.getvalue(), stderr.getvalue()


class SubnetTests(unittest.TestCase):
    def test_ipv4_normalizes_address_inside_network(self):
        result = toolkit.subnet_info("192.168.10.42/24")
        self.assertEqual(result["network"], "192.168.10.0/24")
        self.assertEqual(result["version"], 4)
        self.assertEqual(result["prefix_length"], 24)
        self.assertEqual(result["netmask"], "255.255.255.0")
        self.assertEqual(result["broadcast"], "192.168.10.255")
        self.assertEqual(result["total_addresses"], 256)

    def test_ipv4_small_networks_count_all_addresses(self):
        for cidr, network, broadcast, count in (
            ("192.0.2.3/31", "192.0.2.2/31", "192.0.2.3", 2),
            ("192.0.2.3/32", "192.0.2.3/32", "192.0.2.3", 1),
        ):
            with self.subTest(cidr=cidr):
                result = toolkit.subnet_info(cidr)
                self.assertEqual(result["network"], network)
                self.assertEqual(result["broadcast"], broadcast)
                self.assertEqual(result["total_addresses"], count)

    def test_ipv6_large_network_does_not_enumerate_addresses(self):
        # Uma implementação que percorresse /64 seria impraticável.
        with mock.patch.object(ipaddress.IPv6Network, "__iter__",
                               side_effect=AssertionError("não enumere endereços")), \
             mock.patch.object(ipaddress.IPv6Network, "hosts",
                               side_effect=AssertionError("não enumere hosts")):
            result = toolkit.subnet_info("2001:db8::1234/64")
        self.assertEqual(result["network"], "2001:db8::/64")
        self.assertEqual(result["version"], 6)
        self.assertEqual(result["total_addresses"], 18446744073709551616)
        self.assertNotIn("broadcast", result)

    def test_ipv6_single_address(self):
        result = toolkit.subnet_info("2001:db8::1/128")
        self.assertEqual(result["network"], "2001:db8::1/128")
        self.assertEqual(result["prefix_length"], 128)
        self.assertEqual(result["total_addresses"], 1)
        self.assertNotIn("broadcast", result)


class DNSTests(unittest.TestCase):
    def test_dual_stack_answers_are_deduplicated(self):
        ipv4 = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0))
        ipv6 = (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", 0, 0, 0))
        with mock.patch("toolkit.socket.getaddrinfo", return_value=[ipv6, ipv4, ipv4, ipv6]) as resolver:
            result = toolkit.resolve_dns("lab.example")
        self.assertEqual(result["host"], "lab.example")
        self.assertCountEqual(result["addresses"], [
            {"family": "IPv4", "address": "192.0.2.1"},
            {"family": "IPv6", "address": "2001:db8::1"},
        ])
        resolver.assert_called_once_with("lab.example", None,
                                         family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)

    def test_resolver_error_is_reported(self):
        error = socket.gaierror(socket.EAI_NONAME, "nome inexistente")
        with mock.patch("toolkit.socket.getaddrinfo", side_effect=error):
            with self.assertRaises(socket.gaierror):
                toolkit.resolve_dns("missing.example")

    def test_empty_result_is_not_success(self):
        with mock.patch("toolkit.socket.getaddrinfo", return_value=[]):
            with self.assertRaisesRegex(OSError, "não retornou endereços"):
                toolkit.resolve_dns("empty.example")


class TCPTests(unittest.TestCase):
    def test_real_connection_sends_no_data_and_closes(self):
        # Porta efêmera escolhida pelo SO evita depender de uma porta fixa livre.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(2)
            port = listener.getsockname()[1]
            result = toolkit.check_tcp("127.0.0.1", port, 2)
            accepted, _ = listener.accept()
            with accepted:
                accepted.settimeout(2)
                self.assertEqual(accepted.recv(1), b"")
        self.assertEqual(result["host"], "127.0.0.1")
        self.assertEqual(result["port"], port)
        self.assertEqual(result["address"], "127.0.0.1")
        self.assertEqual(result["timeout_seconds"], 2)
        self.assertGreaterEqual(result["duration_ms"], 0)

    def test_timeout_returns_failure_json(self):
        with mock.patch("toolkit.socket.create_connection", side_effect=TimeoutError("tempo esgotado")):
            status, stdout, stderr = invoke_main(["tcp", "127.0.0.1", "8000", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout), {
            "ok": False, "command": "tcp", "error": "tempo esgotado",
        })

    def test_connection_error_returns_failure_json(self):
        with mock.patch("toolkit.socket.create_connection", side_effect=OSError("conexão recusada")):
            status, stdout, stderr = invoke_main(["tcp", "127.0.0.1", "8000", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        self.assertFalse(json.loads(stdout)["ok"])
        self.assertIn("conexão recusada", json.loads(stdout)["error"])


class CLITests(unittest.TestCase):
    def test_subnet_json_success(self):
        status, stdout, stderr = invoke_main(["subnet", "192.0.2.42/24", "--json"])
        result = json.loads(stdout)
        self.assertEqual(status, 0)
        self.assertEqual(stderr, "")
        self.assertTrue(result["ok"])
        self.assertEqual(result["command"], "subnet")
        self.assertEqual(result["data"]["network"], "192.0.2.0/24")
        self.assertEqual(result["data"]["total_addresses"], 256)

    def test_dns_json_failure_preserves_command_and_message(self):
        with mock.patch("toolkit.socket.getaddrinfo", side_effect=OSError("erro de resolução")):
            status, stdout, stderr = invoke_main(["dns", "missing.example", "--json"])
        self.assertEqual(status, 1)
        self.assertEqual(stderr, "")
        self.assertEqual(json.loads(stdout), {
            "ok": False, "command": "dns", "error": "erro de resolução",
        })

    def test_text_failure_goes_to_stderr(self):
        with mock.patch("toolkit.socket.getaddrinfo", side_effect=OSError("erro de resolução")):
            status, stdout, stderr = invoke_main(["dns", "missing.example"])
        self.assertEqual(status, 1)
        self.assertEqual(stdout, "")
        self.assertIn("erro de resolução", stderr)

    def test_port_limits_are_accepted_without_connecting(self):
        for port in ("1", "65535"):
            with self.subTest(port=port):
                arguments = toolkit.build_parser().parse_args(["tcp", "127.0.0.1", port])
                self.assertEqual(arguments.port, int(port))

    def test_valid_timeout_bounds(self):
        for timeout in ("0.01", "60"):
            with self.subTest(timeout=timeout):
                arguments = toolkit.build_parser().parse_args([
                    "tcp", "127.0.0.1", "8000", "--timeout", timeout,
                ])
                self.assertEqual(arguments.timeout, float(timeout))

    def test_invalid_arguments_exit_two_before_network_operations(self):
        cases = [[], ["dns"], ["dns", ""], ["dns", "bad host"],
                 ["subnet", "192.0.2.1/33"], ["subnet", "2001:db8::/129"],
                 ["subnet", "not-a-network"]]
        cases.extend(["tcp", "127.0.0.1", port, "--json"]
                     for port in ("0", "-1", "65536", "abc", "1.5"))
        cases.extend(["tcp", "127.0.0.1", "8000", "--timeout", timeout, "--json"]
                     for timeout in ("nan", "inf", "0", "61", "abc"))
        with mock.patch("toolkit.socket.create_connection") as connect, \
             mock.patch("toolkit.socket.getaddrinfo") as resolve:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        with self.assertRaises(SystemExit) as exit_context:
                            toolkit.main(arguments)
                    self.assertEqual(exit_context.exception.code, 2)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertIn("usage:", stderr.getvalue())
            connect.assert_not_called()
            resolve.assert_not_called()

    def test_real_script_help_exits_successfully(self):
        for arguments in (["--help"], ["dns", "--help"],
                          ["tcp", "--help"], ["subnet", "--help"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([sys.executable, str(ROOT / "toolkit.py"), *arguments],
                                        capture_output=True, text=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                self.assertIn("usage:", result.stdout)

    def test_real_script_emits_json_with_success_exit_code(self):
        result = subprocess.run([
            sys.executable, str(ROOT / "toolkit.py"), "subnet", "2001:db8::/128", "--json",
        ], capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        output = json.loads(result.stdout)
        self.assertTrue(output["ok"])
        self.assertEqual(output["data"]["total_addresses"], 1)
        self.assertNotIn("broadcast", output["data"])


if __name__ == "__main__":
    unittest.main()
