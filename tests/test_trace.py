"""Saídas nativas simuladas mantêm os testes independentes de rede e do SO."""

import socket
import subprocess
import unittest
from unittest import mock

import route_trace


LINUX = """traceroute to 192.0.2.5 (192.0.2.5), 12 hops max, 60 byte packets
 1  192.0.2.1  0.312 ms
 2  *
 3  192.0.2.5  1.120 ms
"""
WINDOWS = """Tracing route to 192.0.2.5 over a maximum of 12 hops:
  1    <1 ms    <1 ms     1 ms  192.0.2.1
  2     *        *        *     Request timed out.
  3     4 ms     3 ms     4 ms  192.0.2.5
Trace complete.
"""


class TraceTests(unittest.TestCase):
    def run_native(self, output=LINUX, system="Linux", destination="192.0.2.5", returncode=0, stderr=""):
        with mock.patch("route_trace.platform.system", return_value=system), \
             mock.patch("route_trace.shutil.which", return_value="/system/traceroute"), \
             mock.patch("route_trace.subprocess.run", return_value=subprocess.CompletedProcess([], returncode, output, stderr)) as run:
            result = route_trace.trace_route(destination)
        return result, run

    def test_linux_success_and_safe_arguments(self):
        result, run = self.run_native()
        self.assertTrue(result["completed"])
        self.assertEqual(result["destination"], "192.0.2.5")
        self.assertEqual(result["hops"][1], {"ttl": 2, "address": None, "rtt_ms": None, "timeout": True})
        self.assertEqual(result["hops"][-1]["rtt_ms"], 1.120)
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/system/traceroute", "-n", "-q", "1", "-m", "12", "-w", "1.0", "192.0.2.5"])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 17)
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")

    def test_zero_exit_without_destination_is_incomplete(self):
        result, _ = self.run_native(output=" 1  192.0.2.1  1.0 ms\n 2 *\n")
        self.assertFalse(result["completed"])
        self.assertFalse(result["timed_out"])

    def test_unreachable_destination_does_not_count_as_arrival(self):
        result, _ = self.run_native(output=" 1 192.0.2.5 0.312 ms !H\n")
        self.assertFalse(result["completed"])
        self.assertEqual(result["hops"][0]["annotation"], "!H")

    def test_windows_three_probes_and_upper_bound(self):
        result, run = self.run_native(output=WINDOWS, system="Windows")
        self.assertTrue(result["completed"])
        self.assertEqual(result["method"], "tracert")
        self.assertTrue(result["hops"][0]["rtt_is_upper_bound"])
        self.assertEqual(result["hops"][0]["probe_rtt_ms"], [1.0, 1.0, 1.0])
        self.assertEqual(run.call_args.args[0], ["/system/traceroute", "-d", "-4", "-h", "12", "-w", "1000", "192.0.2.5"])

    def test_ipv6_linux(self):
        result, run = self.run_native(output=" 1 2001:db8::1 0.1 ms\n", destination="2001:db8::1")
        self.assertTrue(result["completed"])
        self.assertIn("-6", run.call_args.args[0])

    def test_macos_ipv6_uses_dedicated_binary(self):
        with mock.patch("route_trace.platform.system", return_value="Darwin"), \
             mock.patch("route_trace.shutil.which", return_value="/usr/sbin/traceroute6") as which, \
             mock.patch("route_trace.subprocess.run", return_value=subprocess.CompletedProcess([], 0, " 1 ::1 0.100 ms\n", "")) as run:
            result = route_trace.trace_route("::1")
        which.assert_called_once_with("traceroute6")
        self.assertTrue(result["completed"])
        self.assertNotIn("-6", run.call_args.args[0])

    def test_resolves_hostname_before_constructing_command(self):
        answer = (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("192.0.2.5", 0))
        with mock.patch("route_trace.socket.getaddrinfo", return_value=[answer]):
            result, run = self.run_native(destination="lab.example;touch-file")
        self.assertEqual(result["host"], "lab.example;touch-file")
        self.assertEqual(run.call_args.args[0][-1], "192.0.2.5")
        self.assertNotIn("lab.example;touch-file", run.call_args.args[0])

    def test_rejects_options_and_whitespace(self):
        for host in ("-I", "--help", "bad host", "bad\nhost", "", "bad\x00host"):
            with self.subTest(host=host), mock.patch("route_trace.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    route_trace.trace_route(host)
                run.assert_not_called()

    def test_missing_binary_has_actionable_message(self):
        with mock.patch("route_trace.platform.system", return_value="Linux"), mock.patch("route_trace.shutil.which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "apt install traceroute"):
                route_trace.trace_route("127.0.0.1")

    def test_nonzero_status_reports_permission_failure(self):
        with self.assertRaisesRegex(RuntimeError, "Operation not permitted"):
            self.run_native(returncode=1, stderr="socket: Operation not permitted")

    def test_subprocess_timeout_retains_partial_hops(self):
        with mock.patch("route_trace.platform.system", return_value="Linux"), \
             mock.patch("route_trace.shutil.which", return_value="/usr/bin/traceroute"), \
             mock.patch("route_trace.subprocess.run", side_effect=subprocess.TimeoutExpired([], 17, output=b" 1 192.0.2.1 0.5 ms\n", stderr=b"")):
            result = route_trace.trace_route("192.0.2.5")
        self.assertFalse(result["completed"])
        self.assertTrue(result["timed_out"])
        self.assertEqual(result["hops"][0]["address"], "192.0.2.1")

    def test_empty_output_is_execution_failure(self):
        with self.assertRaisesRegex(RuntimeError, "não retornou saltos"):
            self.run_native(output="")

    def test_invalid_limits_fail_before_running(self):
        for options in ({"max_hops": 0}, {"max_hops": 65}, {"max_hops": True}, {"timeout": 0},
                        {"timeout": float("nan")}, {"timeout": float("inf")}, {"timeout": 61}):
            with self.subTest(options=options), mock.patch("route_trace.subprocess.run") as run:
                with self.assertRaises(ValueError):
                    route_trace.trace_route("127.0.0.1", **options)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
