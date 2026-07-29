from __future__ import annotations

import errno
import socket
import unittest
from unittest.mock import patch

from probe.aliyun_fc_probe import _run, classify_socket_error
from scripts.apply_tcp_probe import TCP_PROBE_SKIP_TYPES, should_probe_proxy


class ProbeProtocolTests(unittest.TestCase):
    def test_only_udp_protocols_are_skipped(self) -> None:
        self.assertEqual(TCP_PROBE_SKIP_TYPES, {"tuic", "hysteria", "hysteria2"})
        for protocol in ("ss", "ssr", "snell", "http", "socks5", "vmess", "vless", "trojan"):
            self.assertTrue(should_probe_proxy({"type": protocol}), protocol)
        for protocol in TCP_PROBE_SKIP_TYPES:
            self.assertFalse(should_probe_proxy({"type": protocol}), protocol)


class SocketErrorClassificationTests(unittest.TestCase):
    def test_refusal_reset_and_abort_prove_endpoint_was_reached(self) -> None:
        self.assertEqual(
            classify_socket_error(ConnectionRefusedError(errno.ECONNREFUSED, "refused")),
            (True, "rejected"),
        )
        self.assertEqual(
            classify_socket_error(ConnectionResetError(errno.ECONNRESET, "reset")),
            (True, "rejected"),
        )
        self.assertEqual(
            classify_socket_error(ConnectionAbortedError(errno.ECONNABORTED, "aborted")),
            (True, "rejected"),
        )

    def test_timeout_dns_and_unreachable_are_not_reachable(self) -> None:
        self.assertEqual(classify_socket_error(socket.timeout("timeout")), (False, "timeout"))
        reachable, label = classify_socket_error(socket.gaierror(socket.EAI_NONAME, "not found"))
        self.assertFalse(reachable)
        self.assertEqual(label, "dns_error")
        self.assertEqual(
            classify_socket_error(OSError(errno.ENETUNREACH, "no route")),
            (False, "unreachable"),
        )

    def test_unknown_oserror_is_fail_closed(self) -> None:
        reachable, label = classify_socket_error(OSError(errno.EACCES, "denied"))
        self.assertFalse(reachable)
        self.assertEqual(label, f"os_error_{errno.EACCES}")

    def test_response_keeps_boolean_compatibility_and_classification_summary(self) -> None:
        details = [
            {"ok": True, "classification": "connected"},
            {"ok": False, "classification": "timeout"},
        ]
        with patch("probe.aliyun_fc_probe._probe_endpoint", side_effect=details):
            result = _run({"endpoints": ["one:1", "two:2"]})

        self.assertEqual(result["ok"], {"one:1": True, "two:2": False})
        self.assertEqual(result["classifications"], {"connected": 1, "timeout": 1})


if __name__ == "__main__":
    unittest.main()
