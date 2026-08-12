from __future__ import annotations

import errno
import json
import os
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import yaml

from probe.aliyun_fc_probe import _run, classify_socket_error
from scripts.apply_tcp_probe import TCP_PROBE_SKIP_TYPES, main, should_probe_proxy
from scripts.proxy_identity import canonical_proxy_fingerprint


class ProbeProtocolTests(unittest.TestCase):
    def test_only_udp_protocols_are_skipped(self) -> None:
        self.assertEqual(TCP_PROBE_SKIP_TYPES, {"tuic", "hysteria", "hysteria2"})
        for protocol in ("ss", "ssr", "snell", "http", "socks5", "vmess", "vless", "trojan"):
            self.assertTrue(should_probe_proxy({"type": protocol}), protocol)
        for protocol in TCP_PROBE_SKIP_TYPES:
            self.assertFalse(should_probe_proxy({"type": protocol}), protocol)

    def test_candidate_v2_fc_rewrite_preserves_same_endpoint_variants(self) -> None:
        variants = [
            {
                "name": "shared",
                "type": "ss",
                "server": "shared.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "one",
            },
            {
                "name": "shared",
                "type": "vless",
                "server": "shared.example",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "network": "tcp",
            },
            {
                "name": "drop-third",
                "type": "http",
                "server": "blocked.example",
                "port": 8443,
                "username": "user",
                "password": "password",
            },
        ]
        task_temp = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        with tempfile.TemporaryDirectory(dir=task_temp) as directory:
            root = Path(directory)
            profile = root / "profile.yaml"
            cache = root / "cache.json"
            profile.write_text(yaml.safe_dump({"proxies": variants}), encoding="utf-8")
            cache.write_text(
                json.dumps(
                    {
                        "shared.example:443": {"ok": True, "ts": 2_000_000_000},
                        "blocked.example:8443": {"ok": False, "ts": 2_000_000_000},
                    }
                ),
                encoding="utf-8",
            )

            with (
                patch("scripts.apply_tcp_probe.CACHE_FILE", cache),
                patch("scripts.apply_tcp_probe.time.time", return_value=2_000_000_001),
                patch.dict(
                    os.environ,
                    {
                        "ENABLE_CANDIDATE_V2": "true",
                        "PROFILE_FILE": str(profile),
                    },
                    clear=False,
                ),
            ):
                self.assertEqual(main(), 0)

            output = yaml.safe_load(profile.read_text(encoding="utf-8"))

        self.assertEqual(len(output["proxies"]), 2)
        self.assertEqual(
            {canonical_proxy_fingerprint(proxy) for proxy in output["proxies"]},
            {canonical_proxy_fingerprint(proxy) for proxy in variants[:2]},
        )

    def test_fc_probe_failure_does_not_log_the_raw_exception(self) -> None:
        candidate = {
            "name": "ordinary",
            "type": "ss",
            "server": "public.example",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "safe-secret",
        }
        task_temp = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        with tempfile.TemporaryDirectory(dir=task_temp) as directory:
            root = Path(directory)
            profile = root / "profile.yaml"
            cache = root / "cache.json"
            profile.write_text(
                yaml.safe_dump({"proxies": [candidate]}), encoding="utf-8"
            )
            output = StringIO()
            with (
                patch("scripts.apply_tcp_probe.CACHE_FILE", cache),
                patch(
                    "scripts.apply_tcp_probe.urllib.request.urlopen",
                    side_effect=OSError(
                        "https://probe.invalid/?token=private-sentinel runner=10.0.0.5"
                    ),
                ),
                patch.dict(
                    os.environ,
                    {
                        "PROFILE_FILE": str(profile),
                        "PROBE_URL": "https://probe.invalid/?token=private-sentinel",
                        "PROBE_TOKEN": "private-token",
                    },
                    clear=False,
                ),
                redirect_stdout(output),
            ):
                self.assertEqual(main(), 0)

        logged = output.getvalue()
        self.assertIn("FC probe request failed", logged)
        self.assertNotIn("private-sentinel", logged)
        self.assertNotIn("10.0.0.5", logged)


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
