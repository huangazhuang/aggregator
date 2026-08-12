from __future__ import annotations

import copy
import unittest

from scripts.proxy_schema import (
    PROXY_SCHEMA_POLICY_VERSION,
    SUPPORTED_PROXY_TYPES,
    ProxySchemaError,
    connection_proxy_projection,
    validate_proxy_schema,
)


UUID = "12345678-1234-1234-1234-123456789abc"
CERTIFICATE = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----"
PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----"


def fixtures() -> dict[str, dict]:
    return {
        "ss": {
            "name": "SS",
            "type": "ss",
            "server": "ss.example",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "secret",
            "plugin": "obfs",
            "plugin-opts": {"mode": "tls", "host": "front.example"},
        },
        "ssr": {
            "name": "SSR",
            "type": "ssr",
            "server": "ssr.example",
            "port": 443,
            "cipher": "chacha20-ietf",
            "password": "secret",
            "obfs": "tls1.2_ticket_auth",
            "protocol": "auth_sha1_v4",
        },
        "vmess": {
            "name": "VMess",
            "type": "vmess",
            "server": "vmess.example",
            "port": 443,
            "uuid": UUID,
            "alterId": 0,
            "cipher": "auto",
            "network": "ws",
            "tls": True,
            "fingerprint": "AA:BB",
            "ws-opts": {
                "path": "/ws",
                "headers": {"Host": "front.example", "X-Test": "one"},
            },
        },
        "vless": {
            "name": "VLESS",
            "type": "vless",
            "server": "vless.example",
            "port": 443,
            "uuid": UUID,
            "network": "grpc",
            "tls": True,
            "grpc-opts": {
                "grpc-service-name": "service",
                "grpc-user-agent": "mihomo",
            },
            "reality-opts": {
                "public-key": "fixture-public-key",
                "short-id": "08",
            },
        },
        "trojan": {
            "name": "Trojan",
            "type": "trojan",
            "server": "trojan.example",
            "port": 443,
            "password": "secret",
            "network": "ws",
            "fingerprint": "CC:DD",
            "ws-opts": {"path": "/trojan", "headers": {"Host": "front.example"}},
        },
        "snell": {
            "name": "Snell",
            "type": "snell",
            "server": "snell.example",
            "port": 44046,
            "psk": "secret",
            "version": 4,
            "obfs-opts": {"mode": "jls", "host": "front.example", "username": "u", "password": "p"},
        },
        "http": {
            "name": "HTTP",
            "type": "http",
            "server": "http.example",
            "port": 443,
            "tls": True,
            "username": "user",
            "password": "secret",
            "fingerprint": "EE:FF",
            "headers": {"X-Trace": "safe"},
        },
        "socks5": {
            "name": "SOCKS",
            "type": "socks5",
            "server": "socks.example",
            "port": 443,
            "tls": True,
            "username": "user",
            "password": "secret",
            "fingerprint": "11:22",
        },
        "tuic": {
            "name": "TUIC",
            "type": "tuic",
            "server": "tuic.example",
            "port": 443,
            "uuid": UUID,
            "password": "secret",
            "udp-relay-mode": "native",
            "congestion-controller": "bbr",
            "fingerprint": "33:44",
        },
        "hysteria": {
            "name": "Hysteria",
            "type": "hysteria",
            "server": "hy.example",
            "port": 443,
            "auth-str": "secret",
            "up": "30 Mbps",
            "down": "200 Mbps",
            "protocol": "udp",
            "fingerprint": "55:66",
        },
        "hysteria2": {
            "name": "Hysteria2",
            "type": "hysteria2",
            "server": "hy2.example",
            "port": 443,
            "password": "secret",
            "obfs": "salamander",
            "obfs-password": "obfs-secret",
            "fingerprint": "77:88",
        },
        "anytls": {
            "name": "AnyTLS",
            "type": "anytls",
            "server": "anytls.example",
            "port": 443,
            "password": "secret",
            "fingerprint": "99:AA",
            "client-fingerprint": "chrome",
            "udp": True,
        },
    }


class ProxySchemaTests(unittest.TestCase):
    def test_all_supported_protocol_fixtures_pass_and_are_copied(self) -> None:
        values = fixtures()
        self.assertEqual(set(values), set(SUPPORTED_PROXY_TYPES))
        self.assertEqual(PROXY_SCHEMA_POLICY_VERSION, "candidate-proxy-schema-v1")

        for protocol, proxy in values.items():
            with self.subTest(protocol=protocol):
                original = copy.deepcopy(proxy)
                validated = validate_proxy_schema(proxy)
                self.assertEqual(validated, original)
                self.assertIsNot(validated, proxy)
                if "ws-opts" in proxy:
                    self.assertIsNot(validated["ws-opts"], proxy["ws-opts"])

    def test_connection_projection_drops_only_name_and_keeps_tls_fingerprint(self) -> None:
        proxy = fixtures()["anytls"]

        projection = connection_proxy_projection(proxy)

        self.assertNotIn("name", projection)
        self.assertEqual(projection["fingerprint"], "99:AA")
        self.assertEqual(set(projection), set(proxy) - {"name"})

    def test_unknown_top_level_cross_protocol_and_dialer_fields_are_rejected(self) -> None:
        cases = {
            "unknown": ("ss", "collector_note", "internal"),
            "cross_protocol": ("ss", "uuid", UUID),
            "dialer": ("vless", "dialer-proxy", "upstream"),
            "private_prefix": ("http", "_private", "value"),
        }
        values = fixtures()
        for label, (protocol, field, value) in cases.items():
            with self.subTest(label=label), self.assertRaises(ProxySchemaError):
                proxy = copy.deepcopy(values[protocol])
                proxy[field] = value
                validate_proxy_schema(proxy)

    def test_unknown_nested_fields_and_invalid_header_names_are_rejected(self) -> None:
        cases = []
        vless = fixtures()["vless"]
        vless["grpc-opts"]["collector-note"] = "private"
        cases.append(vless)

        ss = fixtures()["ss"]
        ss["plugin-opts"]["password"] = "nested-secret"
        cases.append(ss)

        vmess = fixtures()["vmess"]
        vmess["ws-opts"]["headers"]["Bad\nHeader"] = "value"
        cases.append(vmess)

        for proxy in cases:
            with self.subTest(protocol=proxy["type"]), self.assertRaises(ProxySchemaError):
                validate_proxy_schema(proxy)

    def test_transport_options_must_match_network(self) -> None:
        for protocol, field in (
            ("vmess", "grpc-opts"),
            ("vless", "xhttp-opts"),
            ("trojan", "grpc-opts"),
        ):
            with self.subTest(protocol=protocol, field=field), self.assertRaises(
                ProxySchemaError
            ):
                proxy = fixtures()[protocol]
                proxy[field] = (
                    {"grpc-service-name": "service"}
                    if field == "grpc-opts"
                    else {"path": "/"}
                )
                validate_proxy_schema(proxy)

    def test_dynamic_header_keys_are_allowed_with_position_specific_value_types(self) -> None:
        vmess = fixtures()["vmess"]
        vmess["ws-opts"]["headers"] = {
            "X-Arbitrary-Header": "one",
            "Sec-WebSocket-Protocol": "two",
        }
        http_transport = fixtures()["vless"]
        http_transport["network"] = "http"
        http_transport.pop("grpc-opts")
        http_transport["http-opts"] = {
            "path": ["/one", "/two"],
            "headers": {"X-Arbitrary-Header": ["one", "two"]},
        }

        self.assertEqual(
            validate_proxy_schema(vmess)["ws-opts"]["headers"],
            vmess["ws-opts"]["headers"],
        )
        self.assertEqual(
            validate_proxy_schema(http_transport)["http-opts"]["headers"],
            http_transport["http-opts"]["headers"],
        )

        bad = copy.deepcopy(http_transport)
        bad["http-opts"]["headers"]["X-Arbitrary-Header"] = "not-a-list"
        with self.assertRaises(ProxySchemaError):
            validate_proxy_schema(bad)

    def test_compatibility_aliases_normalize_equal_duplicates_and_reject_conflicts(self) -> None:
        proxy = fixtures()["hysteria"]
        proxy.update(
            {
                "auth_str": proxy["auth-str"],
                "recv_window_conn": 100,
                "recv-window-conn": 100,
                "recv_window": 200,
                "disable_mtu_discovery": False,
            }
        )

        normalized = validate_proxy_schema(proxy)

        self.assertNotIn("auth_str", normalized)
        self.assertNotIn("recv_window_conn", normalized)
        self.assertNotIn("recv_window", normalized)
        self.assertNotIn("disable_mtu_discovery", normalized)
        self.assertEqual(normalized["auth-str"], "secret")
        self.assertEqual(normalized["recv-window-conn"], 100)
        self.assertEqual(normalized["recv-window"], 200)
        self.assertFalse(normalized["disable-mtu-discovery"])

        conflict = copy.deepcopy(proxy)
        conflict["auth_str"] = "different"
        with self.assertRaisesRegex(ProxySchemaError, "conflicting"):
            validate_proxy_schema(conflict)

    def test_hysteria2_auth_compatibility_alias_matches_password(self) -> None:
        proxy = fixtures()["hysteria2"]
        proxy["auth"] = proxy["password"]

        normalized = validate_proxy_schema(proxy)

        self.assertNotIn("auth", normalized)
        self.assertEqual(normalized["password"], "secret")

        proxy["auth"] = "different"
        with self.assertRaisesRegex(ProxySchemaError, "conflicting"):
            validate_proxy_schema(proxy)

    def test_certificate_and_private_key_are_inline_only_and_paired(self) -> None:
        proxy = fixtures()["anytls"]
        proxy["certificate"] = CERTIFICATE
        proxy["private-key"] = PRIVATE_KEY
        self.assertEqual(validate_proxy_schema(proxy)["private-key"], PRIVATE_KEY)

        for certificate, private_key in (
            (r"C:\secret\cert.pem", PRIVATE_KEY),
            (CERTIFICATE, r"C:\secret\key.pem"),
            (CERTIFICATE, None),
        ):
            with self.subTest(
                certificate=certificate, private_key=private_key
            ), self.assertRaises(ProxySchemaError):
                candidate = fixtures()["anytls"]
                candidate["certificate"] = certificate
                if private_key is not None:
                    candidate["private-key"] = private_key
                validate_proxy_schema(candidate)

    def test_embedded_secondary_endpoints_are_explicitly_rejected(self) -> None:
        vless = fixtures()["vless"]
        vless["network"] = "xhttp"
        vless.pop("grpc-opts")
        vless["xhttp-opts"] = {
            "path": "/",
            "download-settings": {"server": "10.0.0.1", "port": 443},
        }
        hysteria2 = fixtures()["hysteria2"]
        hysteria2["realm-opts"] = {
            "enable": True,
            "server-url": "https://10.0.0.1/",
        }

        for proxy in (vless, hysteria2):
            with self.subTest(protocol=proxy["type"]), self.assertRaisesRegex(
                ProxySchemaError, "unsupported"
            ):
                validate_proxy_schema(proxy)

    def test_plugin_and_plugin_options_must_match(self) -> None:
        missing_plugin = fixtures()["ss"]
        missing_plugin.pop("plugin")
        unsupported_plugin = fixtures()["ss"]
        unsupported_plugin["plugin"] = "unknown-plugin"
        wrong_mode = fixtures()["ss"]
        wrong_mode["plugin-opts"]["mode"] = "websocket"

        for proxy in (missing_plugin, unsupported_plugin, wrong_mode):
            with self.assertRaises(ProxySchemaError):
                validate_proxy_schema(proxy)

    def test_anytls_tls_fingerprint_variants_remain_distinct(self) -> None:
        first = fixtures()["anytls"]
        second = copy.deepcopy(first)
        second["name"] = "AnyTLS second"
        second["fingerprint"] = "BB:CC"

        first_projection = connection_proxy_projection(first)
        second_projection = connection_proxy_projection(second)

        self.assertNotEqual(first_projection, second_projection)
        self.assertEqual(first_projection["fingerprint"], "99:AA")
        self.assertEqual(second_projection["fingerprint"], "BB:CC")


if __name__ == "__main__":
    unittest.main()
