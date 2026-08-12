from __future__ import annotations

import unittest

from scripts.proxy_privacy import (
    contains_endpoint_material,
    is_public_proxy_alias,
    iter_sensitive_proxy_scalars,
    normalize_public_alias,
    sanitize_public_proxy_alias,
    structured_proxy_name,
)


def proxy(**updates: object) -> dict[str, object]:
    value: dict[str, object] = {
        "name": "JP source",
        "type": "vless",
        "server": "node.example",
        "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
    }
    value.update(updates)
    return value


class EndpointMaterialTests(unittest.TestCase):
    def test_rejects_ipv4_ipv6_domains_urls_and_explicit_ports(self) -> None:
        unsafe = (
            "JP runner 10.0.0.5",
            "JP [2001:db8::5]:8443",
            "JP 2001:4860:4860::8888",
            "JP 2001:db8::",
            "JP fe80::1%eth0",
            "JP node.example",
            "JP 节点.测试",
            "https://secret.example/sub?token=fake",
            "ss://encoded-value",
            "JP :8443",
            "JP port=8443",
            "JP proxy_port 8443",
            "JP 端口443",
        )
        for alias in unsafe:
            with self.subTest(alias=alias):
                self.assertTrue(contains_endpoint_material(alias))

    def test_actual_port_is_private_but_safe_node_numbers_survive(self) -> None:
        self.assertTrue(contains_endpoint_material("JP 443 Premium", actual_port=443))
        self.assertTrue(contains_endpoint_material("JP 0443 Premium", actual_port="443"))
        for alias in ("JP 01", "HK-02", "NRT-01", "TLS1.3", "Version 1.2"):
            with self.subTest(alias=alias):
                self.assertFalse(contains_endpoint_material(alias, actual_port=443))

    def test_actual_single_label_server_is_private_without_short_region_false_positive(self) -> None:
        self.assertTrue(contains_endpoint_material("JP edge-node", actual_server="edge-node"))
        self.assertTrue(contains_endpoint_material("node", actual_server="node"))
        self.assertFalse(contains_endpoint_material("KR Premium", actual_server="kr"))


class SensitiveScalarTests(unittest.TestCase):
    def test_recursively_finds_nested_credentials_and_auth_variants(self) -> None:
        candidate = proxy(
            **{
                "plugin-opts": {"password": "plugin-secret-987654"},
                "reality-opts": {
                    "private-key": "reality-private-abcdef",
                    "public-key": "reality-public-safe",
                },
                "xhttp-opts": {
                    "headers": {
                        "Authorization": "Bearer nested-token-abcdef",
                        "X-Api-Key": "api-secret-uvwxyz",
                        "XApiKey": "camel-api-secret-123456",
                        "X-Auth": "custom-auth-secret-abcdef",
                    }
                },
                "ws-opts": {
                    "headers": {"Cookie": "session=cookie-secret-123456"}
                },
                "auth": [
                    {"username": "nested-user", "password": "nested-pass-654321"}
                ],
            }
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        expected = {
            "00000000-0000-4000-8000-000000000001",
            "plugin-secret-987654",
            "reality-private-abcdef",
            "Bearer nested-token-abcdef",
            "nested-token-abcdef",
            "api-secret-uvwxyz",
            "camel-api-secret-123456",
            "custom-auth-secret-abcdef",
            "session=cookie-secret-123456",
            "cookie-secret-123456",
            "nested-user",
            "nested-pass-654321",
        }
        self.assertTrue(expected.issubset(values))
        self.assertNotIn("reality-public-safe", values)

    def test_public_key_and_tls_fingerprint_are_not_credentials(self) -> None:
        candidate = proxy(
            uuid=None,
            **{
                "fingerprint": "chrome",
                "reality-opts": {"public-key": "public-key-material"},
            },
        )
        self.assertEqual(list(iter_sensitive_proxy_scalars(candidate)), [])
        self.assertEqual(
            sanitize_public_proxy_alias("JP chrome public-key-material", candidate),
            "JP chrome public-key-material",
        )

    def test_finds_tlsmirror_primary_key_and_list_form_header_credentials(self) -> None:
        candidate = proxy(
            uuid=None,
            **{
                "tlsmirror-opts": {
                    "primary-key": "mirror-primary-secret-123456",
                },
                "xhttp-opts": {
                    "headers": [
                        {
                            "name": "Authorization",
                            "value": "Bearer list-auth-token-abcdef",
                        },
                        {
                            "name": "X-Api-Key",
                            "values": [
                                "first-list-api-secret-123456",
                                "second-list-api-secret-654321",
                            ],
                        },
                        {
                            "name": "User-Agent",
                            "value": "ordinary-browser-label",
                        },
                        {
                            "name": "X-Region-Label",
                            "values": ["ordinary-region-label"],
                        },
                    ]
                },
            },
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {
                "mirror-primary-secret-123456",
                "Bearer list-auth-token-abcdef",
                "list-auth-token-abcdef",
                "first-list-api-secret-123456",
                "second-list-api-secret-654321",
            }.issubset(values)
        )
        self.assertNotIn("Authorization", values)
        self.assertNotIn("ordinary-browser-label", values)
        self.assertNotIn("ordinary-region-label", values)

    def test_cycles_do_not_recurse_forever(self) -> None:
        auth: dict[str, object] = {"password": "cycle-secret"}
        auth["child"] = auth
        candidate = proxy(auth=auth)
        self.assertIn("cycle-secret", set(iter_sensitive_proxy_scalars(candidate)))

    def test_scanner_does_not_mutate_the_proxy_tree(self) -> None:
        candidate = proxy(**{"plugin-opts": {"password": "stable-secret"}})
        before = repr(candidate)
        list(iter_sensitive_proxy_scalars(candidate))
        self.assertEqual(repr(candidate), before)


class PublicAliasTests(unittest.TestCase):
    def test_rejects_endpoint_and_nested_secret_aliases(self) -> None:
        candidate = proxy(
            **{
                "plugin-opts": {"password": "nested-secret-987654"},
                "xhttp-opts": {
                    "headers": {"Authorization": "Bearer header-token-abcdef"}
                },
            }
        )
        unsafe = (
            "JP runner 10.0.0.5",
            "JP nested-secret-987654",
            "JP header-token-abcdef",
            "JP node.example",
            "JP 443",
            "JP password=unrelated-secret",
        )
        for alias in unsafe:
            with self.subTest(alias=alias):
                self.assertEqual(sanitize_public_proxy_alias(alias, candidate), "")

    def test_keeps_normal_asia_labels_and_only_strips_dynamic_suffixes(self) -> None:
        candidate = proxy(password="KR")
        expected = {
            "JP 01": "JP 01",
            "HK-02": "HK-02",
            "NRT-01": "NRT-01",
            "🇰🇷 Korea Premium": "🇰🇷 Korea Premium",
            "Japan Fast | 80ms": "Japan Fast",
            "Korea Timeout": "Korea",
            "KR Premium": "KR Premium",
        }
        for alias, result in expected.items():
            with self.subTest(alias=alias):
                self.assertEqual(sanitize_public_proxy_alias(alias, candidate), result)
        self.assertEqual(sanitize_public_proxy_alias("KR", candidate), "")

    def test_checks_private_material_before_truncating(self) -> None:
        candidate = proxy(**{"plugin-opts": {"password": "late-secret-abcdef"}})
        alias = "JP " + "A" * 120 + " late-secret-abcdef"
        self.assertEqual(sanitize_public_proxy_alias(alias, candidate), "")

    def test_rejects_tlsmirror_and_list_header_secret_aliases(self) -> None:
        candidate = proxy(
            **{
                "tlsmirror-opts": {
                    "primary-key": "mirror-primary-secret-123456",
                },
                "xhttp-opts": {
                    "headers": [
                        {
                            "name": "Authorization",
                            "value": "Bearer list-auth-token-abcdef",
                        },
                        {
                            "name": "X-Api-Key",
                            "values": ["list-api-secret-123456"],
                        },
                        {
                            "name": "User-Agent",
                            "value": "ordinary-browser-label",
                        },
                    ]
                },
            }
        )

        unsafe = (
            "JP mirror-primary-secret-123456",
            "JP Bearer list-auth-token-abcdef",
            "JP list-auth-token-abcdef",
            "JP list-api-secret-123456",
        )
        for alias in unsafe:
            with self.subTest(alias=alias):
                self.assertEqual(sanitize_public_proxy_alias(alias, candidate), "")
        self.assertEqual(
            sanitize_public_proxy_alias("JP ordinary-browser-label", candidate),
            "JP ordinary-browser-label",
        )

    def test_validator_requires_canonical_safe_form(self) -> None:
        candidate = proxy()
        self.assertTrue(is_public_proxy_alias("JP 01", candidate))
        self.assertFalse(is_public_proxy_alias(" JP 01 ", candidate))
        self.assertFalse(is_public_proxy_alias("JP node.example", candidate))
        self.assertFalse(is_public_proxy_alias("", candidate))

    def test_normalizer_is_formatting_only_and_bounded(self) -> None:
        self.assertEqual(normalize_public_alias("  JP\x00 01 | 80ms  "), "JP 01")
        self.assertEqual(normalize_public_alias("A" * 120), "A" * 96)
        with self.assertRaises(ValueError):
            normalize_public_alias("JP", max_length=0)


class StructuredFallbackTests(unittest.TestCase):
    def test_builds_deterministic_region_and_protocol_names(self) -> None:
        self.assertEqual(
            structured_proxy_name(
                region_hints=["JP", "HK", "JP", "unknown"],
                protocol="ss",
                protected_asia=True,
            ),
            "ASIA-KEEP HK-JP SS",
        )
        self.assertEqual(
            structured_proxy_name(region_hints=[], protocol="vless"),
            "CANDIDATE VLESS",
        )
        self.assertEqual(
            structured_proxy_name(
                region_hints=[], protocol="unsafe endpoint.example", protected_asia=True
            ),
            "ASIA-KEEP NODE",
        )

    def test_fallback_never_uses_raw_proxy_material(self) -> None:
        name = structured_proxy_name(
            region_hints=["KR"],
            protocol="../../../password=secret",
            protected_asia=True,
        )
        self.assertEqual(name, "ASIA-KEEP KR NODE")
        self.assertFalse(contains_endpoint_material(name))


if __name__ == "__main__":
    unittest.main()
