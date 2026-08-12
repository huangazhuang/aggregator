from __future__ import annotations

import unittest

from scripts.proxy_privacy import (
    contains_endpoint_material,
    contains_sensitive_scalar_material,
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

    def test_decodes_basic_authorization_from_mapping_and_list_headers(self) -> None:
        candidate = proxy(
            uuid=None,
            **{
                "xhttp-opts": {
                    "headers": {
                        "Authorization": "Basic dXNlcjpwYXNzMTIz",
                    }
                },
                "ws-opts": {
                    "headers": [
                        {
                            "name": "Proxy-Authorization",
                            "values": ["Basic bGlzdHVzZXI6bGlzdHBhc3M0NTY="],
                        }
                    ]
                },
            },
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {
                "dXNlcjpwYXNzMTIz",
                "user:pass123",
                "user",
                "pass123",
                "bGlzdHVzZXI6bGlzdHBhc3M0NTY=",
                "listuser:listpass456",
                "listuser",
                "listpass456",
            }.issubset(values)
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP USER:PASS123", candidate), ""
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP LISTPASS456", candidate), ""
        )
        self.assertEqual(sanitize_public_proxy_alias("JP USER", candidate), "JP USER")
        self.assertEqual(sanitize_public_proxy_alias("USER", candidate), "")

    def test_arbitrary_header_names_still_hide_authorization_schemes(self) -> None:
        candidate = proxy(
            uuid=None,
            **{
                "xhttp-opts": {
                    "headers": {
                        "X-Foo": "Bearer ARBITRARYBEARERABC123",
                        "X-MBX-APIKEY": "Bearer EXCHANGESECRETABC123",
                    }
                }
            },
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {
                "ARBITRARYBEARERABC123",
                "EXCHANGESECRETABC123",
            }.issubset(values)
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP ARBITRARYBEARERABC123", candidate), ""
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP EXCHANGESECRETABC123", candidate), ""
        )

    def test_digest_and_cookie_values_strip_wrapping_quotes(self) -> None:
        candidate = proxy(
            uuid=None,
            **{
                "ws-opts": {
                    "headers": {
                        "Authorization": (
                            'Digest username="user", nonce="DIGESTNONCEABC123"'
                        ),
                        "Cookie": 'sid="COOKIESECRETABC123"',
                    }
                }
            },
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {"DIGESTNONCEABC123", "COOKIESECRETABC123"}.issubset(values)
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP DIGESTNONCEABC123", candidate), ""
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP COOKIESECRETABC123", candidate), ""
        )

    def test_finds_hysteria_v1_obfs_and_authenticated_ssr_protocol_param(self) -> None:
        hysteria = proxy(
            type="hysteria",
            uuid=None,
            auth="hysteria-auth-secret",
            obfs="hysteria-obfs-secret-123456",
        )
        authenticated_ssr = proxy(
            type="ssr",
            uuid=None,
            password="ssr-password-secret",
            protocol="auth_chain_a",
            **{"protocol-param": "12345:ssr-user-key-secret"},
        )

        self.assertIn(
            "hysteria-obfs-secret-123456",
            set(iter_sensitive_proxy_scalars(hysteria)),
        )
        self.assertTrue(
            {
                "12345:ssr-user-key-secret",
                "12345",
                "ssr-user-key-secret",
            }.issubset(set(iter_sensitive_proxy_scalars(authenticated_ssr)))
        )
        self.assertEqual(
            sanitize_public_proxy_alias(
                "JP HYSTERIA-OBFS-SECRET-123456", hysteria
            ),
            "",
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP SSR-USER-KEY-SECRET", authenticated_ssr),
            "",
        )

    def test_ssr_http_obfs_header_credentials_are_private(self) -> None:
        candidate = proxy(
            type="ssr",
            uuid=None,
            password="ssr-password-secret",
            protocol="origin",
            obfs="http_simple",
            **{
                "protocol-param": "ordinary-public-param",
                "obfs-param": (
                    "front.example#Authorization: Bearer SSRHEADERSECRETABC123\\r\\n"
                    'Cookie: sid="SSRCOOKIESECRETABC123"\\r\\n'
                ),
            },
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {"SSRHEADERSECRETABC123", "SSRCOOKIESECRETABC123"}.issubset(values)
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP SSRHEADERSECRETABC123", candidate), ""
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP SSRCOOKIESECRETABC123", candidate), ""
        )

    def test_does_not_treat_other_obfs_modes_or_plain_ssr_params_as_secrets(self) -> None:
        hysteria2 = proxy(
            type="hysteria2",
            uuid=None,
            password="hy2-password-secret",
            obfs="salamander",
            **{"obfs-password": "hy2-obfs-password-secret"},
        )
        plain_ssr = proxy(
            type="ssr",
            uuid=None,
            password="ssr-password-secret",
            obfs="tls1.2_ticket_auth",
            protocol="origin",
            **{"protocol-param": "ordinary-public-param"},
        )

        self.assertNotIn("salamander", set(iter_sensitive_proxy_scalars(hysteria2)))
        self.assertNotIn(
            "tls1.2_ticket_auth", set(iter_sensitive_proxy_scalars(plain_ssr))
        )
        self.assertNotIn(
            "ordinary-public-param", set(iter_sensitive_proxy_scalars(plain_ssr))
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP salamander", hysteria2), "JP salamander"
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP ordinary-public-param", plain_ssr),
            "JP ordinary-public-param",
        )

    def test_private_key_pem_body_lines_and_tokens_are_secret(self) -> None:
        private_key = """-----BEGIN PRIVATE KEY-----
PRIVATEKEYABC123
MIIEFAKEBASE64PAYLOAD987654321
-----END PRIVATE KEY-----"""
        candidate = proxy(uuid=None, **{"private-key": private_key})

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertIn("PRIVATEKEYABC123", values)
        self.assertIn("MIIEFAKEBASE64PAYLOAD987654321", values)
        self.assertIn("PRIVATEKEYABC123MIIEFAKEBASE64PAYLOAD987654321", values)
        self.assertEqual(
            sanitize_public_proxy_alias("JP privatekeyabc123", candidate), ""
        )

    def test_private_key_pem_body_fragments_are_secret(self) -> None:
        body_line = "MIIEFAKEBASE64PAYLOAD987654321ABCDEFGHIJKLMNOPQRSTUV"
        candidate = proxy(
            uuid=None,
            **{
                "private-key": (
                    "-----BEGIN PRIVATE KEY-----\n"
                    f"{body_line}\n"
                    "-----END PRIVATE KEY-----"
                )
            },
        )

        self.assertEqual(
            sanitize_public_proxy_alias(f"JP {body_line[:16]}", candidate), ""
        )

    def test_reverse_fragment_matching_does_not_drop_ordinary_word_labels(self) -> None:
        candidate = proxy(uuid=None, password="XPREMIUMNODE1Y")

        self.assertEqual(
            sanitize_public_proxy_alias("JP PREMIUMNODE1", candidate),
            "JP PREMIUMNODE1",
        )

    def test_finds_all_strict_xhttp_secret_keys_and_vless_encryption_material(self) -> None:
        encryption_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        encryption = f"mlkem768x25519plus.native.1rtt.{encryption_key}"
        candidate = proxy(
            **{
                "encryption": encryption,
                "xhttp-opts": {
                    "x-padding-key": "padding-secret-123456",
                    "session-key": "session-secret-123456",
                    "seq-key": "sequence-secret-123456",
                    "uplink-data-key": "uplink-secret-123456",
                },
            }
        )

        values = set(iter_sensitive_proxy_scalars(candidate))

        self.assertTrue(
            {
                "padding-secret-123456",
                "session-secret-123456",
                "sequence-secret-123456",
                "uplink-secret-123456",
                encryption,
                encryption_key,
            }.issubset(values)
        )
        self.assertNotIn("none", set(iter_sensitive_proxy_scalars(proxy(encryption="none"))))

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

    def test_secret_matching_is_case_insensitive_but_short_values_stay_exact(self) -> None:
        candidate = proxy(
            uuid="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            password="secretabc123",
        )

        self.assertEqual(
            sanitize_public_proxy_alias(
                "JP AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE", candidate
            ),
            "",
        )
        self.assertEqual(
            sanitize_public_proxy_alias("JP SECRETABC123", candidate), ""
        )
        self.assertEqual(sanitize_public_proxy_alias("KR Premium", proxy(password="kr")), "KR Premium")
        self.assertEqual(sanitize_public_proxy_alias("KR", proxy(password="kr")), "")
        self.assertTrue(
            contains_sensitive_scalar_material("JP SECRETABC123", ["secretabc123"])
        )
        self.assertFalse(contains_sensitive_scalar_material("KR Premium", ["kr"]))

    def test_rejects_xhttp_and_vless_encryption_key_aliases(self) -> None:
        encryption_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        candidate = proxy(
            **{
                "encryption": f"mlkem768x25519plus.native.1rtt.{encryption_key}",
                "xhttp-opts": {
                    "x-padding-key": "padding-secret-123456",
                    "session-key": "session-secret-123456",
                    "seq-key": "sequence-secret-123456",
                    "uplink-data-key": "uplink-secret-123456",
                },
            }
        )

        for alias in (
            "JP PADDING-SECRET-123456",
            "JP session-secret-123456",
            "JP sequence-secret-123456",
            "JP uplink-secret-123456",
            f"JP {encryption_key}",
        ):
            with self.subTest(alias=alias):
                self.assertEqual(sanitize_public_proxy_alias(alias, candidate), "")
        self.assertEqual(
            sanitize_public_proxy_alias("JP encryption none", proxy(encryption="none")),
            "JP encryption none",
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
