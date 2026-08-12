from __future__ import annotations

import traceback
import unittest
from unittest.mock import patch

import yaml

from scripts.cnb_mihomo_filter import calculate_cnb_publish_floor, load_optional_json
from scripts.pipeline_utils import (
    ClashYamlSerializationError,
    QuotedString,
    build_candidate_v2_clash_profile,
    calculate_publish_floor,
    dump_clash_yaml,
    exact_unique_proxy_variants,
    filtered_profile,
    normalize_reality_short_ids,
)
from scripts.proxy_identity import canonical_proxy_fingerprint
from subscribe import clash


class PublishFloorTests(unittest.TestCase):
    def test_uses_minimum_when_previous_profile_is_small(self) -> None:
        self.assertEqual(calculate_publish_floor(20, 80, 0.25), 20)

    def test_scales_with_previous_publication(self) -> None:
        self.assertEqual(calculate_publish_floor(20, 240, 0.25), 60)

    def test_dynamic_cnb_policy_can_shrink_from_150_back_to_80(self) -> None:
        self.assertEqual(calculate_publish_floor(80, 150, 0.50), 80)

    def test_cnb_floor_is_lower_than_target_and_ignores_elite_expansion(self) -> None:
        self.assertEqual(calculate_cnb_publish_floor(50, 80, 80, 0.50), (50, 80))
        self.assertEqual(calculate_cnb_publish_floor(50, 150, 80, 0.50), (50, 80))

    def test_rejects_invalid_settings(self) -> None:
        with self.assertRaises(ValueError):
            calculate_publish_floor(0, 80, 0.25)
        with self.assertRaises(ValueError):
            calculate_publish_floor(20, -1, 0.25)
        with self.assertRaises(ValueError):
            calculate_publish_floor(20, 80, 1.1)

    def test_optional_status_loader_returns_json_mapping(self) -> None:
        with patch("scripts.cnb_mihomo_filter.read_source", return_value=b'{"run_at":"now"}'):
            self.assertEqual(load_optional_json("status.json"), {"run_at": "now"})


class RealitySerializationTests(unittest.TestCase):
    def test_shared_serializer_failure_has_fixed_message_and_no_secret_context(self) -> None:
        secret = "shared-yaml-fake-secret-521314"
        with patch(
            "scripts.pipeline_utils.yaml.dump",
            side_effect=yaml.representer.RepresenterError(secret),
        ):
            with self.assertRaises(ClashYamlSerializationError) as raised:
                dump_clash_yaml({"proxies": []})

        self.assertEqual(str(raised.exception), "Clash YAML serialization failed")
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(secret, "".join(traceback.format_exception(raised.exception)))

    def test_string_subclasses_are_double_quoted_without_changing_plain_strings(self) -> None:
        class ForeignQuotedString(str):
            pass

        profile = {
            "plain": "ordinary-text",
            "pipeline-quoted": QuotedString("08"),
            "collector-quoted": clash.QuotedStr("521314"),
            "foreign-quoted": ForeignQuotedString("foreign-value"),
            "proxies": [],
        }

        content, rejected = dump_clash_yaml(profile)

        self.assertEqual(rejected, [])
        self.assertIn("plain: ordinary-text", content)
        self.assertIn('pipeline-quoted: "08"', content)
        self.assertIn('collector-quoted: "521314"', content)
        self.assertIn('foreign-quoted: "foreign-value"', content)
        loaded = yaml.safe_load(content)
        self.assertEqual(loaded["pipeline-quoted"], "08")
        self.assertEqual(loaded["collector-quoted"], "521314")
        self.assertEqual(loaded["foreign-quoted"], "foreign-value")

    def test_numeric_authentication_and_reality_values_remain_strings(self) -> None:
        profile = {
            "proxies": [
                {
                    "name": "numeric-auth",
                    "type": "http",
                    "server": "public.example",
                    "port": 443,
                    "username": clash.QuotedStr("08"),
                    "password": clash.QuotedStr("521314"),
                },
                {
                    "name": "numeric-reality",
                    "type": "vless",
                    "reality-opts": {"short-id": clash.QuotedStr("08")},
                },
            ]
        }

        content, rejected = dump_clash_yaml(profile)

        self.assertEqual(rejected, [])
        self.assertIn('username: "08"', content)
        self.assertIn('password: "521314"', content)
        self.assertIn('short-id: "08"', content)
        loaded = yaml.safe_load(content)["proxies"]
        self.assertEqual(loaded[0]["username"], "08")
        self.assertEqual(loaded[0]["password"], "521314")
        self.assertEqual(loaded[1]["reality-opts"]["short-id"], "08")

    def test_reality_proxy_validation_is_idempotent_after_short_id_quoting(self) -> None:
        proxy = {
            "name": "reality",
            "type": "vless",
            "server": "public.example",
            "port": 443,
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "network": "tcp",
            "tls": True,
            "reality-opts": {
                "public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "short-id": "54462e21",
            },
        }

        self.assertTrue(clash.verify(proxy, mihomo=True))
        self.assertIsInstance(proxy["reality-opts"]["short-id"], clash.QuotedStr)
        self.assertTrue(clash.verify(proxy, mihomo=True))

    def test_reality_proxy_validation_still_rejects_bad_short_ids(self) -> None:
        base = {
            "name": "reality",
            "type": "vless",
            "server": "public.example",
            "port": 443,
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "network": "tcp",
            "tls": True,
            "reality-opts": {
                "public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "short-id": "",
            },
        }

        for short_id in ("abc", "zz", "001122334455667788"):
            with self.subTest(short_id=short_id):
                proxy = yaml.safe_load(yaml.safe_dump(base))
                proxy["reality-opts"]["short-id"] = short_id
                self.assertFalse(clash.verify(proxy, mihomo=True))

    def test_numeric_looking_short_ids_remain_quoted_strings(self) -> None:
        profile = {
            "proxies": [
                {"name": "leading-zero", "type": "vless", "reality-opts": {"short-id": "08"}},
                {
                    "name": "scientific-looking",
                    "type": "vless",
                    "reality-opts": {"short-id": "54462e21"},
                },
            ]
        }

        content, rejected = dump_clash_yaml(profile)

        self.assertEqual(rejected, [])
        self.assertIn('short-id: "08"', content)
        self.assertIn('short-id: "54462e21"', content)
        loaded = yaml.safe_load(content)
        self.assertEqual([item["reality-opts"]["short-id"] for item in loaded["proxies"]], ["08", "54462e21"])

    def test_malformed_short_id_is_rejected_before_mihomo_startup(self) -> None:
        proxies = [
            {"name": "good", "reality-opts": {"short-id": "a0"}},
            {"name": "odd", "reality-opts": {"short-id": "abc"}},
            {"name": "non-hex", "reality-opts": {"short-id": "zz"}},
        ]

        normalized, rejected = normalize_reality_short_ids(proxies)

        self.assertEqual([item["name"] for item in normalized], ["good"])
        self.assertEqual(rejected, ["odd", "non-hex"])


class ProfileFilteringTests(unittest.TestCase):
    def test_filters_proxies_and_group_references_without_breaking_nested_groups(self) -> None:
        profile = {
            "proxies": [{"name": "a"}, {"name": "b"}, {"name": "c"}],
            "proxy-groups": [
                {"name": "auto", "type": "url-test", "proxies": ["a", "b", "c"]},
                {"name": "select", "type": "select", "proxies": ["auto", "DIRECT", "c", "missing"]},
            ],
        }

        output = filtered_profile(profile, [{"name": "c"}, {"name": "a"}])

        self.assertEqual([item["name"] for item in output["proxies"]], ["c", "a"])
        self.assertEqual(output["proxy-groups"][0]["proxies"], ["c", "a"])
        self.assertEqual(output["proxy-groups"][1]["proxies"], ["auto", "DIRECT", "c"])
        self.assertEqual([item["name"] for item in profile["proxies"]], ["a", "b", "c"])


class CandidateV2ExactProfileTests(unittest.TestCase):
    def variants(self) -> list[dict]:
        return [
            {
                "name": "ASIA-KEEP HK shared",
                "type": "ss",
                "server": "shared.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "secret-a",
                "plugin": "obfs",
                "plugin-opts": {"mode": "tls", "host": "one.example"},
            },
            {
                "name": "ASIA-KEEP HK shared",
                "type": "ss",
                "server": "shared.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "secret-a",
                "plugin": "obfs",
                "plugin-opts": {"mode": "tls", "host": "two.example"},
            },
            {
                "name": "ASIA-KEEP HK shared",
                "type": "vless",
                "server": "shared.example",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "network": "ws",
                "ws-opts": {"path": "/one"},
                "tls": True,
            },
            {
                "name": "ASIA-KEEP HK shared",
                "type": "http",
                "server": "shared.example",
                "port": 443,
                "username": "user-one",
                "password": "http-one",
                "tls": True,
            },
            {
                "name": "ASIA-KEEP HK shared",
                "type": "http",
                "server": "shared.example",
                "port": 443,
                "username": "user-two",
                "password": "http-two",
                "tls": True,
            },
        ]

    def test_keeps_same_endpoint_connection_variants_and_folds_only_exact_duplicates(self) -> None:
        variants = self.variants()
        exact_duplicate = yaml.safe_load(yaml.safe_dump(variants[0]))
        exact_duplicate["name"] = "ordinary duplicate alias"

        output = exact_unique_proxy_variants([*variants, exact_duplicate])

        self.assertEqual(len(output), len(variants))
        self.assertEqual(
            {canonical_proxy_fingerprint(proxy) for proxy in output},
            {canonical_proxy_fingerprint(proxy) for proxy in variants},
        )
        self.assertEqual(len({proxy["name"] for proxy in output}), len(output))
        duplicate_result = next(
            proxy
            for proxy in output
            if canonical_proxy_fingerprint(proxy)
            == canonical_proxy_fingerprint(variants[0])
        )
        self.assertEqual(duplicate_result["name"], "ASIA-KEEP HK shared")

    def test_basic_profile_is_deterministic_and_references_every_variant(self) -> None:
        variants = self.variants()

        first = build_candidate_v2_clash_profile(
            variants,
            external_controller="127.0.0.1:9090",
            test_url="https://gmgn.ai/",
        )
        second = build_candidate_v2_clash_profile(
            reversed(variants),
            external_controller="127.0.0.1:9090",
            test_url="https://gmgn.ai/",
        )

        self.assertEqual(first, second)
        names = [proxy["name"] for proxy in first["proxies"]]
        self.assertEqual(first["proxy-groups"][0]["proxies"], names)
        self.assertEqual(first["proxy-groups"][1]["proxies"], ["automatic", *names])

    def test_exact_helper_rejects_unknown_state_and_name_chains(self) -> None:
        proxy = self.variants()[0]
        proxy["metrics"] = {"collector_note": "private-sentinel"}

        with self.assertRaisesRegex(ValueError, "schema is unsupported"):
            exact_unique_proxy_variants([proxy])
        chained = dict(proxy)
        chained.pop("metrics")
        chained["dialer-proxy"] = "upstream-name"
        with self.assertRaisesRegex(ValueError, "schema is unsupported"):
            exact_unique_proxy_variants([chained])


if __name__ == "__main__":
    unittest.main()
