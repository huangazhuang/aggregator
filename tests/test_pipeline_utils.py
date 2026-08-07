from __future__ import annotations

import unittest
from unittest.mock import patch

import yaml

from scripts.cnb_mihomo_filter import load_optional_json
from scripts.pipeline_utils import (
    calculate_publish_floor,
    dump_clash_yaml,
    filtered_profile,
    normalize_reality_short_ids,
)


class PublishFloorTests(unittest.TestCase):
    def test_uses_minimum_when_previous_profile_is_small(self) -> None:
        self.assertEqual(calculate_publish_floor(20, 80, 0.25), 20)

    def test_scales_with_previous_publication(self) -> None:
        self.assertEqual(calculate_publish_floor(20, 240, 0.25), 60)

    def test_dynamic_cnb_policy_can_shrink_from_150_back_to_80(self) -> None:
        self.assertEqual(calculate_publish_floor(80, 150, 0.50), 80)

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


if __name__ == "__main__":
    unittest.main()
