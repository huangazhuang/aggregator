from __future__ import annotations

import re
import unittest
from unittest.mock import patch

from scripts.apply_tcp_probe import should_drop_proxy
from scripts.build_crawler_config import asia_domains
from scripts.cnb_mihomo_filter import (
    new_probe_record,
    percentile,
    run_probe_rounds,
    select_preliminary_candidates,
    select_stable_results,
    summarize_probe_record,
)
from scripts.filter_reachability import select_reachability_passes
from subscribe.asia import is_preferred_asian_proxy


class PreferredAsiaRecognitionTests(unittest.TestCase):
    def test_recognizes_requested_regions_and_explicit_marker(self) -> None:
        for name in (
            "🇭🇰 香港 01",
            "TW-Taipei-02",
            "Singapore 03",
            "JP Tokyo 04",
            "KR Seoul 05",
            "ASIA-KEEP generic-node",
            "日-06",
        ):
            self.assertTrue(is_preferred_asian_proxy({"name": name}), name)

    def test_does_not_treat_status_or_unrelated_nodes_as_preferred(self) -> None:
        for name in ("下次更新时间", "剩余流量 20 GB", "US Los Angeles", "Germany 01"):
            self.assertFalse(is_preferred_asian_proxy({"name": name}), name)


class AsiaSourceTests(unittest.TestCase):
    def test_country_and_mixed_asia_sources_are_kept_without_liveness_filter(self) -> None:
        domains = asia_domains()

        self.assertEqual(len(domains), 9)
        self.assertTrue(all(domain["liveness"] is False for domain in domains))
        self.assertEqual(
            {domain["name"] for domain in domains if domain["name"].startswith("asia-au1rxx-")},
            {
                "asia-au1rxx-hk",
                "asia-au1rxx-tw",
                "asia-au1rxx-sg",
                "asia-au1rxx-jp",
                "asia-au1rxx-kr",
            },
        )
        mixed = [domain for domain in domains if domain["include"]]
        self.assertEqual(len(mixed), 4)
        for domain in mixed:
            self.assertIsNotNone(re.search(domain["include"], "🇸🇬 Singapore 01", flags=re.I))
            self.assertIsNone(re.search(domain["include"], "US Los Angeles 01", flags=re.I))


class AsiaFilterBypassTests(unittest.TestCase):
    def test_tcp_probe_never_drops_requested_asia(self) -> None:
        blocked = {"asia.example:443", "us.example:443"}

        self.assertFalse(
            should_drop_proxy(
                {"name": "🇭🇰 HK 01", "type": "vless", "server": "asia.example", "port": 443},
                blocked,
            )
        )
        self.assertTrue(
            should_drop_proxy(
                {"name": "US 01", "type": "vless", "server": "us.example", "port": 443},
                blocked,
            )
        )

    def test_strict_site_filter_keeps_asia_even_when_it_was_not_tested(self) -> None:
        checks = [
            {"name": "🇹🇼 Taiwan retained"},
            {"name": "ordinary-pass"},
            {"name": "ordinary-fail"},
        ]
        tested = checks[1:]
        masks = [[True, False], [True, True], [True, True]]

        selected = select_reachability_passes(checks, tested, masks)

        self.assertEqual(
            [proxy["name"] for proxy in selected],
            ["🇹🇼 Taiwan retained", "ordinary-pass"],
        )



def probe_summary(
    name: str,
    asia: bool,
    successes: int = 20,
    p90: float = 300.0,
    median: float = 200.0,
    jitter: float = 20.0,
) -> dict:
    return {
        "name": name,
        "preferred_asia": asia,
        "attempts": 20,
        "success_count": successes,
        "success_rate": successes / 20,
        "min_delay_ms": max(median - 20, 1),
        "median_delay_ms": median,
        "p90_delay_ms": p90,
        "max_delay_ms": p90,
        "jitter_ms": jitter,
    }


class CnbStabilitySelectionTests(unittest.TestCase):
    def test_independent_rounds_capture_timeout_then_fast_recovery(self) -> None:
        proxy = {"name": "flaky-node", "type": "vless", "server": "example.com", "port": 443}
        records = {"flaky-node": new_probe_record(proxy)}
        with (
            patch(
                "scripts.cnb_mihomo_filter.api_json",
                side_effect=[TimeoutError("temporary timeout"), {"delay": 80}],
            ),
            patch("scripts.cnb_mihomo_filter.time.sleep") as sleep,
        ):
            run_probe_rounds(
                "127.0.0.1:9090",
                [proxy],
                records,
                "https://www.gstatic.com/generate_204",
                204,
                3000,
                1,
                2,
                0.75,
                "test",
            )

        summary = summarize_probe_record(records["flaky-node"])
        self.assertEqual(summary["samples_ms"], [None, 80])
        self.assertEqual(summary["success_count"], 1)
        self.assertEqual(summary["success_rate"], 0.5)
        sleep.assert_called_once_with(0.75)

    def test_p90_uses_nearest_rank(self) -> None:
        self.assertEqual(percentile(list(range(10, 110, 10)), 0.90), 90.0)

    def test_preliminary_pool_reserves_asia_and_non_asia_even_after_three_failures(self) -> None:
        summaries = [probe_summary(f"asia-{index}", True, successes=0, p90=3000) for index in range(5)]
        summaries += [probe_summary(f"global-{index}", False, successes=3) for index in range(5)]

        selected = select_preliminary_candidates(summaries, 4, 3, 1)

        self.assertEqual(sum(name.startswith("asia-") for name in selected), 3)
        self.assertEqual(sum(name.startswith("global-") for name in selected), 1)

    def test_fourteen_of_twenty_is_qualified_but_thirteen_is_not(self) -> None:
        summaries = [
            probe_summary("pass-14", True, successes=14),
            probe_summary("fail-13", True, successes=13),
        ]

        selected, qualified = select_stable_results(
            summaries,
            0.70,
            0.80,
            2800,
            1,
            2,
            0,
            0,
            0.90,
            2000,
        )

        self.assertEqual([item["name"] for item in qualified], ["pass-14"])
        self.assertEqual([item["name"] for item in selected], ["pass-14"])

    def test_dynamic_capacity_can_reach_150_while_non_asia_stays_at_ten(self) -> None:
        summaries = [probe_summary(f"asia-{index:03d}", True, successes=19) for index in range(140)]
        summaries += [probe_summary(f"global-{index:03d}", False, successes=19) for index in range(30)]

        selected, qualified = select_stable_results(
            summaries,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )

        self.assertEqual(len(qualified), 170)
        self.assertEqual(len(selected), 150)
        self.assertEqual(sum(item["preferred_asia"] for item in selected), 140)
        self.assertEqual(sum(not item["preferred_asia"] for item in selected), 10)

    def test_non_asia_never_exceeds_twenty_when_asia_is_insufficient(self) -> None:
        summaries = [probe_summary(f"asia-{index:03d}", True, successes=19) for index in range(60)]
        summaries += [probe_summary(f"global-{index:03d}", False, successes=19) for index in range(50)]

        selected, _ = select_stable_results(
            summaries,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )

        self.assertEqual(len(selected), 80)
        self.assertEqual(sum(item["preferred_asia"] for item in selected), 60)
        self.assertEqual(sum(not item["preferred_asia"] for item in selected), 20)

    def test_capacity_above_eighty_requires_elite_results(self) -> None:
        base = [probe_summary(f"asia-base-{index:03d}", True, successes=20) for index in range(70)]
        base += [probe_summary(f"global-base-{index:03d}", False, successes=20) for index in range(10)]
        merely_qualified = [
            probe_summary(f"asia-extra-{index:03d}", True, successes=17)
            for index in range(50)
        ]

        selected, _ = select_stable_results(
            base + merely_qualified,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )
        self.assertEqual(len(selected), 80)

        elite = [
            probe_summary(f"asia-elite-{index:03d}", True, successes=18, p90=1500)
            for index in range(70)
        ]
        selected, _ = select_stable_results(
            base + elite,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )
        self.assertEqual(len(selected), 150)

    def test_elite_expansion_uses_exact_success_and_p90_boundaries(self) -> None:
        base = [probe_summary(f"asia-base-{index:03d}", True) for index in range(70)]
        base += [probe_summary(f"global-base-{index:03d}", False) for index in range(10)]
        boundary_cases = [
            probe_summary("elite-boundary-pass", True, successes=18, p90=2000),
            probe_summary("elite-success-fail", True, successes=17, p90=2000),
            probe_summary("elite-p90-fail", True, successes=18, p90=2001),
        ]

        selected, qualified = select_stable_results(
            base + boundary_cases,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )

        selected_names = {item["name"] for item in selected}
        self.assertEqual(len(qualified), 83)
        self.assertEqual(len(selected), 81)
        self.assertIn("elite-boundary-pass", selected_names)
        self.assertNotIn("elite-success-fail", selected_names)
        self.assertNotIn("elite-p90-fail", selected_names)

    def test_non_asia_minimum_is_not_required_when_fewer_are_available(self) -> None:
        summaries = [probe_summary(f"asia-{index:03d}", True, successes=19) for index in range(120)]
        summaries += [probe_summary(f"global-{index:03d}", False, successes=19) for index in range(5)]

        selected, _ = select_stable_results(
            summaries,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )

        self.assertEqual(len(selected), 125)
        self.assertEqual(sum(item["preferred_asia"] for item in selected), 120)
        self.assertEqual(sum(not item["preferred_asia"] for item in selected), 5)

    def test_faster_elite_non_asia_can_expand_from_ten_to_twenty(self) -> None:
        summaries = [
            probe_summary(f"asia-{index:03d}", True, successes=19, p90=500, median=350)
            for index in range(130)
        ]
        summaries += [
            probe_summary(f"global-{index:03d}", False, successes=19, p90=200, median=120)
            for index in range(20)
        ]

        selected, _ = select_stable_results(
            summaries,
            0.70,
            0.80,
            2800,
            80,
            150,
            10,
            20,
            0.90,
            2000,
        )

        self.assertEqual(len(selected), 150)
        self.assertEqual(sum(item["preferred_asia"] for item in selected), 130)
        self.assertEqual(sum(not item["preferred_asia"] for item in selected), 20)


if __name__ == "__main__":
    unittest.main()
