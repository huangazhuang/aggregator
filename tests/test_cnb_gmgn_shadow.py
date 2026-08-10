import argparse
import io
import json
import os
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
from pathlib import Path

import yaml

from scripts.cnb_gmgn_shadow import (
    check_shadow_proxy,
    classify_error,
    count_histogram,
    estimate_worst_case_probe_seconds,
    load_fresh_source_snapshot,
    merge_round_trends,
    merge_shadow,
    new_shadow_record,
    partition_proxies,
    run_shadow_rounds,
    summarize_shadow_record,
    threshold_counts,
    validate_common_settings,
)


class ShadowMetricTests(unittest.TestCase):
    def test_1000ms_is_qualified_but_1001ms_is_slow(self):
        summary = summarize_shadow_record(
            {
                "preferred_asia": True,
                "samples_ms": [80, 1000, 1001, None],
            },
            1000,
            node_id="n1_000000000000000000000001",
        )

        self.assertEqual(summary["attempts"], 4)
        self.assertEqual(summary["response_count"], 3)
        self.assertEqual(summary["within_limit_count"], 2)
        self.assertEqual(summary["slow_response_count"], 1)
        self.assertEqual(summary["no_result_count"], 1)

    def test_timeout_then_fast_recovery_is_counted_independently(self):
        summary = summarize_shadow_record(
            {"preferred_asia": True, "samples_ms": [None, 80]},
            1000,
            node_id="n1_000000000000000000000002",
        )

        self.assertEqual(summary["within_limit_count"], 1)
        self.assertEqual(summary["no_result_count"], 1)
        self.assertEqual(summary["within_limit_rate"], 0.5)

    def test_histograms_and_threshold_counts_use_within_limit_rounds(self):
        results = [
            {"preferred_asia": True, "within_limit_count": 18},
            {"preferred_asia": True, "within_limit_count": 14},
            {"preferred_asia": False, "within_limit_count": 20},
            {"preferred_asia": False, "within_limit_count": 9},
        ]

        self.assertEqual(count_histogram(results, "within_limit_count", 20)["18"], 1)
        counts = threshold_counts(results)
        self.assertEqual(counts["18"], {"total": 2, "asia": 1, "non_asia": 1})
        self.assertEqual(counts["14"], {"total": 3, "asia": 2, "non_asia": 1})
        self.assertEqual(counts["10"], {"total": 3, "asia": 2, "non_asia": 1})

    def test_invalid_delay_window_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_common_settings(
                request_timeout_ms=1000,
                qualified_delay_ms=1000,
                total_rounds=20,
                shard_count=4,
            )

    def test_controller_504_is_timeout_and_target_status_is_preserved(self):
        self.assertEqual(classify_error("Gateway Timeout", 504), "timeout")
        self.assertEqual(
            classify_error("unexpected status code: 429", 503), "http_429"
        )

    def test_mihomo_http_error_body_is_kept_for_local_classification(self):
        error = urllib.error.HTTPError(
            "http://127.0.0.1/delay",
            503,
            "Service Unavailable",
            {},
            io.BytesIO(b'{"message":"unexpected status code: 429"}'),
        )
        with patch("scripts.cnb_gmgn_shadow.urllib.request.urlopen", side_effect=error):
            result = check_shadow_proxy(
                "127.0.0.1:19090",
                {"name": "node-a"},
                "https://gmgn.ai/",
                200,
                3000,
            )

        self.assertFalse(result["ok"])
        self.assertEqual(result["controller_status"], 503)
        self.assertEqual(
            classify_error(result["error"], result["controller_status"]), "http_429"
        )

    def test_mihomo_exit_after_last_requests_rejects_the_round(self):
        class Process:
            returncode = 9

            def __init__(self):
                self.polls = 0

            def poll(self):
                self.polls += 1
                return None if self.polls == 1 else self.returncode

        proxy = {"name": "node-a", "type": "ss", "server": "a.example", "port": 1}
        records = {"node-a": new_shadow_record(proxy)}
        with patch(
            "scripts.cnb_gmgn_shadow.check_shadow_proxy",
            return_value={"name": "node-a", "ok": True, "delay_ms": 80, "error": ""},
        ):
            with self.assertRaises(RuntimeError):
                run_shadow_rounds(
                    "127.0.0.1:19090",
                    [proxy],
                    records,
                    target_url="https://gmgn.ai/",
                    expected_status=200,
                    request_timeout_ms=3000,
                    qualified_delay_ms=1000,
                    workers=1,
                    total_rounds=1,
                    round_gap=0,
                    process=Process(),
                    shard_index=0,
                )


class ShadowPartitionTests(unittest.TestCase):
    PROXIES = [
        {"name": "node-a", "type": "ss", "server": "a.example", "port": 1},
        {"name": "node-b", "type": "ss", "server": "b.example", "port": 2},
        {"name": "node-c", "type": "ss", "server": "c.example", "port": 3},
        {"name": "node-d", "type": "ss", "server": "d.example", "port": 4},
        {"name": "node-e", "type": "ss", "server": "e.example", "port": 5},
        {"name": "node-f", "type": "ss", "server": "f.example", "port": 6},
        {"name": "node-g", "type": "ss", "server": "g.example", "port": 7},
    ]

    def test_partition_is_complete_balanced_and_input_order_independent(self):
        first = partition_proxies(self.PROXIES, 4)
        second = partition_proxies(list(reversed(self.PROXIES)), 4)

        first_names = [[proxy["name"] for proxy in shard] for shard in first]
        second_names = [[proxy["name"] for proxy in shard] for shard in second]
        self.assertEqual(first_names, second_names)
        flattened = [name for shard in first_names for name in shard]
        self.assertCountEqual(flattened, [proxy["name"] for proxy in self.PROXIES])
        self.assertEqual(len(flattened), len(set(flattened)))
        sizes = [len(shard) for shard in first]
        self.assertLessEqual(max(sizes) - min(sizes), 1)

    def test_capacity_estimate_accounts_for_all_timeout_batches(self):
        shards = partition_proxies(
            [
                {"name": f"node-{index}", "server": f"{index}.example", "port": index}
                for index in range(5000)
            ],
            4,
        )
        estimate = estimate_worst_case_probe_seconds(
            shards,
            workers_per_shard=16,
            request_timeout_ms=3000,
            total_rounds=20,
            round_gap=0.75,
        )
        self.assertLess(estimate, 6600)

    def test_missing_source_hash_is_rejected_even_when_profile_is_valid(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None) as directory:
            root = Path(directory)
            profile = root / "clash.yaml"
            status = root / "status.json"
            profile.write_text(
                yaml.safe_dump(
                    {
                        "proxies": [
                            {
                                "name": "node-a",
                                "type": "ss",
                                "server": "a.example",
                                "port": 1,
                                "cipher": "aes-128-gcm",
                                "password": "secret",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            status.write_text(
                json.dumps({"run_at": "2026-08-10T00:00:00Z"}), encoding="utf-8"
            )
            with self.assertRaises(RuntimeError):
                load_fresh_source_snapshot(
                    str(profile),
                    str(status),
                    maximum_age_seconds=10**9,
                    wait_seconds=0,
                    poll_seconds=1,
                )


class ShadowWorkflowTests(unittest.TestCase):
    def test_shadow_pipeline_is_isolated_and_uses_four_parallel_jobs(self):
        repository_root = Path(__file__).resolve().parents[1]
        config = yaml.safe_load((repository_root / ".cnb.yml").read_text(encoding="utf-8"))
        shadow = config["main"]["web_trigger_gmgn_shadow"][0]
        official = config["main"]["crontab: 10 11,23 * * *"][0]

        self.assertEqual(official["env"]["TARGET_URL"], "https://www.gstatic.com/generate_204")
        self.assertEqual(shadow["env"]["SHADOW_TARGET_URL"], "https://gmgn.ai/")
        self.assertEqual(shadow["env"]["SHADOW_REQUEST_TIMEOUT_MS"], "3000")
        self.assertEqual(shadow["env"]["SHADOW_QUALIFIED_DELAY_MS"], "1000")
        self.assertEqual(shadow["env"]["SHADOW_TOTAL_ROUNDS"], "20")
        self.assertEqual(shadow["env"]["SHADOW_BRANCH"], "clash-cn-gmgn-shadow")
        self.assertEqual(shadow["env"]["SOURCE_MAX_AGE_SECONDS"], "36000")
        self.assertEqual(shadow["env"]["SHADOW_WORKERS_PER_SHARD"], "16")
        self.assertNotIn("SHADOW_SHARDS", shadow["env"])
        self.assertEqual(shadow["stages"][0]["timeout"], "30m")
        prepare_script = str(shadow["stages"][0]["script"])
        self.assertIn("--shard-count 4", prepare_script)
        self.assertIn("--source-freshness-wait-seconds", prepare_script)
        self.assertIn("--max-estimated-probe-seconds", prepare_script)
        jobs = shadow["stages"][1]["jobs"]
        self.assertEqual(set(jobs), {"shard-0", "shard-1", "shard-2", "shard-3"})
        self.assertTrue(all(job["timeout"] == "120m" for job in jobs.values()))
        scripts = "\n".join(str(job["script"]) for job in jobs.values())
        for port in (19090, 19091, 19092, 19093, 17890, 17891, 17892, 17893):
            self.assertEqual(scripts.count(str(port)), 1)

    def test_shadow_tag_trigger_resolves_to_the_isolated_pipeline(self):
        repository_root = Path(__file__).resolve().parents[1]
        config = yaml.safe_load((repository_root / ".cnb.yml").read_text(encoding="utf-8"))

        shadow = config["main"]["web_trigger_gmgn_shadow"][0]
        self.assertEqual(config["cnb-gmgn-shadow-*"]["tag_push"][0], shadow)

    def test_github_trigger_is_queued_and_restricted_to_main(self):
        repository_root = Path(__file__).resolve().parents[1]
        workflow = yaml.safe_load(
            (repository_root / ".github/workflows/sync-cnb.yml").read_text(encoding="utf-8")
        )

        self.assertFalse(workflow["concurrency"]["cancel-in-progress"])
        steps = workflow["jobs"]["sync"]["steps"]
        validation = next(step for step in steps if step["name"] == "Require main for manual runs")
        self.assertIn("refs/heads/main", validation["run"])
        checkout = next(step for step in steps if step["name"] == "Checkout GitHub main")
        self.assertEqual(checkout["with"]["ref"], "main")


class ShadowMergeTests(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    @staticmethod
    def manifest() -> dict:
        return {
            "kind": "cnb-gmgn-shadow-manifest",
            "schema_version": 1,
            "run_id": "shadow_test",
            "main_sha": "main-sha",
            "source_run_at": "2026-08-10T00:00:00Z",
            "source_sha256": "source-sha",
            "target_url": "https://gmgn.ai/",
            "expected_status": 200,
            "request_timeout_ms": 3000,
            "qualified_delay_ms": 1000,
            "total_rounds": 2,
            "round_gap_seconds": 0.75,
            "shard_count": 1,
            "workers_per_shard": 1,
            "estimated_worst_case_seconds": 100,
            "source_count": 1,
            "source_asia_count": 1,
            "runner": {
                "runner_public_ip": "203.0.113.10",
                "runner_country": "China",
                "runner_region": "Shanghai",
                "runner_org": "example",
                "runner_geo_provider": "test",
            },
            "shards": [
                {
                    "shard_index": 0,
                    "proxy_count": 1,
                    "preferred_asia_count": 1,
                    "profile_file": "shards/shard-0.yaml",
                    "profile_sha256": "shard-sha",
                }
            ],
        }

    @staticmethod
    def fragment() -> dict:
        return {
            "kind": "cnb-gmgn-shadow-fragment",
            "schema_version": 1,
            "run_id": "shadow_test",
            "main_sha": "main-sha",
            "source_sha256": "source-sha",
            "target_url": "https://gmgn.ai/",
            "expected_status": 200,
            "request_timeout_ms": 3000,
            "qualified_delay_ms": 1000,
            "total_rounds": 2,
            "shard_count": 1,
            "shard_index": 0,
            "shard_profile_sha256": "shard-sha",
            "proxy_count": 1,
            "preferred_asia_count": 1,
            "duration_seconds": 1.0,
            "round_trends": [
                {
                    "round": 1,
                    "within_limit_count": 0,
                    "slow_response_count": 0,
                    "no_result_count": 1,
                },
                {
                    "round": 2,
                    "within_limit_count": 1,
                    "slow_response_count": 0,
                    "no_result_count": 0,
                },
            ],
            "error_counts": {"timeout": 1},
            "results": [
                {
                    "node_id": "n1_000000000000000000000003",
                    "preferred_asia": True,
                    "attempts": 2,
                    "response_count": 1,
                    "within_limit_count": 1,
                    "slow_response_count": 0,
                    "no_result_count": 1,
                    "response_rate": 0.5,
                    "within_limit_rate": 0.5,
                    "min_delay_ms": 80,
                    "median_delay_ms": 80,
                    "p90_delay_ms": 80,
                    "max_delay_ms": 80,
                    "jitter_ms": 0,
                }
            ],
        }

    def test_merge_requires_every_fragment(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")
            args = argparse.Namespace(
                manifest=str(manifest_path),
                fragments=[],
                output_dir=str(root / "output"),
                results_url="",
            )

            with self.assertRaises(RuntimeError):
                merge_shadow(args)

    def test_complete_merge_emits_only_redacted_node_data(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            fragment_path = root / "fragment.json"
            manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")
            fragment_path.write_text(json.dumps(self.fragment()), encoding="utf-8")
            output_dir = root / "output"
            args = argparse.Namespace(
                manifest=str(manifest_path),
                fragments=[str(fragment_path)],
                output_dir=str(output_dir),
                results_url="https://example.invalid/gmgn-shadow-results.json",
            )

            self.assertEqual(merge_shadow(args), 0)
            serialized = (output_dir / "gmgn-shadow-results.json").read_text(encoding="utf-8")
            self.assertNotIn("server.example", serialized)
            payload = json.loads(serialized)
            self.assertNotIn("name", payload["results"][0])
            self.assertNotIn("server", payload["results"][0])
            self.assertNotIn("password", payload["results"][0])
            self.assertNotIn("runner_public_ip", serialized)
            self.assertIn("egress region not verified", payload["region_classification"])
            self.assertEqual(payload["results"][0]["within_limit_count"], 1)
            self.assertEqual(payload["round_trends"][1]["within_limit_count"], 1)

    def test_merge_rejects_incomplete_or_unredacted_node_result(self):
        for mutation in ("incomplete", "secret-field"):
            with self.subTest(mutation=mutation), self.temporary_directory() as directory:
                root = Path(directory)
                fragment = self.fragment()
                if mutation == "incomplete":
                    fragment["results"][0]["attempts"] = 0
                else:
                    fragment["results"][0]["server"] = "secret.example"
                manifest_path = root / "manifest.json"
                fragment_path = root / "fragment.json"
                manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")
                fragment_path.write_text(json.dumps(fragment), encoding="utf-8")
                args = argparse.Namespace(
                    manifest=str(manifest_path),
                    fragments=[str(fragment_path)],
                    output_dir=str(root / "output"),
                    results_url="",
                )

                with self.assertRaises(RuntimeError):
                    merge_shadow(args)

    def test_merge_rejects_round_totals_that_do_not_match_nodes(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            fragment = self.fragment()
            fragment["round_trends"][0]["no_result_count"] = 0
            manifest_path = root / "manifest.json"
            fragment_path = root / "fragment.json"
            manifest_path.write_text(json.dumps(self.manifest()), encoding="utf-8")
            fragment_path.write_text(json.dumps(fragment), encoding="utf-8")
            args = argparse.Namespace(
                manifest=str(manifest_path),
                fragments=[str(fragment_path)],
                output_dir=str(root / "output"),
                results_url="",
            )

            with self.assertRaises(RuntimeError):
                merge_shadow(args)

    def test_round_trends_merge_by_round_number(self):
        fragments = [self.fragment(), self.fragment()]
        merged = merge_round_trends(fragments, 2)

        self.assertEqual(merged[0]["no_result_count"], 2)
        self.assertEqual(merged[1]["within_limit_count"], 2)


if __name__ == "__main__":
    unittest.main()
