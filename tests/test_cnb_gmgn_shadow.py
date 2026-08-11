import argparse
import copy
import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from unittest.mock import patch
from pathlib import Path

import yaml

from scripts.cnb_gmgn_shadow import (
    FORMAL_TOTAL_ROUNDS,
    SELECTION_FRAGMENT_SCHEMA_VERSION,
    SELECTION_RESULT_FIELDS,
    SHADOW_SCHEMA_VERSION,
    build_parser,
    check_shadow_proxy,
    classify_error,
    count_histogram,
    estimate_worst_case_probe_seconds,
    file_sha256,
    load_fresh_source_snapshot,
    merge_round_trends,
    merge_shadow,
    new_shadow_record,
    partition_proxies,
    run_shadow_rounds,
    summarize_shadow_record,
    threshold_counts,
    validate_common_settings,
    validate_prepare_settings,
    validate_private_output_paths,
    validate_selection_fragment,
    validate_shadow_manifest,
    wait_for_shadow_mihomo,
    write_json_atomic,
    probe_shadow_shard,
)


TEST_RUN_ID = "shadow_" + "1" * 32
TEST_MAIN_SHA = "a" * 40
TEST_SOURCE_SHA = "b" * 64
TEST_SHARD_SHA = "c" * 64


def formal_manifest(shards: list[dict], *, total_rounds: int = 20) -> dict:
    return {
        "kind": "cnb-gmgn-shadow-manifest",
        "schema_version": SHADOW_SCHEMA_VERSION,
        "run_id": TEST_RUN_ID,
        "prepared_at": "2026-08-10T00:05:00Z",
        "main_sha": TEST_MAIN_SHA,
        "source_run_at": "2026-08-10T00:00:00Z",
        "source_sha256": TEST_SOURCE_SHA,
        "source_age_seconds": 300,
        "source_count": sum(int(shard["proxy_count"]) for shard in shards),
        "source_asia_count": sum(
            int(shard["preferred_asia_count"]) for shard in shards
        ),
        "rejected_reality_count": 0,
        "target_url": "https://gmgn.ai/",
        "expected_status": 200,
        "request_timeout_ms": 3000,
        "qualified_delay_ms": 1000,
        "total_rounds": total_rounds,
        "round_gap_seconds": 0.75,
        "shard_count": len(shards),
        "workers_per_shard": 1,
        "estimated_worst_case_seconds": 100.0,
        "runner": {
            "runner_country": "China",
            "runner_region": "Shanghai",
            "runner_org": "example",
            "runner_geo_provider": "test",
        },
        "shards": shards,
    }


def one_success_round_trends(success_round: int = 20) -> list[dict]:
    return [
        {
            "round": round_index,
            "within_limit_count": int(round_index == success_round),
            "slow_response_count": 0,
            "no_result_count": int(round_index != success_round),
        }
        for round_index in range(1, 21)
    ]


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

    def test_half_and_five_round_windows_are_counted(self):
        summary = summarize_shadow_record(
            {
                "preferred_asia": True,
                "samples_ms": [
                    100,
                    1100,
                    None,
                    1200,
                    1300,
                    200,
                    300,
                    1500,
                    None,
                    1600,
                    400,
                    500,
                    600,
                    1100,
                    None,
                    700,
                    800,
                    900,
                    1000,
                    1001,
                ],
            },
            1000,
            node_id="n1_000000000000000000000004",
        )

        self.assertEqual(summary["within_limit_count"], 10)
        self.assertEqual(summary["first_half_within_limit_count"], 3)
        self.assertEqual(summary["second_half_within_limit_count"], 7)
        self.assertEqual(summary["within_limit_count_rounds_1_5"], 1)
        self.assertEqual(summary["within_limit_count_rounds_6_10"], 2)
        self.assertEqual(summary["within_limit_count_rounds_11_15"], 3)
        self.assertEqual(summary["within_limit_count_rounds_16_20"], 4)

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

    def test_formal_prepare_rejects_nineteen_and_twenty_one_rounds(self):
        for total_rounds in (19, 21):
            with self.subTest(total_rounds=total_rounds):
                args = argparse.Namespace(
                    request_timeout_ms=3000,
                    qualified_delay_ms=1000,
                    total_rounds=total_rounds,
                    shard_count=4,
                    main_sha="a" * 40,
                    target_url="https://gmgn.ai/",
                    expected_status=200,
                    source_max_age_seconds=36000,
                    source_freshness_wait_seconds=0,
                    source_freshness_poll_seconds=60,
                    round_gap=0.75,
                    workers_per_shard=16,
                    max_estimated_probe_seconds=0,
                )

                with self.assertRaisesRegex(ValueError, "exactly 20 rounds"):
                    validate_prepare_settings(args)

    def test_formal_prepare_rejects_non_production_target_settings(self):
        base = dict(
            request_timeout_ms=3000,
            qualified_delay_ms=1000,
            total_rounds=20,
            shard_count=4,
            main_sha="a" * 40,
            target_url="https://gmgn.ai/",
            expected_status=200,
            source_max_age_seconds=36000,
            source_freshness_wait_seconds=0,
            source_freshness_poll_seconds=60,
            round_gap=0.75,
            workers_per_shard=16,
            max_estimated_probe_seconds=0,
        )
        for field, value in (
            ("target_url", "https://example.com/"),
            ("expected_status", 204),
            ("request_timeout_ms", 2000),
            ("qualified_delay_ms", 999),
        ):
            with self.subTest(field=field):
                values = dict(base)
                values[field] = value
                with self.assertRaisesRegex(ValueError, "formal GMGN"):
                    validate_prepare_settings(argparse.Namespace(**values))

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


class ShadowPrivacyTests(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    def test_private_atomic_json_is_created_with_restrictive_mode(self):
        with self.temporary_directory() as directory:
            path = Path(directory) / "private.json"
            with patch(
                "scripts.cnb_gmgn_shadow.os.open", wraps=os.open
            ) as secure_open:
                write_json_atomic(path, {"secret": "value"}, mode=0o600)

            _temporary, flags, create_mode = secure_open.call_args.args
            self.assertEqual(create_mode, 0o600)
            self.assertTrue(flags & os.O_EXCL)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_private_startup_failure_never_echoes_mihomo_log_tail(self):
        class Process:
            returncode = 9

            def poll(self):
                return self.returncode

        with patch(
            "scripts.cnb_gmgn_shadow.wait_for_mihomo",
            side_effect=RuntimeError(
                "Mihomo exited: node=Japan-secret password=private-password"
            ),
        ):
            with self.assertRaises(RuntimeError) as raised:
                wait_for_shadow_mihomo(
                    "127.0.0.1:19090",
                    Process(),
                    Path("private-mihomo.log"),
                )

        message = str(raised.exception)
        self.assertIn("contents were suppressed", message)
        self.assertNotIn("Japan-secret", message)
        self.assertNotIn("private-password", message)


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


class ShadowProbeTests(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    def test_probe_parser_accepts_optional_private_selection_output(self):
        args = build_parser().parse_args(
            [
                "probe",
                "--manifest",
                "manifest.json",
                "--shard-index",
                "0",
                "--mihomo",
                "mihomo",
                "--work-dir",
                "work",
                "--output",
                "public.json",
                "--selection-output",
                "private.json",
                "--private-output-root",
                ".cnb-runtime/private",
                "--controller-port",
                "19090",
                "--mixed-port",
                "17890",
            ]
        )

        self.assertEqual(args.selection_output, "private.json")
        self.assertEqual(args.private_output_root, ".cnb-runtime/private")

    def test_probe_rejects_an_old_manifest_schema_before_loading_a_shard(self):
        with self.temporary_directory() as directory:
            manifest_path = Path(directory) / "manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "kind": "cnb-gmgn-shadow-manifest",
                        "schema_version": SHADOW_SCHEMA_VERSION - 1,
                    }
                ),
                encoding="utf-8",
            )
            args = argparse.Namespace(manifest=str(manifest_path), shard_index=0)

            with self.assertRaisesRegex(RuntimeError, "manifest schema"):
                probe_shadow_shard(args)

    def test_probe_strictly_validates_manifest_before_loading_a_shard(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            manifest = formal_manifest(
                [
                    {
                        "shard_index": 0,
                        "proxy_count": 1,
                        "preferred_asia_count": 0,
                        "profile_file": "missing-shard.yaml",
                        "profile_sha256": TEST_SHARD_SHA,
                    }
                ]
            )
            del manifest["runner"]
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "manifest fields"):
                probe_shadow_shard(
                    argparse.Namespace(manifest=str(manifest_path), shard_index=0)
                )

    def test_probe_rejects_non_twenty_round_manifests_before_shard_io(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            for total_rounds in (19, 21):
                with self.subTest(total_rounds=total_rounds):
                    manifest = formal_manifest(
                        [
                            {
                                "shard_index": 0,
                                "proxy_count": 1,
                                "preferred_asia_count": 0,
                                "profile_file": "missing-shard.yaml",
                                "profile_sha256": TEST_SHARD_SHA,
                            }
                        ],
                        total_rounds=total_rounds,
                    )
                    manifest_path = root / f"manifest-{total_rounds}.json"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

                    with self.assertRaisesRegex(RuntimeError, "exactly 20 rounds"):
                        probe_shadow_shard(
                            argparse.Namespace(
                                manifest=str(manifest_path), shard_index=0
                            )
                        )

    def test_private_output_root_rejects_public_git_and_escape_paths(self):
        with self.temporary_directory() as directory:
            root = Path(directory).resolve()
            valid_private = root / ".cnb-runtime" / "gmgn-shadow" / "selection"
            redacted = root / "public-cn-shadow" / "fragment.json"
            selection = valid_private / "selection.json"
            validate_private_output_paths(redacted, selection, valid_private)

            cases = (
                (
                    redacted,
                    root / "private" / "selection.json",
                    root / "private",
                    r"\.cnb-runtime",
                ),
                (
                    redacted,
                    root / ".cnb-runtime" / "public-cn-secret" / "selection.json",
                    root / ".cnb-runtime" / "public-cn-secret",
                    "public-cn",
                ),
                (
                    redacted,
                    root / ".git" / ".cnb-runtime" / "selection.json",
                    root / ".git" / ".cnb-runtime",
                    r"\.git",
                ),
                (
                    redacted,
                    root / "outside.json",
                    valid_private,
                    "inside the private output root",
                ),
                (
                    valid_private / "public-fragment.json",
                    selection,
                    valid_private,
                    "redacted output",
                ),
            )
            for public_path, private_path, private_root, message in cases:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(RuntimeError, message):
                        validate_private_output_paths(
                            public_path.resolve(),
                            private_path.resolve(),
                            private_root.resolve(),
                        )

    def test_probe_writes_private_proxy_selection_separately_from_redacted_fragment(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            shard_dir = root / "shards"
            shard_dir.mkdir()
            shard_path = shard_dir / "shard-0.yaml"
            proxy = {
                "name": "private-node",
                "type": "ss",
                "server": "secret.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "private-password",
                "uuid": "private-uuid",
            }
            shard_path.write_text(
                yaml.safe_dump({"proxies": [proxy]}, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            manifest = formal_manifest(
                [
                    {
                        "shard_index": 0,
                        "proxy_count": 1,
                        "preferred_asia_count": 0,
                        "profile_file": "shards/shard-0.yaml",
                        "profile_sha256": file_sha256(shard_path),
                    }
                ]
            )
            manifest["round_gap_seconds"] = 0
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            mihomo = root / "mihomo"
            mihomo.write_text("", encoding="utf-8")
            public_path = root / "redacted-fragment.json"
            private_root = root / ".cnb-runtime" / "gmgn-shadow" / "selection"
            private_path = private_root / "selection-fragment.json"

            class Process:
                returncode = None

                def poll(self):
                    return self.returncode

                def terminate(self):
                    self.returncode = 0

                def wait(self, timeout=None):
                    return self.returncode

                def kill(self):
                    self.returncode = -9

            def fake_rounds(_controller, _proxies, records, **_kwargs):
                record = records["private-node"]
                record["samples_ms"] = [80, *([None] * 19)]
                record["error_counts"] = {"timeout": 19}
                return one_success_round_trends(success_round=1)

            args = argparse.Namespace(
                manifest=str(manifest_path),
                shard_index=0,
                mihomo=str(mihomo),
                work_dir=str(root / "work"),
                output=str(public_path),
                selection_output=str(private_path),
                private_output_root=str(private_root),
                controller_port=19090,
                mixed_port=17890,
            )
            missing_private_root = copy.copy(args)
            missing_private_root.private_output_root = ""
            with self.assertRaisesRegex(RuntimeError, "requires --private-output-root"):
                probe_shadow_shard(missing_private_root)
            with (
                patch("scripts.cnb_gmgn_shadow.subprocess.Popen", return_value=Process()),
                patch("scripts.cnb_gmgn_shadow.wait_for_shadow_mihomo"),
                patch("scripts.cnb_gmgn_shadow.run_shadow_rounds", side_effect=fake_rounds),
                patch("scripts.cnb_gmgn_shadow.verify_mihomo_health"),
            ):
                self.assertEqual(probe_shadow_shard(args), 0)

            public_text = public_path.read_text(encoding="utf-8")
            public_payload = json.loads(public_text)
            self.assertNotIn("secret.example", public_text)
            self.assertNotIn("private-password", public_text)
            self.assertNotIn("private-uuid", public_text)
            self.assertNotIn("proxy", public_payload["results"][0])
            for sensitive_field in ("name", "server", "port", "uuid", "password"):
                self.assertNotIn(sensitive_field, public_payload["results"][0])
            self.assertEqual(
                public_payload["results"][0]["first_half_within_limit_count"], 1
            )
            self.assertEqual(
                public_payload["results"][0]["second_half_within_limit_count"], 0
            )
            self.assertEqual(
                public_payload["results"][0]["within_limit_count_rounds_1_5"], 1
            )

            private_payload = json.loads(private_path.read_text(encoding="utf-8"))
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)
            self.assertEqual(
                set(private_payload),
                {
                    "kind",
                    "schema_version",
                    "run_id",
                    "main_sha",
                    "source_sha256",
                    "target_url",
                    "expected_status",
                    "request_timeout_ms",
                    "qualified_delay_ms",
                    "total_rounds",
                    "shard_count",
                    "shard_index",
                    "shard_profile_sha256",
                    "proxy_count",
                    "preferred_asia_count",
                    "results",
                },
            )
            self.assertEqual(private_payload["kind"], "cnb-gmgn-selection-fragment")
            self.assertEqual(
                private_payload["schema_version"], SELECTION_FRAGMENT_SCHEMA_VERSION
            )
            self.assertEqual(private_payload["run_id"], TEST_RUN_ID)
            self.assertEqual(private_payload["main_sha"], TEST_MAIN_SHA)
            self.assertEqual(private_payload["source_sha256"], TEST_SOURCE_SHA)
            self.assertEqual(private_payload["target_url"], "https://gmgn.ai/")
            self.assertEqual(private_payload["expected_status"], 200)
            self.assertEqual(private_payload["request_timeout_ms"], 3000)
            self.assertEqual(private_payload["qualified_delay_ms"], 1000)
            self.assertEqual(private_payload["total_rounds"], 20)
            self.assertEqual(private_payload["shard_count"], 1)
            self.assertEqual(private_payload["shard_index"], 0)
            self.assertEqual(
                private_payload["shard_profile_sha256"], file_sha256(shard_path)
            )
            self.assertEqual(private_payload["proxy_count"], 1)
            self.assertEqual(private_payload["preferred_asia_count"], 0)
            selection = private_payload["results"][0]
            self.assertEqual(selection["proxy"]["server"], "secret.example")
            self.assertEqual(selection["proxy"]["port"], 443)
            self.assertEqual(selection["proxy"]["password"], "private-password")
            self.assertEqual(selection["proxy"]["uuid"], "private-uuid")
            self.assertEqual(selection["summary"], public_payload["results"][0])
            self.assertEqual(set(selection), SELECTION_RESULT_FIELDS)
            self.assertRegex(selection["summary"]["node_id"], r"^n1_[0-9a-f]{24}$")

            mutations = []
            extra_identity = copy.deepcopy(private_payload)
            extra_identity["results"][0]["source_name"] = "must-not-change-schema"
            mutations.append((extra_identity, "result fields"))
            missing_name = copy.deepcopy(private_payload)
            missing_name["results"][0]["proxy"]["name"] = ""
            mutations.append((missing_name, "proxy names"))
            malformed_node_id = copy.deepcopy(private_payload)
            malformed_node_id["results"][0]["summary"]["node_id"] = "private-node"
            mutations.append((malformed_node_id, "malformed node ID"))
            for mutated, message in mutations:
                with self.subTest(message=message):
                    with self.assertRaisesRegex(RuntimeError, message):
                        validate_selection_fragment(
                            manifest,
                            mutated,
                            manifest["shards"][0],
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
        self.assertEqual(
            shadow["env"]["GMGN_OUTPUT_BRANCH"], "clash-cn-gmgn-output"
        )
        self.assertEqual(shadow["env"]["SOURCE_MAX_AGE_SECONDS"], "36000")
        self.assertEqual(shadow["env"]["SHADOW_WORKERS_PER_SHARD"], "16")
        self.assertNotIn("SHADOW_SHARDS", shadow["env"])
        self.assertEqual(shadow["stages"][0]["timeout"], "30m")
        prepare_script = str(shadow["stages"][0]["script"])
        self.assertEqual(prepare_script.count("umask 077"), 1)
        self.assertIn("--shard-count 4", prepare_script)
        self.assertIn("--source-freshness-wait-seconds", prepare_script)
        self.assertIn("--max-estimated-probe-seconds", prepare_script)
        jobs = shadow["stages"][1]["jobs"]
        self.assertEqual(set(jobs), {"shard-0", "shard-1", "shard-2", "shard-3"})
        self.assertTrue(all(job["timeout"] == "120m" for job in jobs.values()))
        self.assertTrue(
            all(str(job["script"]).count("umask 077") == 1 for job in jobs.values())
        )
        scripts = "\n".join(str(job["script"]) for job in jobs.values())
        for port in (19090, 19091, 19092, 19093, 17890, 17891, 17892, 17893):
            self.assertEqual(scripts.count(str(port)), 1)
        for index in range(4):
            self.assertEqual(
                scripts.count(
                    f"--selection-output .cnb-runtime/gmgn-shadow/selection/shard-{index}.json"
                ),
                1,
            )
        self.assertEqual(
            scripts.count(
                "--private-output-root .cnb-runtime/gmgn-shadow/selection"
            ),
            4,
        )

        stages = {stage["name"]: stage for stage in shadow["stages"]}
        build = str(stages["Build the independent GMGN priority profile"]["script"])
        publish = str(stages["Publish the independent GMGN priority profile"]["script"])
        shadow_publish = str(stages["Publish the isolated GMGN shadow report"]["script"])
        self.assertIn("python3 -m scripts.cnb_gmgn_publish", build)
        self.assertIn("--previous-profile", build)
        self.assertIn('previous_cache_key="$(date +%s)"', build)
        self.assertIn(
            'previous_profile_url="${profile_url}?cnb_previous=${previous_cache_key}"',
            build,
        )
        self.assertIn("--previous-status", build)
        self.assertIn("git ls-remote --exit-code", build)
        self.assertIn('"refs/heads/${GMGN_OUTPUT_BRANCH}"', build)
        self.assertIn("branch_check_status", build)
        self.assertIn("--previous-publication-exists", build)
        self.assertIn("clash/clash-linux-amd -t", build)
        self.assertIn("-f public-cn-gmgn/clash.yaml", build)
        for index in range(4):
            self.assertIn(
                f".cnb-runtime/gmgn-shadow/selection/shard-{index}.json", build
            )
        self.assertIn("clash.yaml", publish)
        self.assertIn("${GMGN_OUTPUT_BRANCH}", publish)
        self.assertNotIn("gmgn-shadow-results.json", publish)
        self.assertNotIn(".cnb-runtime/gmgn-shadow/selection", shadow_publish)
        self.assertNotIn("clash.yaml", shadow_publish)

    def test_generated_cnb_workspaces_are_ignored_from_main_repository(self):
        repository_root = Path(__file__).resolve().parents[1]
        ignore_rules = {
            line.strip()
            for line in (repository_root / ".gitignore").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        self.assertTrue(
            {
                "/.cnb-runtime/",
                "/public-cn/",
                "/public-cn-shadow/",
                "/public-cn-gmgn/",
            }.issubset(ignore_rules)
        )

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
        return formal_manifest(
            [
                {
                    "shard_index": 0,
                    "proxy_count": 1,
                    "preferred_asia_count": 1,
                    "profile_file": "shards/shard-0.yaml",
                    "profile_sha256": TEST_SHARD_SHA,
                }
            ]
        )

    @staticmethod
    def fragment() -> dict:
        return {
            "kind": "cnb-gmgn-shadow-fragment",
            "schema_version": SHADOW_SCHEMA_VERSION,
            "run_id": TEST_RUN_ID,
            "main_sha": TEST_MAIN_SHA,
            "source_sha256": TEST_SOURCE_SHA,
            "target_url": "https://gmgn.ai/",
            "expected_status": 200,
            "request_timeout_ms": 3000,
            "qualified_delay_ms": 1000,
            "total_rounds": 20,
            "shard_count": 1,
            "shard_index": 0,
            "shard_profile_sha256": TEST_SHARD_SHA,
            "proxy_count": 1,
            "preferred_asia_count": 1,
            "duration_seconds": 1.0,
            "round_trends": one_success_round_trends(),
            "error_counts": {"timeout": 19},
            "results": [
                {
                    "node_id": "n1_000000000000000000000003",
                    "preferred_asia": True,
                    "attempts": 20,
                    "response_count": 1,
                    "within_limit_count": 1,
                    "first_half_within_limit_count": 0,
                    "second_half_within_limit_count": 1,
                    "within_limit_count_rounds_1_5": 0,
                    "within_limit_count_rounds_6_10": 0,
                    "within_limit_count_rounds_11_15": 0,
                    "within_limit_count_rounds_16_20": 1,
                    "slow_response_count": 0,
                    "no_result_count": 19,
                    "response_rate": 0.05,
                    "within_limit_rate": 0.05,
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

    def test_merge_rejects_non_twenty_round_manifest_before_fragments(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            for total_rounds in (19, 21):
                with self.subTest(total_rounds=total_rounds):
                    manifest = self.manifest()
                    manifest["total_rounds"] = total_rounds
                    manifest_path = root / f"manifest-{total_rounds}.json"
                    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
                    args = argparse.Namespace(
                        manifest=str(manifest_path),
                        fragments=[],
                        output_dir=str(root / "output"),
                        results_url="",
                    )

                    with self.assertRaisesRegex(RuntimeError, "exactly 20 rounds"):
                        merge_shadow(args)

    def test_merge_rejects_fragment_schema_before_result_processing(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            fragment = self.fragment()
            fragment["schema_version"] = SHADOW_SCHEMA_VERSION - 1
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

            with self.assertRaisesRegex(RuntimeError, "fragment schema"):
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
            self.assertNotIn("port", payload["results"][0])
            self.assertNotIn("uuid", payload["results"][0])
            self.assertNotIn("password", payload["results"][0])
            self.assertNotIn("runner_public_ip", serialized)
            self.assertIn("egress region not verified", payload["region_classification"])
            self.assertEqual(payload["results"][0]["within_limit_count"], 1)
            self.assertEqual(
                payload["results"][0]["first_half_within_limit_count"], 0
            )
            self.assertEqual(
                payload["results"][0]["second_half_within_limit_count"], 1
            )
            self.assertEqual(payload["round_trends"][19]["within_limit_count"], 1)

    def test_merge_rejects_incomplete_or_unredacted_node_result(self):
        for mutation in ("incomplete", "secret-field", "inconsistent-window"):
            with self.subTest(mutation=mutation), self.temporary_directory() as directory:
                root = Path(directory)
                fragment = self.fragment()
                if mutation == "incomplete":
                    fragment["results"][0]["attempts"] = 0
                elif mutation == "secret-field":
                    fragment["results"][0]["server"] = "secret.example"
                else:
                    fragment["results"][0]["first_half_within_limit_count"] = 1
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

    def test_merge_rejects_half_windows_that_disagree_with_round_trends(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            fragment = self.fragment()
            fragment["round_trends"] = one_success_round_trends(success_round=1)
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

            with self.assertRaisesRegex(RuntimeError, "half-window totals"):
                merge_shadow(args)

    def test_merge_rejects_block_windows_that_disagree_with_round_trends(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            fragment = self.fragment()
            fragment["round_trends"] = one_success_round_trends(success_round=11)
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

            with self.assertRaisesRegex(RuntimeError, "five-round block totals"):
                merge_shadow(args)

    def test_round_trends_merge_by_round_number(self):
        fragments = [self.fragment(), self.fragment()]
        merged = merge_round_trends(fragments, 20)

        self.assertEqual(merged[0]["no_result_count"], 2)
        self.assertEqual(merged[19]["within_limit_count"], 2)


if __name__ == "__main__":
    unittest.main()
