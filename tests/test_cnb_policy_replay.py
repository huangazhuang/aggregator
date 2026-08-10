from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

from scripts.cnb_diagnostics import (
    POLICY_NODE_ID_KEY,
    build_failure_diagnostic,
    build_redacted_probe_results,
    redacted_result,
    write_failure_diagnostic,
    write_redacted_probe_results,
)
from scripts.cnb_mihomo_filter import _write_failure_diagnostic, select_stable_results
from scripts.cnb_policy_replay import load_replay_input, main, replay_policy


def probe_summary(
    name: str,
    *,
    asia: bool,
    successes: int,
    p90: float = 300.0,
) -> dict:
    return {
        "name": name,
        "type": "vless",
        "server": f"{name}.secret.example",
        "port": 443,
        "uuid": f"uuid-secret-{name}",
        "password": f"password-secret-{name}",
        "preferred_asia": asia,
        "attempts": 5,
        "success_count": successes,
        "success_rate": successes / 5,
        "min_delay_ms": 100,
        "median_delay_ms": 180,
        "p90_delay_ms": p90,
        "jitter_ms": 25,
        "samples_ms": [100, 180, p90, None, None],
        "last_error": "credential-like raw error must stay private",
    }


THRESHOLDS = (
    ("strict", 4, 500.0),
    ("fallback", 3, 500.0),
    ("emergency", 2, 700.0),
    ("elite", 5, 400.0),
)


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    root = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
    return tempfile.TemporaryDirectory(dir=root)


class RedactedProbeResultsTests(unittest.TestCase):
    def test_redacted_result_has_only_opaque_id_and_aggregate_metrics(self) -> None:
        summary = probe_summary("private-node-name", asia=True, successes=3)

        first = redacted_result(summary)
        second = redacted_result(dict(summary))

        self.assertNotEqual(first["node_id"], second["node_id"])
        self.assertRegex(first["node_id"], r"^n1_[0-9a-f]{24}$")
        self.assertEqual(
            {key: value for key, value in first.items() if key != "node_id"},
            {key: value for key, value in second.items() if key != "node_id"},
        )
        self.assertEqual(first["success_rate"], 0.6)
        self.assertEqual(first["min_delay_ms"], 100)
        self.assertEqual(
            set(first),
            {
                "node_id",
                "preferred_asia",
                "attempts",
                "success_count",
                "success_rate",
                "min_delay_ms",
                "median_delay_ms",
                "p90_delay_ms",
                "jitter_ms",
            },
        )

    def test_standalone_bundle_omits_connection_credentials_and_adds_tiers(self) -> None:
        summaries = [
            probe_summary("asia-fallback", asia=True, successes=3),
            probe_summary("global-strict", asia=False, successes=4),
        ]

        payload = build_redacted_probe_results(
            summaries=summaries,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=1,
            non_asia_max=2,
            base_target=2,
            max_nodes=3,
            required_count=2,
        )
        serialized = json.dumps(payload, ensure_ascii=False)

        for secret in (
            "asia-fallback.secret.example",
            "global-strict.secret.example",
            "uuid-secret-asia-fallback",
            "password-secret-global-strict",
            "credential-like raw error",
            "private-node-name",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(payload["result_count"], 2)
        self.assertEqual(
            {item["policy_tier"] for item in payload["results"]},
            {"asia-fallback", "non-asia-strict"},
        )
        self.assertTrue(all(item["complete"] for item in payload["results"]))

    def test_failure_stays_small_and_references_independent_results_file(self) -> None:
        summaries = [probe_summary(f"asia-{index}", asia=True, successes=3) for index in range(25)]
        failure = build_failure_diagnostic(
            failure_kind="publish_floor_not_reached",
            message="not enough nodes",
            summaries=summaries,
            required_count=4,
            selected_count=3,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            base_target=4,
            max_nodes=6,
            replay_results_file="redacted-probe-results.json",
            replay_run_id="r1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )

        self.assertNotIn("results", failure)
        self.assertEqual(failure["replay"]["results_file"], "redacted-probe-results.json")
        self.assertEqual(failure["replay"]["result_count"], 25)
        self.assertLess(len(json.dumps(failure)), 10000)

    def test_filter_failure_writes_both_summary_and_standalone_replay_data(self) -> None:
        summaries = [
            probe_summary("asia-fallback", asia=True, successes=3),
            probe_summary("global-strict", asia=False, successes=4),
        ]
        args = Namespace(
            total_rounds=5,
            min_success_rate=0.8,
            max_qualified_p90_ms=500.0,
            asia_fallback_min_success=3,
            asia_emergency_min_success=2,
            asia_emergency_max_p90_ms=700.0,
            elite_min_success_rate=1.0,
            elite_max_p90_ms=400.0,
            non_asia_min=1,
            non_asia_max=2,
            base_target=2,
            max_nodes=3,
            asia_emergency_max_count=0,
            main_sha="main-safe-sha",
        )

        with temporary_directory() as directory, redirect_stdout(io.StringIO()):
            _write_failure_diagnostic(
                Path(directory),
                failure_kind="publish_floor_not_reached",
                message="not enough nodes",
                summaries=summaries,
                qualified_summaries=summaries,
                required_count=2,
                selected_count=1,
                previous_published_count=80,
                previous_publish_baseline=80,
                args=args,
                source_sha256="source-safe-sha",
            )
            failure = json.loads((Path(directory) / "failure.json").read_text(encoding="utf-8"))
            replay_text = (Path(directory) / "redacted-probe-results.json").read_text(
                encoding="utf-8"
            )

        self.assertEqual(failure["replay"]["results_file"], "redacted-probe-results.json")
        self.assertEqual(failure["replay"]["result_count"], 2)
        self.assertNotIn("asia-fallback.secret.example", replay_text)
        self.assertNotIn("password-secret-global-strict", replay_text)


class PolicyReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.summaries = [
            probe_summary("asia-strict", asia=True, successes=4),
            probe_summary("asia-fallback", asia=True, successes=3),
            probe_summary("asia-emergency", asia=True, successes=2, p90=600),
            probe_summary("asia-rejected", asia=True, successes=1),
            probe_summary("global-strict-a", asia=False, successes=4),
            probe_summary("global-strict-b", asia=False, successes=4),
        ]
        self.bundle = build_redacted_probe_results(
            summaries=self.summaries,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=1,
            non_asia_max=2,
            base_target=4,
            max_nodes=6,
            required_count=4,
        )

    def test_replay_calls_tiered_production_selector_and_reports_counts(self) -> None:
        report = replay_policy(self.bundle)

        self.assertTrue(report["passed"])
        self.assertEqual(report["qualified_count"], 5)
        self.assertEqual(report["selected_count"], 4)
        self.assertEqual(report["selected_asia_count"], 3)
        self.assertEqual(report["selected_non_asia_count"], 1)
        self.assertEqual(
            report["selected_tier_counts"],
            {
                "asia-strict": 1,
                "asia-fallback": 1,
                "asia-emergency": 1,
                "non-asia-strict": 1,
            },
        )

    def test_latest_failure_shape_replays_to_seven_asia_plus_twenty_non_asia(self) -> None:
        summaries = [
            probe_summary(f"asia-{index}", asia=True, successes=4)
            for index in range(7)
        ]
        summaries += [
            probe_summary(f"global-{index}", asia=False, successes=4)
            for index in range(250)
        ]
        bundle = build_redacted_probe_results(
            summaries=summaries,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=10,
            non_asia_max=20,
            base_target=80,
            max_nodes=150,
            required_count=80,
        )

        report = replay_policy(bundle)

        self.assertFalse(report["passed"])
        self.assertEqual(report["qualified_count"], 257)
        self.assertEqual(report["qualified_asia_count"], 7)
        self.assertEqual(report["qualified_non_asia_count"], 250)
        self.assertEqual(report["selected_count"], 27)
        self.assertEqual(report["selected_asia_count"], 7)
        self.assertEqual(report["selected_non_asia_count"], 20)

    def test_policy_override_explains_region_cap_shortfall(self) -> None:
        report = replay_policy(
            self.bundle,
            {
                "base_target": 5,
                "max_nodes": 5,
                "required_count": 5,
                "non_asia_max": 1,
            },
        )

        self.assertFalse(report["passed"])
        self.assertEqual(report["qualified_count"], 5)
        self.assertEqual(report["selected_count"], 4)
        self.assertEqual(
            report["failure_reason_code"],
            "selectable_count_below_publish_floor",
        )
        self.assertIn("non-Asia cap", report["failure_reason"])

    def test_strict_cli_override_keeps_the_shared_production_line_in_sync(self) -> None:
        report = replay_policy(
            self.bundle,
            {
                "strict_min_success": 5,
                "qualified_p90_ms": 600,
            },
        )

        self.assertEqual(report["policy"]["strict_min_success"], 5)
        self.assertEqual(report["policy"]["non_asia_min_success"], 5)
        self.assertEqual(report["policy"]["qualified_p90_ms"], 600)
        self.assertEqual(report["policy"]["non_asia_p90_ms"], 600)

    def test_failure_json_can_load_colocated_standalone_bundle(self) -> None:
        failure = build_failure_diagnostic(
            failure_kind="publish_floor_not_reached",
            message="not enough nodes",
            summaries=self.summaries,
            required_count=4,
            selected_count=4,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=1,
            non_asia_max=2,
            base_target=4,
            max_nodes=6,
            replay_results_file="redacted-probe-results.json",
            replay_run_id=self.bundle["run_id"],
        )
        with temporary_directory() as directory:
            write_redacted_probe_results(directory, self.bundle)
            failure_path = write_failure_diagnostic(directory, failure)

            loaded = load_replay_input(failure_path)
            report = replay_policy(loaded)

        self.assertTrue(report["passed"])
        self.assertEqual(report["selected_count"], 4)

    def test_failure_loader_rejects_a_bundle_from_another_run(self) -> None:
        failure = build_failure_diagnostic(
            failure_kind="publish_floor_not_reached",
            message="not enough nodes",
            summaries=self.summaries,
            required_count=4,
            selected_count=4,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=1,
            non_asia_max=2,
            base_target=4,
            max_nodes=6,
            replay_results_file="redacted-probe-results.json",
            replay_run_id="r1_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        with temporary_directory() as directory:
            write_redacted_probe_results(directory, self.bundle)
            failure_path = write_failure_diagnostic(directory, failure)

            with self.assertRaisesRegex(ValueError, "different run_id"):
                load_replay_input(failure_path)

    def test_replay_uses_the_same_opaque_tie_breaker_as_production(self) -> None:
        summaries = [
            probe_summary("name-sorts-first", asia=True, successes=4),
            probe_summary("name-sorts-last", asia=True, successes=4),
        ]
        summaries[0][POLICY_NODE_ID_KEY] = "n1_ffffffffffffffffffffffff"
        summaries[1][POLICY_NODE_ID_KEY] = "n1_000000000000000000000000"
        selected, _ = select_stable_results(
            summaries,
            0.8,
            0.8,
            500,
            1,
            1,
            0,
            0,
            1.0,
            400,
            asia_tiering=True,
            total_rounds=5,
            asia_fallback_min_success=3,
            asia_emergency_min_success=2,
            asia_emergency_max_p90_ms=700,
        )
        bundle = build_redacted_probe_results(
            summaries=summaries,
            total_rounds=5,
            asia_thresholds=THRESHOLDS,
            non_asia_minimum_success=4,
            non_asia_p90_limit_ms=500,
            non_asia_min=0,
            non_asia_max=0,
            base_target=1,
            max_nodes=1,
            required_count=1,
        )

        report = replay_policy(bundle)

        self.assertEqual(selected[0][POLICY_NODE_ID_KEY], "n1_000000000000000000000000")
        self.assertEqual(report["selected_node_ids"], ["n1_000000000000000000000000"])

    def test_cli_accepts_standalone_file_and_emits_json_report(self) -> None:
        with temporary_directory() as directory:
            path = write_redacted_probe_results(directory, self.bundle)
            output = io.StringIO()
            with redirect_stdout(output):
                return_code = main([str(path), "--json"])

        report = json.loads(output.getvalue())
        self.assertEqual(return_code, 0)
        self.assertTrue(report["passed"])
        self.assertEqual(report["selected_count"], 4)

    def test_incomplete_rounds_match_production_fail_closed_gate(self) -> None:
        bundle = json.loads(json.dumps(self.bundle))
        bundle["results"][0]["attempts"] = 4
        bundle["results"][0]["success_count"] = 3

        report = replay_policy(bundle)

        self.assertFalse(report["passed"])
        self.assertEqual(report["selected_count"], 0)
        self.assertEqual(report["failure_reason_code"], "incomplete_probe_rounds")

    def test_replay_rejects_an_unsupported_selection_schema(self) -> None:
        bundle = json.loads(json.dumps(self.bundle))
        bundle["policy"]["selection_schema_version"] = 999

        with self.assertRaisesRegex(ValueError, "selection_schema_version"):
            replay_policy(bundle)

    def test_replay_rejects_non_production_asia_tiering(self) -> None:
        bundle = json.loads(json.dumps(self.bundle))
        bundle["policy"]["asia_tiering"] = False

        with self.assertRaisesRegex(ValueError, "asia_tiering=true"):
            replay_policy(bundle)

    def test_replay_rejects_a_partial_policy_instead_of_using_defaults(self) -> None:
        bundle = json.loads(json.dumps(self.bundle))
        del bundle["policy"]["non_asia_max"]

        with self.assertRaisesRegex(ValueError, "missing required field.*non_asia_max"):
            replay_policy(bundle)


if __name__ == "__main__":
    unittest.main()
