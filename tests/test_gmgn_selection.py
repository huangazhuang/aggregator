from __future__ import annotations

import copy
import hashlib
import json
import unittest

from scripts.gmgn_history import empty_history, reduce_history
from scripts.gmgn_measurement import ERROR_CATEGORIES
from scripts.gmgn_region import (
    REGION_DECISION_KIND,
    REGION_DECISION_SCHEMA_VERSION,
    REGION_POLICY_VERSION,
)
from scripts.gmgn_selection import (
    GROUP_ALL,
    GROUP_ASIA_BACKUP,
    GROUP_AUTO,
    GROUP_HK,
    GROUP_JP,
    GROUP_KR,
    GROUP_MANUAL_PRIORITY,
    GROUP_NON_ASIA,
    GROUP_SG,
    GROUP_TW,
    SELECTION_INPUT_KIND,
    SELECTION_INPUT_SCHEMA_VERSION,
    SELECTION_POLICY_VERSION,
    SelectionError,
    V2_GROUP_NAMES,
    select_candidates_v2,
)
from tests.test_gmgn_region import protected_history


def cid(index: int) -> str:
    return f"c1_{index:024x}"


def server_id(index: int) -> str:
    return f"srv1_{index:024x}"


def exit_id(index: int) -> str:
    return f"exit1_{index:024x}"


def endpoint_id(index: int) -> str:
    return f"ep1_{index:024x}"


def asn_id(index: int) -> str:
    return f"asn1_{index:024x}"


def measurement(
    index: int,
    *,
    within: int,
    response: int | None = None,
    first: int | None = None,
    second: int | None = None,
    p90: int = 800,
) -> dict:
    response = within if response is None else response
    first = min(within, 10) if first is None else first
    second = within - first if second is None else second
    blocks = [min(first, 5), max(first - 5, 0), min(second, 5), max(second - 5, 0)]
    return {
        "candidate_id": cid(index),
        "attempt_count": 20,
        "response_count": response,
        "within_1000_count": within,
        "slow_response_count": response - within,
        "no_result_count": 20 - response,
        "min_delay_ms": 100 if response else None,
        "median_delay_ms": 400.0 if response else None,
        "p90_delay_ms": float(p90) if response else None,
        "max_delay_ms": 1200 if response > within else (900 if response else None),
        "jitter_ms": 20.0 if response else None,
        "first_half_within_1000_count": first,
        "second_half_within_1000_count": second,
        "five_round_within_1000_counts": blocks,
        "observation_span_seconds": 900.0,
        "error_counts": {
            category: (20 - response if category == "client_timeout" else 0)
            for category in ERROR_CATEGORIES
        },
    }


def region(
    index: int,
    *,
    country: str = "US",
    confidence: str = "verified",
    shared_exit: int | None = None,
) -> dict:
    verified = confidence in {"verified", "conflict"} and country in {"HK", "JP", "KR", "SG", "TW"}
    source_region = country if confidence == "source-specific" else None
    cache = None
    exit_value = None
    asn_value = None
    if confidence in {"verified", "conflict"}:
        exit_value = exit_id(index if shared_exit is None else shared_exit)
        asn_value = asn_id(index)
        cache = {
            "country_code": country,
            "region_code": country,
            "exit_id": exit_value,
            "asn_id": asn_value,
            "queried_at": "2026-08-11T00:00:00Z",
            "expires_at": "2026-08-18T00:00:00Z",
            "stale": False,
            "policy_version": REGION_POLICY_VERSION,
        }
    return {
        "kind": REGION_DECISION_KIND,
        "schema_version": REGION_DECISION_SCHEMA_VERSION,
        "candidate_id": cid(index),
        "identity_key_version": "test-k1",
        "identity_epoch": "identity-v1",
        "country_code": country if confidence in {"verified", "conflict"} else "",
        "region_code": country if confidence in {"verified", "conflict"} else "",
        "exit_id": exit_value,
        "asn_id": asn_value,
        "confidence": confidence,
        "verified_target_asia": verified,
        "temporary_target_asia": confidence == "source-specific",
        "stale": False,
        "reason": "live_verified" if confidence == "verified" else "source_specific_fallback",
        "source_region": source_region,
        "cache": cache,
    }


def candidate_record(
    index: int,
    *,
    source: str | None = None,
    shared_server: int | None = None,
    alias: str | None = None,
) -> dict:
    server_index = index if shared_server is None else shared_server
    return {
        "candidate_id": cid(index),
        "proxy": {
            "name": alias or f"Node {index}",
            "type": "ss",
            "server": f"node-{server_index}.example",
            "port": 10000 + index,
            "cipher": "aes-128-gcm",
            "password": f"secret-{index}",
        },
        "metadata": {
            "aliases": [alias or f"Node {index}"],
            "source_ids": [source or f"public_{index:024x}"],
            "first_seen_at": "2026-08-11T00:00:00Z",
            "last_seen_at": "2026-08-11T00:00:00Z",
            "source_last_success_at": "2026-08-11T00:00:00Z",
            "region_hints": [],
            "region_evidence": [],
            "protected_asia": False,
            "github_check_state": "passed",
            "protocol": "ss",
            "server_id": server_id(server_index),
            "endpoint_id": endpoint_id(index),
            "endpoint_safety_policy_version": "endpoint-safety-v1",
            "endpoint_checked_at": "2026-08-11T00:00:00Z",
        },
    }


def selection_input(records: list[dict], measurements: list[dict], regions: list[dict]) -> dict:
    return {
        "kind": SELECTION_INPUT_KIND,
        "schema_version": SELECTION_INPUT_SCHEMA_VERSION,
        "snapshot": {
            "snapshot_id": "candidate_" + "1" * 24,
            "main_sha": "a" * 40,
            "profile_sha256": "b" * 64,
            "candidate_metadata_sha256": "c" * 64,
            "candidate_metadata_schema_version": 1,
            "identity_key_version": "test-k1",
            "identity_epoch": "identity-v1",
            "candidates": records,
        },
        "accepted_measurement": {
            "kind": "cnb-gmgn-accepted-measurement",
            "schema_version": 1,
            "run_id": "selection-run-1",
            "source_sha256": "d" * 64,
            "main_sha": "a" * 40,
            "profile_sha256": "b" * 64,
            "candidate_metadata_sha256": "c" * 64,
            "candidate_metadata_schema_version": 1,
            "candidate_metadata_count": len(records),
            "identity_key_version": "test-k1",
            "identity_epoch": "identity-v1",
            "validity_policy_version": "gmgn-validity-v1",
            "manifest_sha256": "e" * 64,
            "fragment_sha256": [f"{index:x}" * 64 for index in range(1, 5)],
            "results": measurements,
        },
        "history": empty_history(
            identity_key_version="test-k1",
            identity_epoch="identity-v1",
            selection_policy_version=SELECTION_POLICY_VERSION,
        ),
        "region_decisions": {item["candidate_id"]: item for item in regions},
    }


class SelectionBoundaryTests(unittest.TestCase):
    def test_rejects_unknown_validity_policy_and_error_accounting(self):
        payload = selection_input(
            [candidate_record(6)],
            [measurement(6, within=0, response=0, first=0, second=0)],
            [region(6, country="JP")],
        )
        payload["accepted_measurement"]["validity_policy_version"] = "future-policy"
        with self.assertRaisesRegex(SelectionError, "validity policy"):
            select_candidates_v2(payload)

        payload = selection_input(
            [candidate_record(7)],
            [measurement(7, within=0, response=0, first=0, second=0)],
            [region(7, country="JP")],
        )
        payload["accepted_measurement"]["results"][0]["error_counts"]["client_timeout"] = 19
        with self.assertRaisesRegex(SelectionError, "error counts"):
            select_candidates_v2(payload)

    def test_asia_core_flexible_manual_and_zero_response_boundaries(self):
        records = [candidate_record(index) for index in range(1, 6)]
        measurements = [
            measurement(1, within=14, response=14, first=5, second=9),
            measurement(2, within=14, response=14, first=4, second=10),
            measurement(3, within=13, response=13, first=6, second=7),
            measurement(4, within=0, response=1, first=0, second=0),
            measurement(5, within=0, response=0, first=0, second=0),
        ]
        regions = [region(index, country=("HK", "JP", "KR", "SG", "TW")[index - 1]) for index in range(1, 6)]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        self.assertEqual(result["tier_ids"]["asia_core"], [cid(1)])
        self.assertEqual(result["tier_ids"]["asia_flexible"], [cid(3)])
        self.assertEqual(
            result["tier_ids"]["asia_manual_candidate"], [cid(2), cid(4)]
        )
        self.assertNotIn(cid(5), {item["candidate_id"] for item in result["selected"]})
        self.assertIn(cid(4), result["tier_ids"]["asia_manual_candidate"])
        self.assertNotIn(cid(4), result["priority_ids"])
        self.assertNotIn(cid(4), result["auto_ids"])

    def test_unknown_region_never_gets_asia_threshold_but_can_pass_non_asia_strict(self):
        records = [candidate_record(10), candidate_record(11)]
        measurements = [
            measurement(10, within=14, response=14, first=7, second=7),
            measurement(11, within=16, response=16, first=8, second=8),
        ]
        unknown = [region(10, country="US", confidence="source-specific"), region(11, country="US", confidence="verified")]
        unknown[0]["source_region"] = "JP"

        result = select_candidates_v2(selection_input(records, measurements, unknown))

        self.assertIn(cid(10), result["tier_ids"]["asia_manual_candidate"])
        self.assertIn(cid(11), result["tier_ids"]["non_asia_stable"])
        self.assertNotIn(cid(10), result["priority_ids"])

    def test_history_bad_one_is_retained_but_confirmed_missing_is_not_reintroduced(self):
        record = candidate_record(4)
        zero_payload = selection_input(
            [record],
            [measurement(4, within=0, response=0, first=0, second=0)],
            [region(4, country="KR")],
        )
        zero_payload["history"] = protected_history(4)

        retained = select_candidates_v2(zero_payload)

        self.assertEqual(retained["tier_ids"]["history_protected"], [cid(4)])
        removed_history = reduce_history(
            protected_history(4),
            run_context={
                "run_id": "region-run-3",
                "source_sha256": hashlib.sha256(b"region-3").hexdigest(),
                "accepted_at": "2026-08-03T00:00:00Z",
                "valid_run": True,
                "accepted": True,
                "identity_key_version": "test-k1",
                "identity_epoch": "identity-v1",
                "selection_policy_version": SELECTION_POLICY_VERSION,
            },
            source_events={cid(4): "confirmed_missing"},
            measurements={},
            decisions={},
        )
        responsive_payload = selection_input(
            [record],
            [measurement(4, within=14, response=14, first=7, second=7)],
            [region(4, country="KR")],
        )
        responsive_payload["history"] = removed_history

        removed = select_candidates_v2(responsive_payload)

        self.assertEqual(removed["summary"]["published_count"], 0)
        status = removed["node_status"]["nodes"][0]
        self.assertEqual(status["reason"], "source_confirmed_missing")

    def test_non_asia_first_ten_use_sixteen_and_extra_slots_need_eighteen(self):
        records = [candidate_record(index) for index in range(20, 32)]
        measurements = [
            measurement(index, within=18 if index < 30 or index == 31 else 17, response=18 if index < 30 or index == 31 else 17, first=9 if index < 30 or index == 31 else 8, second=9)
            for index in range(20, 32)
        ]
        regions = [region(index, country="US") for index in range(20, 32)]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        selected = set(result["tier_ids"]["non_asia_stable"])
        self.assertEqual(len(selected), 11)
        self.assertIn(cid(31), selected)
        self.assertNotIn(cid(30), selected)
        self.assertLessEqual(len(selected), 20)


class DiversityAndCapacityTests(unittest.TestCase):
    def test_capacity_trim_preserves_missing_region_before_duplicate_backup(self):
        records = [
            candidate_record(index, shared_server=1, source="public_" + "f" * 24)
            for index in range(1000, 1150)
        ] + [candidate_record(2000)]
        measurements = [
            measurement(index, within=0, response=1, first=0, second=0)
            for index in [*range(1000, 1150), 2000]
        ]
        regions = [
            region(index, country="HK", shared_exit=1) for index in range(1000, 1150)
        ] + [region(2000, country="JP")]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        self.assertEqual(result["summary"]["published_count"], 150)
        self.assertIn(cid(2000), result["tier_ids"]["asia_manual_candidate"])

    def test_strict_priority_caps_same_exit_and_server_at_three(self):
        records = [candidate_record(index, shared_server=1, source=f"public_{index:024x}") for index in range(40, 45)]
        measurements = [measurement(index, within=14, response=14, first=7, second=7) for index in range(40, 45)]
        regions = [region(index, country="JP", shared_exit=1) for index in range(40, 45)]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        self.assertEqual(len(result["tier_ids"]["asia_core"]), 3)
        self.assertEqual(result["summary"]["diversity_trimmed_count"], 2)

    def test_asia_manual_backups_are_not_diversity_trimmed_below_150(self):
        records = [candidate_record(index, shared_server=2, source="public_" + "f" * 24) for index in range(50, 60)]
        measurements = [measurement(index, within=0, response=1, first=0, second=0) for index in range(50, 60)]
        regions = [region(index, country="KR", shared_exit=2) for index in range(50, 60)]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        self.assertEqual(len(result["tier_ids"]["asia_manual_candidate"]), 10)
        self.assertEqual(result["summary"]["diversity_trimmed_count"], 0)
        statuses = {item["candidate_id"]: item for item in result["node_status"]["nodes"]}
        self.assertIn("exit_concentrated", statuses[cid(50)]["concentration_flags"])

    def test_total_is_capped_at_150_without_lowering_quality_thresholds(self):
        records = [candidate_record(index) for index in range(100, 255)]
        measurements = [measurement(index, within=0, response=1, first=0, second=0) for index in range(100, 255)]
        regions = [region(index, country="TW") for index in range(100, 255)]

        result = select_candidates_v2(selection_input(records, measurements, regions))

        self.assertEqual(result["summary"]["published_count"], 150)
        self.assertEqual(result["summary"]["capacity_trimmed_count"], 5)
        self.assertEqual(result["summary"]["stable_capacity_count"], 0)
        self.assertFalse(result["summary"]["desired_capacity_reached"])


class GroupAndPrivacyTests(unittest.TestCase):
    def test_exact_ten_groups_and_manual_backup_membership(self):
        records = [candidate_record(index) for index in range(300, 304)]
        measurements = [
            measurement(300, within=14, response=14, first=7, second=7),
            measurement(301, within=10, response=10, first=5, second=5),
            measurement(302, within=0, response=1, first=0, second=0),
            measurement(303, within=18, response=18, first=9, second=9),
        ]
        regions = [
            region(300, country="HK"),
            region(301, country="JP"),
            region(302, country="KR"),
            region(303, country="US"),
        ]

        result = select_candidates_v2(selection_input(records, measurements, regions))
        groups = {group["name"]: group for group in result["profile"]["proxy-groups"]}

        self.assertEqual(tuple(groups), V2_GROUP_NAMES)
        self.assertIn("Node 302", groups[GROUP_ASIA_BACKUP]["proxies"])
        self.assertIn("Node 302", groups[GROUP_KR]["proxies"])
        self.assertIn("Node 302", groups[GROUP_ALL]["proxies"])
        self.assertNotIn("Node 302", groups[GROUP_MANUAL_PRIORITY]["proxies"])
        self.assertNotIn("Node 302", groups[GROUP_AUTO]["proxies"])
        self.assertNotIn("DIRECT", groups[GROUP_MANUAL_PRIORITY]["proxies"])
        self.assertIn("Node 301", groups[GROUP_MANUAL_PRIORITY]["proxies"])
        self.assertNotIn("Node 301", groups[GROUP_AUTO]["proxies"])
        self.assertIn("Node 303", groups[GROUP_NON_ASIA]["proxies"])
        self.assertEqual(set(groups), set(V2_GROUP_NAMES))

    def test_node_status_is_redacted_and_order_is_input_independent(self):
        records = [candidate_record(index) for index in range(400, 404)]
        measurements = [measurement(index, within=14, response=14, first=7, second=7) for index in range(400, 404)]
        regions = [region(index, country=("HK", "JP", "KR", "SG")[index - 400]) for index in range(400, 404)]
        original = selection_input(records, measurements, regions)
        reversed_input = copy.deepcopy(original)
        reversed_input["snapshot"]["candidates"].reverse()
        reversed_input["accepted_measurement"]["results"].reverse()
        reversed_input["region_decisions"] = dict(reversed(list(reversed_input["region_decisions"].items())))

        first = select_candidates_v2(original)
        second = select_candidates_v2(reversed_input)

        self.assertEqual(first["priority_ids"], second["priority_ids"])
        self.assertEqual(first["tier_ids"], second["tier_ids"])
        public = json.dumps(first["node_status"], ensure_ascii=False)
        for secret in ("secret-", "node-400.example", "public_", '"server"', '"port"'):
            self.assertNotIn(secret, public)
        self.assertEqual(
            set(first["node_status"]["nodes"][0]),
            {
                "candidate_id",
                "output_name",
                "tier",
                "eligible_tier",
                "reason",
                "selected",
                "priority_selected",
                "auto_selected",
                "country_code",
                "region_confidence",
                "region_stale",
                "within_1000_count",
                "under_1000_count",
                "response_count",
                "slow_response_count",
                "over_1000_count",
                "no_result_count",
                "timeout_count",
                "first_half_within_1000_count",
                "second_half_within_1000_count",
                "median_delay_ms",
                "p90_delay_ms",
                "jitter_ms",
                "history_transition",
                "concentration_flags",
            },
        )

    def test_node_status_keeps_timeout_separate_from_slow_and_other_failures(self):
        measured = measurement(450, within=14, response=17, first=7, second=7)
        measured["error_counts"]["client_timeout"] = 1
        measured["error_counts"]["connect"] = 2
        result = select_candidates_v2(
            selection_input(
                [candidate_record(450)],
                [measured],
                [region(450, country="HK")],
            )
        )

        status = result["node_status"]["nodes"][0]
        self.assertEqual(status["under_1000_count"], 14)
        self.assertEqual(status["over_1000_count"], 3)
        self.assertEqual(status["timeout_count"], 1)
        self.assertEqual(status["no_result_count"], 3)


if __name__ == "__main__":
    unittest.main()
