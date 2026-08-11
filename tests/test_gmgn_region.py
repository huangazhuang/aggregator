from __future__ import annotations

import hashlib
import unittest

from scripts.gmgn_history import empty_history, reduce_history
from scripts.gmgn_region import (
    REGION_OBSERVATION_KIND,
    REGION_OBSERVATION_SCHEMA_VERSION,
    REGION_POLICY_VERSION,
    RegionError,
    build_region_query_plan,
    resolve_region_decisions,
)
from scripts.gmgn_selection import SELECTION_POLICY_VERSION


def cid(index: int) -> str:
    return f"c1_{index:024x}"


def exit_id(index: int) -> str:
    return f"exit1_{index:024x}"


def asn_id(index: int) -> str:
    return f"asn1_{index:024x}"


def measurement(response: int) -> dict:
    return {"response_count": response}


def metadata(*evidence: str) -> dict:
    return {"region_evidence": list(evidence)}


def observation(index: int, country: str, at: str) -> dict:
    return {
        "kind": REGION_OBSERVATION_KIND,
        "schema_version": REGION_OBSERVATION_SCHEMA_VERSION,
        "candidate_id": cid(index),
        "identity_key_version": "test-k1",
        "identity_epoch": "identity-v1",
        "country_code": country,
        "region_code": country,
        "exit_id": exit_id(index),
        "asn_id": asn_id(index),
        "observed_at": at,
        "provider_schema": "provider-v1",
    }


def protected_history(index: int) -> dict:
    history = empty_history(
        identity_key_version="test-k1",
        identity_epoch="identity-v1",
        selection_policy_version=SELECTION_POLICY_VERSION,
    )
    cache = {
        "country_code": "KR",
        "region_code": "KR",
        "exit_id": exit_id(index),
        "asn_id": asn_id(index),
        "queried_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-08-08T00:00:00Z",
        "stale": False,
        "policy_version": REGION_POLICY_VERSION,
    }
    responsive = {
        "total_rounds": 20,
        "response_count": 14,
        "within_limit_count": 14,
        "slow_response_count": 0,
        "no_result_count": 6,
        "median_delay_ms": 400.0,
        "p90_delay_ms": 800.0,
        "jitter_ms": 20.0,
    }
    history = reduce_history(
        history,
        run_context={
            "run_id": "region-run-1",
            "source_sha256": hashlib.sha256(b"region-1").hexdigest(),
            "accepted_at": "2026-08-01T00:00:00Z",
            "valid_run": True,
            "accepted": True,
            "identity_key_version": "test-k1",
            "identity_epoch": "identity-v1",
            "selection_policy_version": SELECTION_POLICY_VERSION,
        },
        source_events={cid(index): "present"},
        measurements={cid(index): responsive},
        decisions={
            cid(index): {
                "is_asia": True,
                "proposed_state": "asia_core",
                "source_alias": "Korea Stable",
                "selected": True,
                "region_cache": cache,
            }
        },
    )
    zero = {
        "total_rounds": 20,
        "response_count": 0,
        "within_limit_count": 0,
        "slow_response_count": 0,
        "no_result_count": 20,
        "median_delay_ms": None,
        "p90_delay_ms": None,
        "jitter_ms": None,
    }
    return reduce_history(
        history,
        run_context={
            "run_id": "region-run-2",
            "source_sha256": hashlib.sha256(b"region-2").hexdigest(),
            "accepted_at": "2026-08-02T00:00:00Z",
            "valid_run": True,
            "accepted": True,
            "identity_key_version": "test-k1",
            "identity_epoch": "identity-v1",
            "selection_policy_version": SELECTION_POLICY_VERSION,
        },
        source_events={cid(index): "present"},
        measurements={cid(index): zero},
        decisions={
            cid(index): {
                "is_asia": True,
                "proposed_state": "asia_manual_candidate",
                "source_alias": "Korea Stable",
                "selected": True,
                "region_cache": cache,
            }
        },
    )


class RegionResolutionTests(unittest.TestCase):
    def test_observation_must_bind_identity_version_and_be_fresh(self):
        history = empty_history(
            identity_key_version="test-k1",
            identity_epoch="identity-v1",
            selection_policy_version=SELECTION_POLICY_VERSION,
        )
        wrong_identity = observation(8, "JP", "2026-08-11T00:00:00Z")
        wrong_identity["identity_epoch"] = "identity-v2"
        with self.assertRaisesRegex(RegionError, "identity version mismatch"):
            resolve_region_decisions(
                {cid(8): metadata("source_hint:JP")},
                {cid(8): measurement(1)},
                history,
                {cid(8): wrong_identity},
                now="2026-08-11T00:01:00Z",
            )
        with self.assertRaisesRegex(RegionError, "older than the cache TTL"):
            resolve_region_decisions(
                {cid(8): metadata("source_hint:JP")},
                {cid(8): measurement(1)},
                history,
                {cid(8): observation(8, "JP", "2026-08-03T00:00:00Z")},
                now="2026-08-11T00:01:00Z",
            )

    def test_real_exit_wins_and_records_source_conflict(self):
        candidates = {cid(1): metadata("source_hint:KR")}
        decisions = resolve_region_decisions(
            candidates,
            {cid(1): measurement(20)},
            empty_history(
                identity_key_version="test-k1",
                identity_epoch="identity-v1",
                selection_policy_version=SELECTION_POLICY_VERSION,
            ),
            {cid(1): observation(1, "US", "2026-08-11T00:00:00Z")},
            now="2026-08-11T00:01:00Z",
        )

        self.assertEqual(decisions[cid(1)]["country_code"], "US")
        self.assertEqual(decisions[cid(1)]["confidence"], "conflict")
        self.assertFalse(decisions[cid(1)]["verified_target_asia"])
        self.assertFalse(decisions[cid(1)]["temporary_target_asia"])

    def test_source_specific_fallback_is_manual_only_evidence(self):
        decisions = resolve_region_decisions(
            {cid(2): metadata("source_hint:JP", "name_hint:JP")},
            {cid(2): measurement(1)},
            empty_history(
                identity_key_version="test-k1",
                identity_epoch="identity-v1",
                selection_policy_version=SELECTION_POLICY_VERSION,
            ),
            {},
            now="2026-08-11T00:00:00Z",
        )

        self.assertEqual(decisions[cid(2)]["confidence"], "source-specific")
        self.assertTrue(decisions[cid(2)]["temporary_target_asia"])
        self.assertFalse(decisions[cid(2)]["verified_target_asia"])
        self.assertIsNone(decisions[cid(2)]["cache"])

    def test_name_hint_alone_never_grants_asia_fallback(self):
        decisions = resolve_region_decisions(
            {cid(3): metadata("name_hint:SG")},
            {cid(3): measurement(1)},
            empty_history(
                identity_key_version="test-k1",
                identity_epoch="identity-v1",
                selection_policy_version=SELECTION_POLICY_VERSION,
            ),
            {},
            now="2026-08-11T00:00:00Z",
        )

        self.assertEqual(decisions[cid(3)]["confidence"], "unknown")
        self.assertFalse(decisions[cid(3)]["temporary_target_asia"])

    def test_history_protected_node_uses_thirty_day_stale_grace(self):
        history = protected_history(4)
        candidates = {cid(4): metadata("source_hint:KR")}
        decisions = resolve_region_decisions(
            candidates,
            {cid(4): measurement(0)},
            history,
            {},
            now="2026-08-11T00:00:00Z",
        )

        self.assertEqual(decisions[cid(4)]["country_code"], "KR")
        self.assertTrue(decisions[cid(4)]["stale"])
        self.assertEqual(decisions[cid(4)]["reason"], "history_cache_grace")
        self.assertIn(cid(4), build_region_query_plan(candidates, {cid(4): measurement(0)}, history))

    def test_new_zero_response_candidate_is_not_queried(self):
        history = empty_history(
            identity_key_version="test-k1",
            identity_epoch="identity-v1",
            selection_policy_version=SELECTION_POLICY_VERSION,
        )
        self.assertEqual(
            build_region_query_plan(
                {cid(5): metadata("source_hint:TW")},
                {cid(5): measurement(0)},
                history,
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
