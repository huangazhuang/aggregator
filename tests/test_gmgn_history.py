from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.gmgn_history import (
    HistoryMigrationError,
    HistoryValidationError,
    bootstrap_legacy_profile,
    empty_history,
    garbage_collect_tombstones,
    history_json_bytes,
    legacy_tombstone_count,
    load_history,
    migrate_history_identity,
    reconcile_legacy_tombstone,
    reduce_history,
    validate_history,
    write_history_atomic,
)
from scripts.proxy_identity import IdentitySettings, candidate_id, canonical_proxy_fingerprint


KEY = b"documented-history-test-key"
OLD = IdentitySettings(KEY, "history-key-v1", "identity-v1")
NEW = IdentitySettings(b"documented-history-test-key-v2", "history-key-v2", "identity-v2")
POLICY = "selection-v2-test"
BASE_TIME = datetime(2026, 8, 11, 0, 0, tzinfo=timezone.utc)


def timestamp(hours: float = 0) -> str:
    return (BASE_TIME + timedelta(hours=hours)).isoformat().replace("+00:00", "Z")


def sha(index: int) -> str:
    return hashlib.sha256(f"source-{index}".encode()).hexdigest()


def proxy(name: str = "Korea Stable") -> dict:
    return {
        "name": name,
        "type": "vless",
        "server": "history.example",
        "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000101",
        "tls": True,
        "network": "ws",
        "ws-opts": {"path": "/history"},
    }


def cid(item: dict | None = None, settings: IdentitySettings = OLD) -> str:
    return candidate_id(
        item or proxy(),
        key=settings.key,
        identity_key_version=settings.identity_key_version,
        identity_epoch=settings.identity_epoch,
    )


def measurement(response: int, within: int | None = None) -> dict:
    within = response if within is None else within
    slow = response - within
    return {
        "attempts": 20,
        "response_count": response,
        "within_limit_count": within,
        "slow_response_count": slow,
        "no_result_count": 20 - response,
        "median_delay_ms": 320 if response else None,
        "p90_delay_ms": 760 if response else None,
        "jitter_ms": 30 if response else None,
    }


def run(index: int, hours: float, *, valid: bool = True, accepted: bool = True) -> dict:
    return {
        "run_id": f"run-{index}",
        "source_sha256": sha(index),
        "accepted_at": timestamp(hours),
        "valid_run": valid,
        "accepted": accepted,
        "identity_key_version": OLD.identity_key_version,
        "identity_epoch": OLD.identity_epoch,
        "selection_policy_version": POLICY,
    }


def decision(name: str = "Korea Stable", state: str = "asia_core") -> dict:
    return {
        "is_asia": True,
        "proposed_state": state,
        "source_alias": name,
        "selected": True,
        "region_cache": None,
    }


def stage(
    history: dict,
    run_context: dict,
    *,
    sample: dict | None = None,
    source_state: str | None = None,
    staged_decision: dict | None = None,
    candidate: str | None = None,
) -> dict:
    candidate = candidate or cid()
    return reduce_history(
        history,
        run_context=run_context,
        source_events={} if source_state is None else {candidate: source_state},
        measurements={} if sample is None else {candidate: sample},
        decisions={}
        if staged_decision is None
        else {candidate: staged_decision},
    )


class HistoryReducerTests(unittest.TestCase):
    def initial(self) -> dict:
        return empty_history(
            identity_key_version=OLD.identity_key_version,
            identity_epoch=OLD.identity_epoch,
            selection_policy_version=POLICY,
        )

    def responsive(self) -> dict:
        return stage(
            self.initial(),
            run(1, 0),
            sample=measurement(16),
            staged_decision=decision(),
        )

    def test_core_bad1_noncounted_bad2_bad3_remove_then_fast_recovery(self) -> None:
        history = self.responsive()
        node_id = cid()
        self.assertEqual(history["nodes"][node_id]["current_state"], "asia_core")

        history = stage(history, run(2, 6), sample=measurement(0), staged_decision=decision())
        self.assertEqual(history["nodes"][node_id]["bad_run_streak"], 1)
        self.assertEqual(history["nodes"][node_id]["current_state"], "history_protected")

        too_soon = stage(
            history, run(3, 7), sample=measurement(0), staged_decision=decision()
        )
        self.assertEqual(too_soon["last_accepted_run_id"], "run-3")
        self.assertEqual(too_soon["nodes"][node_id]["bad_run_streak"], 1)
        self.assertFalse(
            too_soon["nodes"][node_id]["recent_observations"][-1]["counted_bad"]
        )

        history = stage(
            too_soon, run(4, 12), sample=measurement(0), staged_decision=decision()
        )
        self.assertEqual(history["nodes"][node_id]["bad_run_streak"], 2)
        history = stage(
            history, run(5, 18), sample=measurement(0), staged_decision=decision()
        )
        self.assertEqual(history["nodes"][node_id]["bad_run_streak"], 3)
        self.assertEqual(history["nodes"][node_id]["current_state"], "removed_bad_streak")
        self.assertTrue(history["nodes"][node_id]["removed"])

        recovered = stage(
            history,
            run(6, 18.1),
            sample=measurement(12),
            staged_decision=decision(state="asia_flexible"),
        )
        node = recovered["nodes"][node_id]
        self.assertEqual(node["bad_run_streak"], 0)
        self.assertEqual(node["current_state"], "asia_flexible")
        self.assertEqual(node["transition_reason"], "recovered_quality")
        self.assertFalse(node["removed"])
        self.assertEqual(len(node["recent_observations"]), 5)

    def test_responsive_run_resets_bad1_without_waiting_six_hours(self) -> None:
        history = stage(
            self.responsive(), run(2, 6), sample=measurement(0), staged_decision=decision()
        )
        recovered = stage(
            history,
            run(3, 6.1),
            sample=measurement(1),
            staged_decision=decision(state="asia_manual_candidate"),
        )
        node = recovered["nodes"][cid()]
        self.assertEqual(node["bad_run_streak"], 0)
        self.assertEqual(node["current_state"], "asia_manual_candidate")
        self.assertEqual(node["transition_reason"], "recovered_response")

    def test_invalid_rejected_and_duplicate_runs_leave_bytes_unchanged(self) -> None:
        history = self.responsive()
        before = history_json_bytes(history)
        invalid = stage(
            history,
            run(2, 6, valid=False, accepted=False),
            sample=measurement(0),
            staged_decision=decision(),
        )
        self.assertEqual(history_json_bytes(invalid), before)

        duplicate_context = run(99, 10)
        duplicate_context["source_sha256"] = history["last_accepted_source_sha256"]
        duplicate = stage(
            history,
            duplicate_context,
            sample=measurement(0),
            staged_decision=decision(),
        )
        self.assertEqual(history_json_bytes(duplicate), before)
        self.assertEqual(history_json_bytes(history), before)

    def test_new_zero_response_asia_is_omitted_but_accepted_run_advances(self) -> None:
        history = stage(
            self.initial(),
            run(1, 0),
            sample=measurement(0),
            staged_decision=decision(name="Korea New"),
        )
        self.assertEqual(history["nodes"], {})
        self.assertEqual(history["last_accepted_run_id"], "run-1")

    def test_temporary_source_failure_does_not_remove_but_confirmed_missing_does(self) -> None:
        history = self.responsive()
        temporary = stage(history, run(2, 6), source_state="temporary_failure")
        node = temporary["nodes"][cid()]
        self.assertEqual(node["current_state"], "asia_core")
        self.assertEqual(node["bad_run_streak"], 0)
        self.assertFalse(node["removed"])

        missing = stage(temporary, run(3, 12), source_state="confirmed_missing")
        node = missing["nodes"][cid()]
        self.assertEqual(node["current_state"], "removed_source_missing")
        self.assertEqual(node["removed_reason"], "source_confirmed_missing")

    def test_last_good_zero_response_does_not_consume_asia_protection(self) -> None:
        history = stage(
            self.responsive(),
            run(2, 6),
            sample=measurement(0),
            source_state="last_good",
            staged_decision=decision(),
        )
        node = history["nodes"][cid()]
        self.assertEqual(node["current_state"], "asia_core")
        self.assertEqual(node["bad_run_streak"], 0)
        self.assertEqual(
            node["recent_observations"][-1]["reason"], "temporary_source_failure"
        )
        self.assertFalse(node["recent_observations"][-1]["counted_bad"])

    def test_unmentioned_node_is_not_given_a_synthetic_observation(self) -> None:
        history = self.responsive()
        before_node = copy.deepcopy(history["nodes"][cid()])
        advanced = reduce_history(
            history,
            run_context=run(2, 6),
            source_events={},
            measurements={},
            decisions={},
        )
        self.assertEqual(advanced["last_accepted_run_id"], "run-2")
        self.assertEqual(advanced["nodes"][cid()], before_node)

    def test_responsive_existing_candidate_requires_a_staged_decision(self) -> None:
        with self.assertRaisesRegex(HistoryValidationError, "staged decision"):
            stage(self.responsive(), run(2, 6), sample=measurement(10))

    def test_duplicate_source_sha_remains_idempotent_after_many_runs(self) -> None:
        history = self.initial()
        for index in range(1, 23):
            history = reduce_history(
                history,
                run_context=run(index, index * 6),
                source_events={},
                measurements={},
                decisions={},
            )
        before = history_json_bytes(history)
        duplicate_context = run(99, 200)
        duplicate_context["source_sha256"] = sha(1)
        duplicate = reduce_history(
            history,
            run_context=duplicate_context,
            source_events={},
            measurements={},
            decisions={},
        )
        self.assertEqual(history_json_bytes(duplicate), before)

    def test_invalid_config_removes_immediately(self) -> None:
        removed = stage(self.responsive(), run(2, 6), source_state="invalid_config")
        self.assertEqual(
            removed["nodes"][cid()]["current_state"], "removed_invalid_config"
        )

    def test_strict_schema_atomic_round_trip_and_public_leak_scan(self) -> None:
        history = self.responsive()
        broken = copy.deepcopy(history)
        broken["unexpected"] = True
        with self.assertRaises(HistoryValidationError):
            validate_history(broken)

        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=preferred or None) as directory:
            path = Path(directory) / "history.json"
            write_history_atomic(path, history)
            self.assertEqual(load_history(path), history)
            serialized = path.read_text(encoding="utf-8")
        self.assertNotIn(KEY.hex(), serialized)
        self.assertNotIn(canonical_proxy_fingerprint(proxy()), serialized)
        self.assertNotIn("history.example", serialized)
        self.assertNotRegex(serialized, r'"(?:server|port|proxy|password|uuid)"\s*:')

    def test_strict_schema_rejects_coercion_and_cross_field_drift(self) -> None:
        history = self.responsive()
        wrong_count = copy.deepcopy(history)
        node = wrong_count["nodes"][cid()]
        node["last_measurement"]["total_rounds"] = "20"
        node["recent_observations"][-1]["total_rounds"] = "20"
        with self.assertRaises(HistoryValidationError):
            validate_history(wrong_count)

        wrong_time = copy.deepcopy(history)
        wrong_time["nodes"][cid()]["first_seen_at"] = "2026-08-11 00:00:00Z"
        with self.assertRaises(HistoryValidationError):
            validate_history(wrong_time)

        wrong_transition = copy.deepcopy(history)
        wrong_transition["nodes"][cid()]["previous_state"] = "asia_flexible"
        with self.assertRaises(HistoryValidationError):
            validate_history(wrong_transition)

        orphan_observation = copy.deepcopy(history)
        orphan_observation["nodes"][cid()]["recent_observations"][-1][
            "run_id"
        ] = "orphan-run"
        with self.assertRaises(HistoryValidationError):
            validate_history(orphan_observation)


class HistoryMigrationTests(unittest.TestCase):
    def history(self) -> dict:
        base = empty_history(
            identity_key_version=OLD.identity_key_version,
            identity_epoch=OLD.identity_epoch,
            selection_policy_version=POLICY,
        )
        return stage(
            base, run(1, 0), sample=measurement(16), staged_decision=decision()
        )

    def removed_history(self) -> dict:
        history = self.history()
        history = stage(
            history, run(2, 6), sample=measurement(0), staged_decision=decision()
        )
        history = stage(
            history, run(3, 12), sample=measurement(0), staged_decision=decision()
        )
        return stage(
            history, run(4, 18), sample=measurement(0), staged_decision=decision()
        )

    def test_active_identity_migration_is_one_to_one_and_preserves_name(self) -> None:
        history = self.history()
        old_name = history["nodes"][cid()]["output_name"]
        migrated = migrate_history_identity(
            history,
            [proxy()],
            old_settings=OLD,
            new_settings=NEW,
            migrated_at=timestamp(1),
        )
        new_id = cid(settings=NEW)
        self.assertNotIn(cid(), migrated["nodes"])
        self.assertEqual(migrated["nodes"][new_id]["output_name"], old_name)
        self.assertEqual(migrated["nodes"][new_id]["transition_reason"], "identity_migrated")

        with self.assertRaises(HistoryMigrationError):
            migrate_history_identity(
                history,
                [],
                old_settings=OLD,
                new_settings=NEW,
                migrated_at=timestamp(1),
            )

    def test_absent_removed_node_becomes_legacy_and_reappears_under_new_id(self) -> None:
        removed = self.removed_history()
        original_name = removed["nodes"][cid()]["output_name"]
        rotated = migrate_history_identity(
            removed,
            [],
            old_settings=OLD,
            new_settings=NEW,
            migrated_at=timestamp(19),
        )
        self.assertEqual(legacy_tombstone_count(rotated), 1)
        with self.assertRaises(HistoryMigrationError):
            reconcile_legacy_tombstone(
                rotated,
                proxy(),
                active_settings=NEW,
                legacy_key_registry={},
                observed_at=timestamp(20),
            )

        reconciled, new_id, changed = reconcile_legacy_tombstone(
            rotated,
            proxy(),
            active_settings=NEW,
            legacy_key_registry={(OLD.identity_key_version, OLD.identity_epoch): OLD.key},
            observed_at=timestamp(20),
        )
        self.assertTrue(changed)
        self.assertEqual(new_id, cid(settings=NEW))
        self.assertEqual(reconciled["nodes"][new_id]["output_name"], original_name)
        self.assertFalse(reconciled["nodes"][new_id]["legacy_identity"])
        self.assertEqual(legacy_tombstone_count(reconciled), 0)

    def test_identity_rotation_rejects_active_to_legacy_id_collision(self) -> None:
        removed = self.removed_history()
        other = {**proxy("Other Active"), "port": 9443}
        unrelated_old_id = "c1_111111111111111111111111"
        with patch(
            "scripts.gmgn_history.candidate_id",
            side_effect=[unrelated_old_id, cid()],
        ), self.assertRaisesRegex(HistoryMigrationError, "legacy tombstone"):
            migrate_history_identity(
                removed,
                [other],
                old_settings=OLD,
                new_settings=NEW,
                migrated_at=timestamp(19),
            )

        rotated = migrate_history_identity(
            removed,
            [],
            old_settings=OLD,
            new_settings=NEW,
            migrated_at=timestamp(19),
        )
        with patch(
            "scripts.gmgn_history.candidate_id", return_value=cid()
        ), self.assertRaisesRegex(HistoryMigrationError, "legacy tombstone"):
            reconcile_legacy_tombstone(
                rotated,
                other,
                active_settings=NEW,
                legacy_key_registry={(OLD.identity_key_version, OLD.identity_epoch): OLD.key},
                observed_at=timestamp(20),
            )

    def test_tombstone_gc_is_explicit_audited_and_retention_checked(self) -> None:
        rotated = migrate_history_identity(
            self.removed_history(),
            [],
            old_settings=OLD,
            new_settings=NEW,
            migrated_at=timestamp(19),
        )
        with self.assertRaises(HistoryMigrationError):
            garbage_collect_tombstones(
                rotated,
                [cid()],
                gc_at=timestamp(24),
                audit_reason="retention-review",
            )
        gc_at = (BASE_TIME + timedelta(days=120)).isoformat().replace("+00:00", "Z")
        cleaned, evidence = garbage_collect_tombstones(
            rotated,
            [cid()],
            gc_at=gc_at,
            audit_reason="approved-retention-gc",
        )
        self.assertEqual(cleaned["nodes"], {})
        self.assertEqual(evidence[0]["candidate_id"], cid())
        self.assertTrue(evidence[0]["legacy_identity"])

    def test_legacy_bootstrap_verifies_hash_count_and_preserves_safe_unique_names(self) -> None:
        proxies = [proxy("Korea Legacy"), {**proxy("Japan Legacy"), "port": 8443}]
        profile_bytes = yaml.safe_dump(
            {"proxies": proxies, "proxy-groups": []},
            allow_unicode=True,
            sort_keys=False,
        ).encode("utf-8")
        status = {
            "kind": "cnb-gmgn-publish-status",
            "schema_version": 1,
            "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
            "published_count": 2,
            "run_id": "legacy-run",
            "source_sha256": sha(1),
            "run_at": timestamp(0),
        }
        history = bootstrap_legacy_profile(
            profile_bytes,
            status,
            identity_settings=OLD,
            selection_policy_version=POLICY,
        )
        self.assertEqual(
            {node["output_name"] for node in history["nodes"].values()},
            {"Korea Legacy", "Japan Legacy"},
        )
        self.assertTrue(
            all(
                node["transition_reason"] == "bootstrap_legacy_profile"
                and node["bad_run_streak"] == 0
                for node in history["nodes"].values()
            )
        )
        bad_status = dict(status, profile_sha256="0" * 64)
        with self.assertRaises(HistoryMigrationError):
            bootstrap_legacy_profile(
                profile_bytes,
                bad_status,
                identity_settings=OLD,
                selection_policy_version=POLICY,
            )
        duplicate_profile = yaml.safe_dump(
            {"proxies": [proxy("Duplicate"), {**proxy("Duplicate"), "port": 9443}]},
            allow_unicode=True,
            sort_keys=False,
        ).encode("utf-8")
        duplicate_status = {
            **status,
            "profile_sha256": hashlib.sha256(duplicate_profile).hexdigest(),
        }
        with self.assertRaises(HistoryMigrationError):
            bootstrap_legacy_profile(
                duplicate_profile,
                duplicate_status,
                identity_settings=OLD,
                selection_policy_version=POLICY,
            )

        dangling_profile = yaml.safe_dump(
            {
                "proxies": [proxy("Korea Legacy")],
                "proxy-groups": [
                    {"name": "Manual", "type": "select", "proxies": ["Missing"]}
                ],
            },
            allow_unicode=True,
            sort_keys=False,
        ).encode("utf-8")
        dangling_status = {
            **status,
            "profile_sha256": hashlib.sha256(dangling_profile).hexdigest(),
            "published_count": 1,
        }
        with self.assertRaisesRegex(HistoryMigrationError, "dangling"):
            bootstrap_legacy_profile(
                dangling_profile,
                dangling_status,
                identity_settings=OLD,
                selection_policy_version=POLICY,
            )

        invalid_proxy = proxy("Korea Legacy")
        invalid_proxy.pop("port")
        invalid_profile = yaml.safe_dump(
            {"proxies": [invalid_proxy], "proxy-groups": []},
            allow_unicode=True,
            sort_keys=False,
        ).encode("utf-8")
        invalid_status = {
            **status,
            "profile_sha256": hashlib.sha256(invalid_profile).hexdigest(),
            "published_count": 1,
        }
        with self.assertRaisesRegex(HistoryMigrationError, "invalid proxy"):
            bootstrap_legacy_profile(
                invalid_profile,
                invalid_status,
                identity_settings=OLD,
                selection_policy_version=POLICY,
            )

        with self.assertRaisesRegex(HistoryMigrationError, "schema"):
            bootstrap_legacy_profile(
                profile_bytes,
                {**status, "schema_version": 99},
                identity_settings=OLD,
                selection_policy_version=POLICY,
            )


if __name__ == "__main__":
    unittest.main()
