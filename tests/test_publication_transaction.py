from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from scripts.gmgn_history import empty_history, reduce_history
from scripts.gmgn_measurement import ERROR_CATEGORIES, VALIDITY_POLICY_VERSION
from scripts.gmgn_region import REGION_POLICY_VERSION
from scripts.gmgn_selection import (
    NODE_STATUS_SCHEMA_VERSION,
    SELECTION_POLICY_VERSION,
    V2_GROUP_NAMES,
)
from scripts.publish_transaction import (
    PreviousState,
    PreviousStateError,
    PublicationError,
    PublicationTransactionError,
    RUN_DIAGNOSTICS_KIND,
    RUN_DIAGNOSTICS_SCHEMA_VERSION,
    attach_previous_bundle,
    authoritative_ref,
    build_publish_bundle,
    classify_previous_ref,
    compute_logical_bundle_hash,
    decide_source_trigger,
    execute_transaction,
    force_with_lease_argument,
    load_publish_bundle,
    parse_expected_previous_tip,
    publication_revision,
    public_json_bytes,
    staging_ref_for_source,
    validate_publish_bundle,
    write_publish_bundle,
)


CID = "c1_" + "1" * 24
SOURCE_SHA = "1" * 64
SOURCE_PROFILE_SHA = "2" * 64
METADATA_SHA = "3" * 64
MAIN_SHA = "a" * 40
ACCEPTED_AT = "2026-08-11T00:00:00Z"
SOURCE_RUN_AT = "2026-08-10T23:45:00Z"


def history_fixture(
    *,
    source_sha: str = SOURCE_SHA,
    accepted_at: str = ACCEPTED_AT,
    run_id: str = "run-1",
    previous_history: dict | None = None,
) -> dict:
    history = previous_history or empty_history(
        identity_key_version="key-v1",
        identity_epoch="epoch-v1",
        selection_policy_version=SELECTION_POLICY_VERSION,
    )
    return reduce_history(
        history,
        run_context={
            "run_id": run_id,
            "source_sha256": source_sha,
            "accepted_at": accepted_at,
            "valid_run": True,
            "accepted": True,
            "identity_key_version": "key-v1",
            "identity_epoch": "epoch-v1",
            "selection_policy_version": SELECTION_POLICY_VERSION,
        },
        source_events={CID: "present"},
        measurements={
            CID: {
                "total_rounds": 20,
                "response_count": 20,
                "within_limit_count": 20,
                "slow_response_count": 0,
                "no_result_count": 0,
                "median_delay_ms": 80.0,
                "p90_delay_ms": 100.0,
                "jitter_ms": 5.0,
            }
        },
        decisions={
            CID: {
                "is_asia": True,
                "proposed_state": "asia_core",
                "source_alias": "Node A",
                "selected": True,
                "region_cache": None,
            }
        },
    )


def selection_fixture(
    *, source_sha: str = SOURCE_SHA, run_id: str = "run-1"
) -> dict:
    proxy = {
        "name": "Node A",
        "type": "ss",
        "server": "203.0.113.10",
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": "fixture-secret",
    }
    groups = [
        {"name": name, "type": "select", "proxies": ["Node A"]}
        for name in V2_GROUP_NAMES
    ]
    summary = {
        "source_candidate_count": 1,
        "published_count": 1,
        "stable_capacity_count": 1,
        "desired_capacity": 80,
        "desired_capacity_reached": False,
        "max_nodes": 150,
        "asia_core_count": 1,
        "asia_flexible_count": 0,
        "asia_manual_candidate_count": 0,
        "history_protected_count": 0,
        "non_asia_stable_count": 0,
        "unknown_region_count": 0,
        "region_counts": {"HK": 1, "JP": 0, "KR": 0, "SG": 0, "TW": 0},
        "capacity_trimmed_count": 0,
        "diversity_trimmed_count": 0,
        "diversity_limits": {
            "exit_id_cap": 3,
            "server_id_cap": 3,
            "asn_id_cap": 3,
            "source_id_cap": 2,
        },
    }
    node_status = {
        "kind": "cnb-gmgn-node-status",
        "schema_version": NODE_STATUS_SCHEMA_VERSION,
        "run_id": run_id,
        "source_sha256": source_sha,
        "main_sha": MAIN_SHA,
        "profile_sha256": SOURCE_PROFILE_SHA,
        "candidate_metadata_sha256": METADATA_SHA,
        "identity_key_version": "key-v1",
        "identity_epoch": "epoch-v1",
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": REGION_POLICY_VERSION,
        "summary": copy.deepcopy(summary),
        "nodes": [
            {
                "candidate_id": CID,
                "output_name": "Node A",
                "tier": "asia_core",
                "eligible_tier": "asia_core",
                "reason": "asia_core_quality",
                "selected": True,
                "priority_selected": True,
                "auto_selected": True,
                "country_code": "HK",
                "region_confidence": "verified",
                "region_stale": False,
                "within_1000_count": 20,
                "under_1000_count": 20,
                "response_count": 20,
                "slow_response_count": 0,
                "over_1000_count": 0,
                "no_result_count": 0,
                "timeout_count": 0,
                "error_counts": {category: 0 for category in ERROR_CATEGORIES},
                "first_half_within_1000_count": 10,
                "second_half_within_1000_count": 10,
                "median_delay_ms": 80.0,
                "p90_delay_ms": 100.0,
                "jitter_ms": 5.0,
                "history_transition": "responsive_observation",
                "concentration_flags": [],
            }
        ],
    }
    return {
        "kind": "cnb-gmgn-selection-result",
        "schema_version": 1,
        "run_id": run_id,
        "source_sha256": source_sha,
        "main_sha": MAIN_SHA,
        "profile_sha256": SOURCE_PROFILE_SHA,
        "candidate_metadata_sha256": METADATA_SHA,
        "identity_key_version": "key-v1",
        "identity_epoch": "epoch-v1",
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": REGION_POLICY_VERSION,
        "selected": [],
        "tier_ids": {
            "asia_core": [CID],
            "asia_flexible": [],
            "asia_manual_candidate": [],
            "history_protected": [],
            "non_asia_stable": [],
        },
        "priority_ids": [CID],
        "auto_ids": [CID],
        "profile": {
            "proxies": [proxy],
            "proxy-groups": groups,
            "rules": ["MATCH,👆手动优先测速"],
        },
        "summary": summary,
        "node_status": node_status,
        "history_decisions": {},
    }


def diagnostics_fixture(
    *,
    source_sha: str = SOURCE_SHA,
    accepted_at: str = ACCEPTED_AT,
    source_run_at: str = SOURCE_RUN_AT,
    run_id: str = "run-1",
    attempt_id: str = "1" * 24,
    retry_of: str | None = None,
) -> dict:
    return {
        "kind": RUN_DIAGNOSTICS_KIND,
        "schema_version": RUN_DIAGNOSTICS_SCHEMA_VERSION,
        "bundle_hash": None,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "retry_of": retry_of,
        "accepted_at": accepted_at,
        "source_run_at": source_run_at,
        "source_sha256": source_sha,
        "main_sha": MAIN_SHA,
        "profile_sha256": SOURCE_PROFILE_SHA,
        "candidate_metadata_sha256": METADATA_SHA,
        "identity_key_version": "key-v1",
        "identity_epoch": "epoch-v1",
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": REGION_POLICY_VERSION,
        "validity_policy_version": VALIDITY_POLICY_VERSION,
        "total_rounds": 20,
        "shard_count": 4,
        "minimum_observation_window_seconds": 900.0,
        "valid_run": True,
        "validity_reasons": [],
        "metrics": {"candidate_count": 1, "target_403_429_rate": 0.0},
        "shards": [
            {
                "shard_index": index,
                "candidate_count": 1 if index == 0 else 0,
                "controller_healthy_check_count": 40,
                "controller_unhealthy_count": 0,
                "egress_country": "CN",
                "egress_region": "shanghai",
                "canary_count": 1,
            }
            for index in range(4)
        ],
    }


def bundle_fixture(
    *,
    source_sha: str = SOURCE_SHA,
    accepted_at: str = ACCEPTED_AT,
    source_run_at: str = SOURCE_RUN_AT,
    run_id: str = "run-1",
    previous_run_index: dict | None = None,
    previous_history: dict | None = None,
):
    binary = b"fixed-mihomo"
    bundle = build_publish_bundle(
        selection_result=selection_fixture(source_sha=source_sha, run_id=run_id),
        history=history_fixture(
            source_sha=source_sha,
            accepted_at=accepted_at,
            run_id=run_id,
            previous_history=previous_history,
        ),
        diagnostics=diagnostics_fixture(
            source_sha=source_sha,
            accepted_at=accepted_at,
            source_run_at=source_run_at,
            run_id=run_id,
        ),
        runtime={
            "python_version": "3.12.11",
            "pyyaml_version": "6.0.2",
            "mihomo_version": "Mihomo v1.19.0",
            "mihomo_sha256": hashlib.sha256(binary).hexdigest(),
        },
        accepted_at=accepted_at,
        source_run_at=source_run_at,
        previous_run_index=previous_run_index,
    )
    return bundle, binary


class PublishBundleTests(unittest.TestCase):
    def test_bundle_hash_is_non_recursive_and_every_payload_is_bound(self) -> None:
        bundle, _binary = bundle_fixture()
        self.assertEqual(compute_logical_bundle_hash(bundle.files), bundle.bundle_hash)
        self.assertEqual(
            set(bundle.files),
            {
                "bundle.json",
                "clash.yaml",
                "status.json",
                "history.json",
                "node-status.json",
                "runs/index.json",
                "runs/run-1/diagnostics.json",
            },
        )
        for path, content in bundle.files.items():
            if path.endswith(".json") and path != "bundle.json":
                self.assertEqual(json.loads(content)["bundle_hash"], bundle.bundle_hash)

    def test_bundle_round_trip_and_exact_allowlist(self) -> None:
        bundle, _binary = bundle_fixture()
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            write_publish_bundle(directory, bundle)
            self.assertEqual(load_publish_bundle(directory).files, bundle.files)
            Path(directory, "README.md").write_text("unbound", encoding="utf-8")
            with self.assertRaisesRegex(PublicationError, "allowlist"):
                load_publish_bundle(directory)

    def test_tamper_and_branch_specific_metadata_fail_closed(self) -> None:
        bundle, _binary = bundle_fixture()
        tampered = dict(bundle.files)
        tampered["clash.yaml"] += b"\n"
        with self.assertRaisesRegex(PublicationError, "hash"):
            validate_publish_bundle(tampered)

        diagnostics = diagnostics_fixture()
        diagnostics["metrics"]["mode"] = "shadow"
        with self.assertRaisesRegex(PublicationError, "branch-specific"):
            build_publish_bundle(
                selection_result=selection_fixture(),
                history=history_fixture(),
                diagnostics=diagnostics,
                runtime={
                    "python_version": "3.12",
                    "pyyaml_version": "6.0.2",
                    "mihomo_version": "fixture",
                    "mihomo_sha256": "4" * 64,
                },
                accepted_at=ACCEPTED_AT,
                source_run_at=SOURCE_RUN_AT,
            )

    def test_public_diagnostics_reject_ip_shaped_regions(self) -> None:
        for value in (
            "203.0.113.7",
            "[2001:db8::7]",
            "203.0.113.7:443",
            "runner-8.8.8.8",
        ):
            diagnostics = diagnostics_fixture()
            diagnostics["shards"][0]["egress_region"] = value
            with self.subTest(field="egress_region", value=value):
                with self.assertRaisesRegex(PublicationError, "IP address"):
                    build_publish_bundle(
                        selection_result=selection_fixture(),
                        history=history_fixture(),
                        diagnostics=diagnostics,
                        runtime={
                            "python_version": "3.12",
                            "pyyaml_version": "6.0.2",
                            "mihomo_version": "fixture",
                            "mihomo_sha256": "4" * 64,
                        },
                        accepted_at=ACCEPTED_AT,
                        source_run_at=SOURCE_RUN_AT,
                    )

        diagnostics = diagnostics_fixture()
        diagnostics["metrics"]["runner_region"] = "2001:db8::8"
        with self.assertRaisesRegex(PublicationError, "IP address"):
            build_publish_bundle(
                selection_result=selection_fixture(),
                history=history_fixture(),
                diagnostics=diagnostics,
                runtime={
                    "python_version": "3.12",
                    "pyyaml_version": "6.0.2",
                    "mihomo_version": "fixture",
                    "mihomo_sha256": "4" * 64,
                },
                accepted_at=ACCEPTED_AT,
                source_run_at=SOURCE_RUN_AT,
            )

        selection = selection_fixture()
        selection["node_status"]["nodes"][0]["timeout_count"] = 1
        with self.assertRaisesRegex(PublicationError, "timeout count"):
            build_publish_bundle(
                selection_result=selection,
                history=history_fixture(),
                diagnostics=diagnostics_fixture(),
                runtime={
                    "python_version": "3.12",
                    "pyyaml_version": "6.0.2",
                    "mihomo_version": "fixture",
                    "mihomo_sha256": "4" * 64,
                },
                accepted_at=ACCEPTED_AT,
                source_run_at=SOURCE_RUN_AT,
            )

        selection = selection_fixture()
        selection["node_status"]["nodes"][0]["error_counts"]["target_403"] = 1
        with self.assertRaisesRegex(PublicationError, "error counts do not conserve"):
            build_publish_bundle(
                selection_result=selection,
                history=history_fixture(),
                diagnostics=diagnostics_fixture(),
                runtime={
                    "python_version": "3.12",
                    "pyyaml_version": "6.0.2",
                    "mihomo_version": "fixture",
                    "mihomo_sha256": "4" * 64,
                },
                accepted_at=ACCEPTED_AT,
                source_run_at=SOURCE_RUN_AT,
            )

    def test_manifest_and_node_status_bindings_fail_closed(self) -> None:
        bundle, _binary = bundle_fixture()
        tampered = dict(bundle.files)
        manifest = json.loads(tampered["bundle.json"])
        manifest["accepted_at"] = "2026-08-11T00:00:01Z"
        tampered["bundle.json"] = public_json_bytes(manifest)
        with self.assertRaisesRegex(PublicationError, "accepted_at"):
            validate_publish_bundle(tampered)

        selection = selection_fixture()
        node_summary = selection["node_status"]["summary"]
        node_summary["published_count"] = 0
        node_summary["stable_capacity_count"] = 0
        node_summary["asia_core_count"] = 0
        node_summary["region_counts"]["HK"] = 0
        with self.assertRaisesRegex(PublicationError, "selected count"):
            build_publish_bundle(
                selection_result=selection,
                history=history_fixture(),
                diagnostics=diagnostics_fixture(),
                runtime={
                    "python_version": "3.12",
                    "pyyaml_version": "6.0.2",
                    "mihomo_version": "fixture",
                    "mihomo_sha256": "4" * 64,
                },
                accepted_at=ACCEPTED_AT,
                source_run_at=SOURCE_RUN_AT,
            )

    def test_run_index_keeps_last_five_and_rejects_duplicate_source(self) -> None:
        bundle, _binary = bundle_fixture()
        previous = json.loads(bundle.files["runs/index.json"])
        with self.assertRaisesRegex(PublicationError, "already contains"):
            bundle_fixture(previous_run_index=previous)


class PreviousAndTransactionTests(unittest.TestCase):
    def test_authoritative_branch_is_exactly_v2_shadow(self) -> None:
        self.assertEqual(
            authoritative_ref(), "refs/heads/clash-cn-gmgn-v2-shadow"
        )
        for branch in ("main", "clash-cn-output", "clash-cn-gmgn-output"):
            with self.subTest(branch=branch):
                with self.assertRaisesRegex(PublicationError, "must be"):
                    authoritative_ref(branch)

    def test_previous_absent_and_unreadable_are_distinct(self) -> None:
        absent = classify_previous_ref(
            branch="clash-cn-gmgn-v2-shadow",
            ls_remote_output="",
            command_returncode=0,
        )
        self.assertFalse(absent.exists)
        with self.assertRaisesRegex(PreviousStateError, "unreadable"):
            classify_previous_ref(
                branch="clash-cn-gmgn-v2-shadow",
                ls_remote_output="",
                command_returncode=128,
            )

    def test_lease_arguments_cover_existing_and_first_publish(self) -> None:
        ref = "refs/heads/clash-cn-gmgn-v2-shadow"
        self.assertEqual(
            force_with_lease_argument(ref, None),
            f"--force-with-lease={ref}:",
        )
        self.assertEqual(
            force_with_lease_argument(ref, "a" * 40),
            f"--force-with-lease={ref}:{'a' * 40}",
        )
        self.assertTrue(staging_ref_for_source(SOURCE_SHA).endswith(SOURCE_SHA))

    def test_expected_previous_tip_and_smoke_revisions_are_strict(self) -> None:
        authoritative = "refs/heads/clash-cn-gmgn-v2-shadow"
        staging = staging_ref_for_source(SOURCE_SHA)
        self.assertIsNone(parse_expected_previous_tip("absent"))
        self.assertEqual(parse_expected_previous_tip("a" * 40), "a" * 40)
        with self.assertRaisesRegex(PublicationError, "expected previous tip"):
            parse_expected_previous_tip("missing")
        self.assertEqual(
            publication_revision(
                ref=staging,
                authoritative=authoritative,
                expected_commit="b" * 40,
            ),
            "b" * 40,
        )
        self.assertEqual(
            publication_revision(
                ref=authoritative,
                authoritative=authoritative,
                expected_commit="b" * 40,
            ),
            "clash-cn-gmgn-v2-shadow",
        )

    def test_transaction_orders_staging_smoke_promotion_and_current_smoke(self) -> None:
        bundle, _binary = bundle_fixture()
        events: list[tuple] = []
        refs: dict[str, str] = {}

        def read_ref(ref: str):
            events.append(("read", ref))
            return refs.get(ref)

        def push(ref: str, expected: str | None, target: str | None):
            events.append(("push", ref, expected, target))
            self.assertEqual(refs.get(ref), expected)
            if target is None:
                refs.pop(ref, None)
            else:
                refs[ref] = target

        def smoke(ref: str, commit: str, _bundle):
            events.append(("smoke", ref, commit))

        result = execute_transaction(
            bundle=bundle,
            previous=PreviousState(False, None, None),
            commit_bundle=lambda _bundle: "b" * 40,
            read_ref=read_ref,
            push_with_lease=push,
            smoke=smoke,
        )
        self.assertEqual(result.commit, "b" * 40)
        self.assertEqual(
            [event[0] for event in events],
            ["read", "push", "smoke", "push", "read", "smoke", "read"],
        )

    def test_post_promotion_failure_rolls_back_with_candidate_tip_lease(self) -> None:
        previous_bundle, _binary = bundle_fixture(
            source_sha="5" * 64,
            accepted_at="2026-08-10T00:00:00Z",
            source_run_at="2026-08-09T23:45:00Z",
            run_id="run-0",
        )
        bundle, _binary = bundle_fixture()
        refs = {"refs/heads/clash-cn-gmgn-v2-shadow": "a" * 40}
        pushes: list[tuple] = []
        smoke_count = 0

        def read_ref(ref: str):
            return refs.get(ref)

        def push(ref: str, expected: str | None, target: str | None):
            pushes.append((ref, expected, target))
            if refs.get(ref) != expected:
                raise RuntimeError("lease conflict")
            if target is None:
                refs.pop(ref, None)
            else:
                refs[ref] = target

        def smoke(_ref: str, _commit: str, _bundle):
            nonlocal smoke_count
            smoke_count += 1
            if smoke_count == 2:
                raise RuntimeError("stale cache")

        previous = attach_previous_bundle(
            PreviousState(True, "a" * 40, None), previous_bundle
        )
        with self.assertRaisesRegex(PublicationTransactionError, "restored"):
            execute_transaction(
                bundle=bundle,
                previous=previous,
                commit_bundle=lambda _bundle: "b" * 40,
                read_ref=read_ref,
                push_with_lease=push,
                smoke=smoke,
            )
        self.assertEqual(refs["refs/heads/clash-cn-gmgn-v2-shadow"], "a" * 40)
        self.assertEqual(pushes[-1][1:], ("b" * 40, "a" * 40))

    def test_older_source_and_tip_change_during_smoke_cannot_overwrite_current(self) -> None:
        previous_bundle, _binary = bundle_fixture(
            source_sha="5" * 64,
            accepted_at="2026-08-10T00:00:00Z",
            source_run_at="2026-08-09T23:45:00Z",
            run_id="run-0",
        )
        stale_bundle, _binary = bundle_fixture(
            source_sha="6" * 64,
            accepted_at="2026-08-11T01:00:00Z",
            source_run_at="2026-08-09T23:30:00Z",
            run_id="run-stale",
        )
        previous = attach_previous_bundle(
            PreviousState(True, "a" * 40, None), previous_bundle
        )
        with self.assertRaisesRegex(PublicationTransactionError, "source snapshot"):
            execute_transaction(
                bundle=stale_bundle,
                previous=previous,
                commit_bundle=lambda _bundle: "b" * 40,
                read_ref=lambda _ref: None,
                push_with_lease=lambda _ref, _expected, _target: None,
                smoke=lambda _ref, _commit, _bundle: None,
            )

        current_bundle, _binary = bundle_fixture()
        refs = {"refs/heads/clash-cn-gmgn-v2-shadow": "a" * 40}

        def read_ref(ref: str):
            return refs.get(ref)

        def push(ref: str, expected: str | None, target: str | None):
            if refs.get(ref) != expected:
                raise RuntimeError("lease conflict")
            if target is None:
                refs.pop(ref, None)
            else:
                refs[ref] = target

        smoke_count = 0

        def smoke(ref: str, _commit: str, _bundle):
            nonlocal smoke_count
            smoke_count += 1
            if smoke_count == 2:
                refs[ref] = "c" * 40

        with self.assertRaisesRegex(PublicationTransactionError, "rollback failed"):
            execute_transaction(
                bundle=current_bundle,
                previous=previous,
                commit_bundle=lambda _bundle: "b" * 40,
                read_ref=read_ref,
                push_with_lease=push,
                smoke=smoke,
            )
        self.assertEqual(refs["refs/heads/clash-cn-gmgn-v2-shadow"], "c" * 40)

    def test_source_sha_trigger_is_idempotent(self) -> None:
        self.assertEqual(
            decide_source_trigger(
                source_sha256=SOURCE_SHA,
                current_status={"source_sha256": SOURCE_SHA},
            ),
            "noop_accepted",
        )
        self.assertEqual(
            decide_source_trigger(
                source_sha256=SOURCE_SHA,
                current_status=None,
                queued_or_running=[SOURCE_SHA],
            ),
            "noop_active",
        )
        self.assertEqual(
            decide_source_trigger(
                source_sha256=SOURCE_SHA,
                current_status=None,
                retry=True,
            ),
            "retry_failed_infrastructure",
        )


if __name__ == "__main__":
    unittest.main()
