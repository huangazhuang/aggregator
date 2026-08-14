from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from scripts import build_crawler_config
from scripts.asia_source_registry import (
    AsiaSourceError,
    ENDPOINT_MAX_VARIANTS,
    REGION_MAX_CANDIDATES,
    REGION_ORDER,
    SOURCE_MAX_CANDIDATES,
    enforce_registered_source_policy,
    estimate_gmgn_capacity,
    evaluate_source_gain,
    external_asia_domains,
    select_registered_source_candidates,
)
from scripts.candidate_contract import CANDIDATE_METADATA_SCHEMA_VERSION
from scripts.evaluate_asia_sources import (
    EvaluationError,
    _audit_output_dir,
    build_report,
    evaluation_identity_settings,
)
from scripts.candidate_snapshot import (
    CANDIDATE_METADATA_KIND,
    CANDIDATE_STATUS_KIND,
    CANDIDATE_STATUS_SCHEMA_VERSION,
    CandidateSnapshotError,
    build_candidate_snapshot,
    evaluate_candidate_publish_gate,
    prepare_candidate_identity_input,
)
from scripts.candidate_sources import (
    EndpointResolutionInfrastructureError,
    provenance_for_task,
    safe_source_descriptor,
)
from scripts.proxy_identity import IdentitySettings, compute_public_ids
from subscribe.workflow import TaskConfig, dedup_task
from subscribe import workflow as workflow_module


IDENTITY = IdentitySettings(
    key=b"asia-source-test-key",
    identity_key_version="test-key-v1",
    identity_epoch="test-epoch-v1",
)
REGION_LABELS = {
    "HK": "Hong Kong",
    "JP": "Japan Tokyo",
    "KR": "Korea Seoul",
    "SG": "Singapore",
    "TW": "Taiwan Taipei",
}


def proxy(
    region: str,
    index: int,
    *,
    port: int | None = None,
    password: str | None = None,
    server: str = "8.8.8.8",
) -> dict:
    return {
        "name": f"{REGION_LABELS[region]} {index}",
        "type": "ss",
        "server": server,
        "port": port if port is not None else 10000 + index,
        "cipher": "aes-128-gcm",
        "password": password or f"secret-{region}-{index}",
    }


class SourceRegistryTests(unittest.TestCase):
    def test_external_sources_are_independently_flagged_and_default_off(self) -> None:
        disabled = external_asia_domains({})
        self.assertEqual({item["candidate_source"] for item in disabled}, {"awesome-vpn"})
        self.assertTrue(all(item["enable"] is False for item in disabled))
        self.assertTrue(all(item["publish_derivatives"] is True for item in disabled))
        self.assertTrue(all(item["liveness"] is False for item in disabled))
        self.assertTrue(all(item["candidate_source_role"] == "fixed" for item in disabled))

        source_only = external_asia_domains({"ENABLE_ASIA_SOURCE_AWESOME_VPN": "true"})
        self.assertTrue(all(item["enable"] is False for item in source_only))

        enabled = external_asia_domains(
            {
                "ENABLE_CANDIDATE_V2": "true",
                "ENABLE_ASIA_SOURCE_AWESOME_VPN": "true",
            }
        )
        states = {item["candidate_source"]: item["enable"] for item in enabled}
        self.assertEqual(states, {"awesome-vpn": True})

        workflow = Path(".github/workflows/clash-verge-auto.yml").read_text(encoding="utf-8")
        self.assertIn("vars.ENABLE_ASIA_SOURCE_AWESOME_VPN || 'false'", workflow)
        self.assertNotIn("ENABLE_ASIA_SOURCE_MAHDIBLAND", workflow)

    def test_generated_crawler_config_keeps_the_registry_key(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "ENABLE_CANDIDATE_V2": "true",
                    "ENABLE_ASIA_SOURCE_AWESOME_VPN": "true",
                },
            ),
            patch.object(build_crawler_config, "add_rotating_clashfree_feed"),
        ):
            config = build_crawler_config.build_config()
        source = next(
            item for item in config["domains"] if item.get("candidate_source") == "awesome-vpn"
        )
        self.assertTrue(source["enable"])
        self.assertEqual(source["candidate_source_role"], "fixed")
        process_text = Path("subscribe/process.py").read_text(encoding="utf-8")
        self.assertIn('candidate_source = utils.trim(site.get("candidate_source", ""))', process_text)
        self.assertIn("candidate_source=candidate_source", process_text)

    def test_generated_config_marks_only_stable_sources_fixed(self) -> None:
        def add_rotation(subscriptions: list[str]) -> None:
            subscriptions.append(
                "https://raw.githubusercontent.com/aiboboxx/clashfree/main/clash20260813.yaml"
            )

        with patch.object(
            build_crawler_config,
            "add_rotating_clashfree_feed",
            side_effect=add_rotation,
        ):
            config = build_crawler_config.build_config()

        domains = {item["name"]: item for item in config["domains"]}
        self.assertEqual(
            domains["community-aggregators"]["candidate_source_role"], "fixed"
        )
        self.assertEqual(
            domains["community-rotating-clashfree"]["candidate_source_role"],
            "dynamic",
        )
        self.assertTrue(
            all(
                domains[spec["name"]]["candidate_source_role"] == "fixed"
                for spec in build_crawler_config.ASIA_SOURCE_SPECS
            )
        )
        self.assertEqual(
            config["crawl"]["config"]["candidate_source_role"], "dynamic"
        )

    def test_task_dedup_keeps_registered_source_policy(self) -> None:
        tasks = [
            TaskConfig(name="plain", bin_name="subconverter", sub="https://example.invalid/sub"),
            TaskConfig(
                name="registered",
                bin_name="subconverter",
                sub="https://example.invalid/sub",
                candidate_source="awesome-vpn",
                candidate_source_role="fixed",
            ),
        ]
        result = dedup_task(tasks)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].candidate_source, "awesome-vpn")
        self.assertEqual(result[0].candidate_source_role, "fixed")

    def test_production_policy_fails_closed_when_flag_is_off(self) -> None:
        with self.assertRaisesRegex(AsiaSourceError, "feature flag is disabled"):
            enforce_registered_source_policy(
                "awesome-vpn",
                [proxy("JP", 1)],
                environment={
                    "ENABLE_CANDIDATE_V2": "true",
                },
            )

    def test_production_policy_cannot_bypass_candidate_v2(self) -> None:
        with self.assertRaisesRegex(AsiaSourceError, "candidate snapshot V2 is disabled"):
            enforce_registered_source_policy(
                "awesome-vpn",
                [proxy("JP", 1)],
                environment={"ENABLE_ASIA_SOURCE_AWESOME_VPN": "true"},
            )

    def test_collection_policy_does_not_require_identity_secret(self) -> None:
        environment = {
            "ENABLE_CANDIDATE_V2": "true",
            "ENABLE_ASIA_SOURCE_AWESOME_VPN": "true",
        }
        with patch(
            "scripts.asia_source_registry.fetch_source_revision",
            return_value={"commit_sha": "a" * 40, "updated_at": "2026-08-11T01:00:00Z"},
        ):
            result = enforce_registered_source_policy(
                "awesome-vpn",
                [proxy("JP", 1)],
                environment=environment,
                now="2026-08-11T02:00:00Z",
            )
        self.assertEqual(len(result.selected), 1)

    def test_runtime_source_failure_returns_empty_for_c1_last_good(self) -> None:
        airport = MagicMock()
        airport.ref = "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml"
        airport.get_subscribe.return_value = ("", "")
        airport.parse.return_value = [proxy("JP", 1)]
        task = TaskConfig(
            name="asia-awesome-vpn",
            bin_name="subconverter",
            sub=airport.ref,
            candidate_source="awesome-vpn",
        )
        with (
            patch.object(workflow_module, "AirPort", return_value=airport),
            patch(
                "scripts.asia_source_registry.enforce_registered_source_policy",
                side_effect=AsiaSourceError("rate limited"),
            ),
        ):
            self.assertEqual(workflow_module.execute(task), [])

    def test_candidate_source_recovers_after_a_temporary_failure(self) -> None:
        source = SimpleNamespace(
            name="asia-awesome-vpn",
            sub="https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        stable_source = SimpleNamespace(
            name="stable-source",
            sub="https://raw.githubusercontent.com/example/stable/master/clash.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        source_node = proxy("JP", 1)
        stable_node = proxy("KR", 2, port=18002)

        def snapshot(previous, run_at: str, source_items: list[dict], outcome: str | None):
            source_events, source_records = provenance_for_task(
                source,
                source_items,
                observed_at=run_at,
                outcome=outcome,
            )
            stable_events, stable_records = provenance_for_task(
                stable_source,
                [stable_node],
                observed_at=run_at,
            )
            profile = [stable_node, *source_items]
            identity_input = prepare_candidate_identity_input(
                yaml.safe_dump({"proxies": profile}, allow_unicode=True).encode(),
                {
                    "sources": source_events + stable_events,
                    "records": source_records + stable_records,
                },
                run_at=run_at,
                mode="collect",
                main_sha=("a" if previous is None else "b") * 40,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="confirmed_absent" if previous is None else "present",
                previous_profile=yaml.safe_load(previous.profile_bytes) if previous else None,
                previous_profile_bytes=previous.profile_bytes if previous else None,
                previous_status=previous.status if previous else None,
                previous_metadata=previous.metadata if previous else None,
                resolver=lambda host, port: ["8.8.8.8"],
            )
            return build_candidate_snapshot(identity_input, settings=IDENTITY)

        initial = snapshot(None, "2026-08-11T00:00:00Z", [source_node], None)
        failed = snapshot(initial, "2026-08-11T01:00:00Z", [], "timeout")
        recovered = snapshot(failed, "2026-08-11T02:00:00Z", [source_node], None)
        source_id = safe_source_descriptor(
            source.sub,
            task_name=source.name,
            publish_derivatives=True,
        )["source_id"]
        self.assertEqual(failed.metadata["sources"][source_id]["health_state"], "using_last_good")
        self.assertEqual(recovered.metadata["sources"][source_id]["health_state"], "recovered")
        self.assertEqual(failed.metadata["sources"][source_id]["consecutive_failures"], 1)
        self.assertEqual(recovered.metadata["sources"][source_id]["consecutive_failures"], 0)
        self.assertEqual(
            failed.metadata["sources"][source_id]["last_success_content_sha256"],
            initial.metadata["sources"][source_id]["last_success_content_sha256"],
        )
        self.assertEqual(
            recovered.metadata["sources"][source_id]["last_success_region_counts"]["JP"],
            1,
        )


class SourceLimitTests(unittest.TestCase):
    def test_limits_are_balanced_and_input_order_independent(self) -> None:
        items = []
        counter = 0
        for region in REGION_ORDER:
            for _ in range(110):
                counter += 1
                items.append(proxy(region, counter))

        first = select_registered_source_candidates(
            "awesome-vpn",
            items,
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )
        second = select_registered_source_candidates(
            "awesome-vpn",
            reversed(items),
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )

        self.assertEqual(len(first.selected), SOURCE_MAX_CANDIDATES)
        self.assertEqual(first.selected, second.selected)
        self.assertTrue(
            all(value <= REGION_MAX_CANDIDATES for value in first.report["selected_region_counts"].values())
        )
        self.assertEqual(set(first.report["selected_region_counts"].values()), {60})

    def test_audit_identity_key_does_not_change_production_selection(self) -> None:
        items = [proxy(region, index) for index, region in enumerate(REGION_ORDER * 80, 1)]
        audit = select_registered_source_candidates(
            "awesome-vpn",
            items,
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )
        production = select_registered_source_candidates(
            "awesome-vpn",
            reversed(items),
            checked_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(audit.selected, production.selected)

    def test_same_endpoint_keeps_at_most_three_variants(self) -> None:
        items = [proxy("JP", index, port=443, password=f"variant-{index}") for index in range(8)]
        result = select_registered_source_candidates(
            "awesome-vpn",
            items,
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(len(result.selected), ENDPOINT_MAX_VARIANTS)
        self.assertEqual(result.report["drop_reasons"]["endpoint_limit"], 5)

    def test_exact_duplicates_do_not_inflate_source_gain(self) -> None:
        original = proxy("KR", 1)
        renamed = {**original, "name": "Korea renamed"}
        result = select_registered_source_candidates(
            "awesome-vpn",
            [original, renamed],
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(result.report["exact_unique_count"], 1)
        self.assertEqual(result.report["drop_reasons"]["exact_duplicate"], 1)

    def test_private_and_unlabelled_endpoints_are_rejected(self) -> None:
        result = select_registered_source_candidates(
            "awesome-vpn",
            [
                proxy("HK", 1, server="127.0.0.1"),
                {**proxy("JP", 2), "name": "United States"},
            ],
            settings=IDENTITY,
            checked_at="2026-08-11T00:00:00Z",
        )
        self.assertEqual(result.selected, ())
        self.assertEqual(result.report["drop_reasons"]["unsafe_endpoint"], 1)
        self.assertEqual(result.report["drop_reasons"]["non_target_region"], 1)

    def test_transient_dns_infrastructure_failure_fails_the_source_evaluation(self) -> None:
        def resolver(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_AGAIN, "try again")

        with self.assertRaisesRegex(EndpointResolutionInfrastructureError, "DNS infrastructure"):
            select_registered_source_candidates(
                "awesome-vpn",
                [proxy("JP", 1, server="transient.example")],
                settings=IDENTITY,
                resolver=resolver,
                checked_at="2026-08-11T00:00:00Z",
            )


class SourceGateTests(unittest.TestCase):
    def test_confirmed_missing_success_is_included_as_acceptable_quorum(self) -> None:
        _, quorum, gate = evaluate_candidate_publish_gate(
            candidate_count=10,
            protected_asia_count=5,
            region_counts={"HK": 1, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 5},
            sources={
                "healthy": {
                    "source_kind": "fixed",
                    "configured_this_run": True,
                    "last_event": "success",
                    "health_state": "healthy",
                },
                "gone": {
                    "source_kind": "fixed",
                    "configured_this_run": True,
                    "last_event": "success",
                    "health_state": "confirmed_missing",
                },
            },
            previous={
                "candidate_count": 10,
                "protected_asia_count": 5,
                "region_hint_counts": {
                    "HK": 1,
                    "JP": 1,
                    "KR": 1,
                    "SG": 1,
                    "TW": 1,
                    "unknown": 5,
                },
            },
        )
        self.assertTrue(gate["passed"])
        self.assertEqual(quorum["eligible"], 2)
        self.assertEqual(quorum["healthy_or_last_good"], 2)

    def test_fresh_two_region_source_with_five_new_endpoints_passes(self) -> None:
        source = [
            proxy("JP", 1, port=20001),
            proxy("JP", 2, port=20002),
            proxy("JP", 3, port=20003),
            proxy("KR", 4, port=20004),
            proxy("KR", 5, port=20005),
            proxy("KR", 6, port=20006),
        ]
        current = [{**proxy("HK", 20, port=21000), "name": "US existing"}]
        report = evaluate_source_gain(
            "awesome-vpn",
            source,
            current,
            source_updated_at="2026-08-11T01:00:00Z",
            evaluated_at="2026-08-11T02:00:00Z",
            settings=IDENTITY,
        )
        self.assertTrue(report["gate"]["passed"])
        self.assertEqual(report["counts"]["new_unique_endpoint_count"], 6)
        self.assertEqual(report["counts"]["new_regions"], ["JP", "KR"])

    def test_stale_high_overlap_source_fails_with_explicit_reasons(self) -> None:
        source = [proxy("JP", index, port=22000 + index) for index in range(1, 7)]
        current = [copy.deepcopy(item) for item in source]
        report = evaluate_source_gain(
            "awesome-vpn",
            source,
            current,
            source_updated_at="2026-08-01T00:00:00Z",
            evaluated_at="2026-08-11T00:00:00Z",
            settings=IDENTITY,
        )
        self.assertFalse(report["gate"]["passed"])
        self.assertIn("source_not_fresh", report["gate"]["reasons"])
        self.assertIn("endpoint_overlap_above_80_percent", report["gate"]["reasons"])

    def test_capacity_uses_c2_constants_and_fails_closed_at_5000(self) -> None:
        below = estimate_gmgn_capacity(4999)
        limit = estimate_gmgn_capacity(5000)
        self.assertTrue(below["below_candidate_hard_limit"])
        self.assertFalse(limit["below_candidate_hard_limit"])
        self.assertEqual(below["rounds"], 20)
        self.assertEqual(below["minimum_observation_window_seconds"], 900.0)
        self.assertEqual(below["largest_shard_count"], 1250)
        self.assertEqual(below["worst_batches_per_round"], 79)
        self.assertEqual(below["delay_attempt_upper_seconds"], 4.0)
        self.assertEqual(below["controller_selection_timeout_seconds"], 1.0)
        self.assertEqual(below["measurement_upper_seconds"], 6320.0)
        self.assertEqual(below["region_lookup_upper_seconds"], 7500.0)
        self.assertEqual(below["direct_probe_upper_seconds"], 300.0)
        self.assertEqual(below["controller_health_upper_seconds"], 60.0)
        self.assertEqual(below["estimated_upper_seconds"], 14325.0)
        self.assertEqual(below["runtime_budget_seconds"], 15000)
        self.assertTrue(below["within_runtime_budget"])

    def test_candidate_snapshot_rejects_a_pool_over_the_versioned_budget(self) -> None:
        item = proxy("JP", 1)
        profile_bytes = yaml.safe_dump({"proxies": [item]}, allow_unicode=True).encode()
        task = SimpleNamespace(
            name="asia-awesome-vpn",
            sub="https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        sources, records = provenance_for_task(
            task,
            [item],
            observed_at="2026-08-11T00:00:00Z",
        )
        with patch(
            "scripts.candidate_snapshot.estimate_gmgn_capacity",
            return_value={"below_candidate_hard_limit": False, "within_runtime_budget": True},
        ):
            with self.assertRaisesRegex(CandidateSnapshotError, "capacity budget"):
                prepare_candidate_identity_input(
                    profile_bytes,
                    {"sources": sources, "records": records},
                    run_at="2026-08-11T00:00:00Z",
                    mode="collect",
                    main_sha="a" * 40,
                    profile_url="https://example.invalid/clash.yaml",
                    candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                    previous_state="confirmed_absent",
                    resolver=lambda host, port: ["8.8.8.8"],
                )

    def test_final_snapshot_rechecks_capacity_after_last_good_merge(self) -> None:
        item = proxy("JP", 1)
        current_item = proxy("KR", 2, port=19002)
        source = SimpleNamespace(
            name="asia-awesome-vpn",
            sub="https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/clash.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        current_source = SimpleNamespace(
            name="current-source",
            sub="https://raw.githubusercontent.com/example/current/master/clash.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        initial_sources, initial_records = provenance_for_task(
            source,
            [item],
            observed_at="2026-08-11T00:00:00Z",
        )
        initial_input = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": [item]}, allow_unicode=True).encode(),
            {"sources": initial_sources, "records": initial_records},
            run_at="2026-08-11T00:00:00Z",
            mode="collect",
            main_sha="a" * 40,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
            resolver=lambda host, port: ["8.8.8.8"],
        )
        initial = build_candidate_snapshot(initial_input, settings=IDENTITY)
        failed_sources, failed_records = provenance_for_task(
            source,
            [],
            observed_at="2026-08-11T01:00:00Z",
            outcome="timeout",
        )
        current_sources, current_records = provenance_for_task(
            current_source,
            [current_item],
            observed_at="2026-08-11T01:00:00Z",
        )
        with patch(
            "scripts.candidate_snapshot.estimate_gmgn_capacity",
            side_effect=[
                {"below_candidate_hard_limit": True, "within_runtime_budget": True},
                {"below_candidate_hard_limit": False, "within_runtime_budget": True},
            ],
        ):
            retry_input = prepare_candidate_identity_input(
                yaml.safe_dump({"proxies": [current_item]}, allow_unicode=True).encode(),
                {
                    "sources": failed_sources + current_sources,
                    "records": failed_records + current_records,
                },
                run_at="2026-08-11T01:00:00Z",
                mode="collect",
                main_sha="b" * 40,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="present",
                previous_profile=yaml.safe_load(initial.profile_bytes),
                previous_profile_bytes=initial.profile_bytes,
                previous_status=initial.status,
                previous_metadata=initial.metadata,
                resolver=lambda host, port: ["8.8.8.8"],
            )
            with self.assertRaisesRegex(CandidateSnapshotError, "capacity budget"):
                build_candidate_snapshot(retry_input, settings=IDENTITY)


class EvaluatorContractTests(unittest.TestCase):
    def test_evaluator_uses_a_dedicated_nonproduction_identity_key(self) -> None:
        settings = evaluation_identity_settings(
            {
                "ASIA_SOURCE_EVAL_HMAC_KEY": "audit-only",
                "ASIA_SOURCE_EVAL_KEY_VERSION": "audit-v1",
                "ASIA_SOURCE_EVAL_EPOCH": "audit-epoch-v1",
                "GMGN_IDENTITY_HMAC_KEY": "must-not-be-used",
            }
        )
        self.assertEqual(settings.key, b"audit-only")
        self.assertEqual(settings.identity_key_version, "audit-v1")

    def test_v2_sidecars_are_bound_without_exposing_the_production_key(self) -> None:
        current = {**proxy("HK", 90, port=26090), "name": "US existing"}
        current_profile_bytes = yaml.safe_dump(
            {"proxies": [current]}, allow_unicode=True, sort_keys=False
        ).encode()
        public_ids = compute_public_ids(
            current,
            key=IDENTITY.key,
            identity_key_version=IDENTITY.identity_key_version,
            identity_epoch=IDENTITY.identity_epoch,
        )
        metadata = {
            "kind": CANDIDATE_METADATA_KIND,
            "schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
            "snapshot_id": "candidate_test",
            "profile_sha256": hashlib.sha256(current_profile_bytes).hexdigest(),
            "identity_key_version": "production-key-v1",
            "identity_epoch": "production-epoch-v1",
            "candidate_count": 1,
            "candidates": {
                public_ids["candidate_id"]: {
                    "endpoint_id": public_ids["endpoint_id"],
                    "server_id": public_ids["server_id"],
                }
            },
        }
        metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
        status = {
            "kind": CANDIDATE_STATUS_KIND,
            "schema_version": CANDIDATE_STATUS_SCHEMA_VERSION,
            "profile_sha256": hashlib.sha256(current_profile_bytes).hexdigest(),
            "candidate_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            "candidate_metadata_schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
            "candidate_count": 1,
            "candidate_metadata_count": 1,
            "snapshot_id": "candidate_test",
            "identity_key_version": "production-key-v1",
            "identity_epoch": "production-epoch-v1",
        }
        source_profile = {
            "proxies": [
                proxy("JP", index, port=27000 + index) for index in range(1, 4)
            ]
            + [proxy("KR", index, port=28000 + index) for index in range(4, 7)]
        }
        report = build_report(
            source_key="awesome-vpn",
            source_profile_bytes=yaml.safe_dump(source_profile).encode(),
            current_profile_bytes=current_profile_bytes,
            current_status_bytes=json.dumps(status).encode(),
            current_metadata_bytes=metadata_bytes,
            source_revision={"commit_sha": "b" * 40, "updated_at": "2026-08-11T01:00:00Z"},
            evaluated_at="2026-08-11T02:00:00Z",
            settings=IDENTITY,
            allow_legacy_current=False,
        )
        self.assertEqual(report["current_snapshot"]["contract"], "candidate-v2")
        self.assertEqual(report["current_snapshot"]["identity_key_version"], "production-key-v1")

    def test_v2_sidecars_reject_wrong_kind_or_unsupported_schema(self) -> None:
        current = proxy("HK", 92, port=26092)
        current_profile_bytes = yaml.safe_dump(
            {"proxies": [current]}, allow_unicode=True, sort_keys=False
        ).encode()
        public_ids = compute_public_ids(
            current,
            key=IDENTITY.key,
            identity_key_version=IDENTITY.identity_key_version,
            identity_epoch=IDENTITY.identity_epoch,
        )
        base_metadata = {
            "kind": CANDIDATE_METADATA_KIND,
            "schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
            "snapshot_id": "candidate_test",
            "profile_sha256": hashlib.sha256(current_profile_bytes).hexdigest(),
            "identity_key_version": "production-key-v1",
            "identity_epoch": "production-epoch-v1",
            "candidate_count": 1,
            "candidates": {
                public_ids["candidate_id"]: {
                    "endpoint_id": public_ids["endpoint_id"],
                    "server_id": public_ids["server_id"],
                }
            },
        }
        source_profile_bytes = yaml.safe_dump({"proxies": []}).encode()
        common = {
            "source_key": "awesome-vpn",
            "source_profile_bytes": source_profile_bytes,
            "current_profile_bytes": current_profile_bytes,
            "source_revision": {
                "commit_sha": "e" * 40,
                "updated_at": "2026-08-11T01:00:00Z",
            },
            "evaluated_at": "2026-08-11T02:00:00Z",
            "settings": IDENTITY,
            "allow_legacy_current": False,
        }

        cases = (
            ("status kind", {"status_kind": "not-candidate-status"}, "status contract"),
            (
                "status schema",
                {"status_schema": CANDIDATE_STATUS_SCHEMA_VERSION + 1},
                "status contract",
            ),
            ("metadata kind", {"metadata_kind": "not-candidate-metadata"}, "metadata contract"),
            (
                "metadata schema",
                {
                    "metadata_schema": CANDIDATE_METADATA_SCHEMA_VERSION + 1,
                    "binding_schema": CANDIDATE_METADATA_SCHEMA_VERSION + 1,
                },
                "metadata contract",
            ),
        )
        for label, changes, expected_error in cases:
            with self.subTest(case=label):
                metadata = copy.deepcopy(base_metadata)
                metadata["kind"] = changes.get("metadata_kind", CANDIDATE_METADATA_KIND)
                metadata["schema_version"] = changes.get(
                    "metadata_schema", CANDIDATE_METADATA_SCHEMA_VERSION
                )
                metadata_bytes = json.dumps(metadata, sort_keys=True).encode()
                status = {
                    "kind": changes.get("status_kind", CANDIDATE_STATUS_KIND),
                    "schema_version": changes.get(
                        "status_schema", CANDIDATE_STATUS_SCHEMA_VERSION
                    ),
                    "profile_sha256": hashlib.sha256(current_profile_bytes).hexdigest(),
                    "candidate_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
                    "candidate_metadata_schema_version": changes.get(
                        "binding_schema", CANDIDATE_METADATA_SCHEMA_VERSION
                    ),
                    "candidate_count": 1,
                    "candidate_metadata_count": 1,
                    "snapshot_id": "candidate_test",
                    "identity_key_version": "production-key-v1",
                    "identity_epoch": "production-epoch-v1",
                }
                with self.assertRaisesRegex(EvaluationError, expected_error):
                    build_report(
                        **common,
                        current_status_bytes=json.dumps(status).encode(),
                        current_metadata_bytes=metadata_bytes,
                    )

    def test_report_is_aggregate_only_and_accepts_legacy_current_explicitly(self) -> None:
        source_profile = {
            "proxies": [proxy("JP", index, port=23000 + index) for index in range(1, 4)]
            + [proxy("KR", index, port=24000 + index) for index in range(4, 7)]
        }
        current_profile = {
            "proxies": [{**proxy("HK", 9, port=25009), "name": "US existing"}]
        }
        source_bytes = yaml.safe_dump(
            source_profile, allow_unicode=True, sort_keys=False
        ).encode()
        current_bytes = yaml.safe_dump(
            current_profile, allow_unicode=True, sort_keys=False
        ).encode()
        status_bytes = json.dumps({
            "run_at": "2026-08-11T00:00:00Z",
            "mode": "collect",
            "alive_check": "true",
            "proxy_count": 1,
            "profile_url": "https://example.invalid/clash.yaml",
            "profile_sha256": hashlib.sha256(current_bytes).hexdigest(),
            "main_sha": "c" * 40,
        }).encode()
        report = build_report(
            source_key="awesome-vpn",
            source_profile_bytes=source_bytes,
            current_profile_bytes=current_bytes,
            current_status_bytes=status_bytes,
            current_metadata_bytes=None,
            source_revision={
                "commit_sha": "a" * 40,
                "updated_at": "2026-08-11T01:00:00Z",
            },
            evaluated_at="2026-08-11T02:00:00Z",
            settings=IDENTITY,
            allow_legacy_current=True,
        )
        serialized = json.dumps(report, ensure_ascii=False)
        self.assertTrue(report["gate"]["passed"])
        self.assertNotIn("secret-JP", serialized)
        self.assertNotIn("8.8.8.8", serialized)
        self.assertEqual(report["current_snapshot"]["contract"], "legacy-profile-status")

    def test_legacy_opt_in_rejects_hash_only_or_v2_looking_status(self) -> None:
        source_profile = {
            "proxies": [proxy("JP", index, port=29000 + index) for index in range(1, 4)]
            + [proxy("KR", index, port=30000 + index) for index in range(4, 7)]
        }
        current_profile = {
            "proxies": [{**proxy("HK", 91, port=31091), "name": "US existing"}]
        }
        source_bytes = yaml.safe_dump(
            source_profile, allow_unicode=True, sort_keys=False
        ).encode()
        current_bytes = yaml.safe_dump(
            current_profile, allow_unicode=True, sort_keys=False
        ).encode()
        profile_sha = hashlib.sha256(current_bytes).hexdigest()
        common = {
            "source_key": "awesome-vpn",
            "source_profile_bytes": source_bytes,
            "current_profile_bytes": current_bytes,
            "current_metadata_bytes": None,
            "source_revision": {
                "commit_sha": "d" * 40,
                "updated_at": "2026-08-11T01:00:00Z",
            },
            "evaluated_at": "2026-08-11T02:00:00Z",
            "settings": IDENTITY,
            "allow_legacy_current": True,
        }

        for status in (
            {"profile_sha256": profile_sha},
            {
                "kind": CANDIDATE_STATUS_KIND,
                "schema_version": CANDIDATE_STATUS_SCHEMA_VERSION,
                "profile_sha256": profile_sha,
                "candidate_metadata_sha256": "0" * 64,
            },
        ):
            with self.subTest(status=status), self.assertRaisesRegex(
                EvaluationError,
                "neither complete candidate V2 nor valid legacy V1",
            ):
                build_report(
                    **common,
                    current_status_bytes=json.dumps(status).encode(),
                )

    def test_audit_output_cannot_escape_dedicated_directory(self) -> None:
        with self.assertRaises(EvaluationError):
            _audit_output_dir(Path(r"D:\xiangmu\linshi\not-the-source-task"))


if __name__ == "__main__":
    unittest.main()
