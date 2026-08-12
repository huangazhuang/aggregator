from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

from scripts.candidate_snapshot import (
    CandidateSnapshotError,
    build_candidate_snapshot,
    evaluate_candidate_publish_gate,
    prepare_candidate_identity_input,
    validate_candidate_snapshot,
    validate_legacy_candidate_baseline,
    write_candidate_snapshot,
)
from scripts.candidate_sources import (
    EndpointSafetyError,
    provenance_for_task,
    safe_source_descriptor,
    validate_proxy_endpoint,
)
from scripts.proxy_identity import IdentitySettings


IDENTITY = IdentitySettings(
    key=b"candidate-snapshot-unit-test-key",
    identity_key_version="candidate-test-key-v1",
    identity_epoch="identity-v1",
)
RUN0 = "2026-08-01T00:00:00Z"
MAIN_SHA = "a" * 40


def public_resolver(_host: str, _port: int) -> list[str]:
    return ["8.8.8.8", "2001:4860:4860::8888"]


def proxy(name: str, server: str, password: str) -> dict:
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": 443,
        "cipher": "aes-128-gcm",
        "password": password,
    }


def task(name: str, source: str) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        sub=source,
        domain="",
        publish_derivatives=True,
    )


def staging(
    profile_proxies: list[dict],
    task_items: list[tuple[SimpleNamespace, list[dict], str | None]],
    *,
    run_at: str,
    previous=None,
) -> dict:
    sources: list[dict] = []
    records: list[dict] = []
    for source_task, proxies, outcome in task_items:
        source_items, proxy_items = provenance_for_task(
            source_task,
            proxies,
            observed_at=run_at,
            outcome=outcome,
        )
        sources.extend(source_items)
        records.extend(proxy_items)
    previous_state = "present" if previous is not None else "confirmed_absent"
    return prepare_candidate_identity_input(
        yaml.safe_dump({"proxies": profile_proxies}, allow_unicode=True, sort_keys=False).encode(),
        {"sources": sources, "records": records},
        run_at=run_at,
        mode="collect",
        main_sha=MAIN_SHA,
        profile_url="https://example.invalid/clash.yaml",
        candidate_metadata_url="https://example.invalid/candidate-metadata.json",
        previous_state=previous_state,
        previous_profile=yaml.safe_load(previous.profile_bytes) if previous else None,
        previous_status=previous.status if previous else None,
        previous_metadata=previous.metadata if previous else None,
        resolver=public_resolver,
    )


def legacy_profile_bytes(nodes: list[dict], groups: list[dict] | None = None) -> bytes:
    profile = {"proxies": nodes}
    if groups is not None:
        profile["proxy-groups"] = groups
    return yaml.safe_dump(profile, allow_unicode=True, sort_keys=False).encode("utf-8")


def legacy_status(profile_bytes: bytes, *, protected_asia_count: int | None = None) -> dict:
    value = {
        "run_at": RUN0,
        "mode": "collect",
        "alive_check": "true",
        "proxy_count": len(yaml.safe_load(profile_bytes)["proxies"]),
        "profile_url": "https://example.invalid/clash.yaml",
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "main_sha": MAIN_SHA,
    }
    if protected_asia_count is not None:
        value["protected_asia_count"] = protected_asia_count
    return value


class CandidateEndpointSafetyTests(unittest.TestCase):
    def test_rejects_literal_and_resolved_private_endpoints(self) -> None:
        for server in (
            "127.0.0.1",
            "10.0.0.1",
            "100.100.100.200",
            "169.254.169.254",
            "168.63.129.16",
            "::1",
            "fd00:ec2::254",
        ):
            with self.subTest(server=server), self.assertRaises(EndpointSafetyError):
                validate_proxy_endpoint(proxy("private", server, "fake"))
        with self.assertRaises(EndpointSafetyError):
            validate_proxy_endpoint(
                proxy("rebind", "public.example", "fake"),
                resolver=lambda _host, _port: ["8.8.8.8", "169.254.169.254"],
            )

    def test_accepts_only_when_every_dns_answer_is_public(self) -> None:
        result = validate_proxy_endpoint(
            proxy("public", "public.example", "fake"),
            resolver=public_resolver,
            checked_at=RUN0,
        )
        self.assertEqual(result["policy_version"], "endpoint-safety-v1")
        self.assertEqual(result["resolved_address_count"], 2)


class CandidateProvenanceSnapshotTests(unittest.TestCase):
    def test_exact_duplicate_merges_all_sources_and_asia_evidence(self) -> None:
        ordinary = proxy("ordinary alias", "node.example", "fake-secret-alpha")
        asia = {**ordinary, "name": "NRT Asia alias"}
        source_a = task("community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml")
        source_b = task("asia-jp", "https://raw.githubusercontent.com/acme/asia/main/jp.yaml")

        first_input = staging(
            [ordinary, asia],
            [(source_a, [ordinary], None), (source_b, [asia], None)],
            run_at=RUN0,
        )
        second_input = staging(
            [asia, ordinary],
            [(source_b, [asia], None), (source_a, [ordinary], None)],
            run_at=RUN0,
        )
        first = build_candidate_snapshot(first_input, settings=IDENTITY)
        second = build_candidate_snapshot(second_input, settings=IDENTITY)

        self.assertEqual(first.profile_bytes, second.profile_bytes)
        self.assertEqual(first.metadata, second.metadata)
        self.assertEqual(first.status, second.status)
        self.assertEqual(len(first.ordered_candidates), 1)
        metadata = first.ordered_candidates[0].metadata
        self.assertEqual(metadata["aliases"], ["NRT Asia alias", "ordinary alias"])
        self.assertEqual(len(metadata["source_ids"]), 2)
        self.assertEqual(metadata["region_hints"], ["JP"])
        self.assertTrue(metadata["protected_asia"])
        self.assertEqual(metadata["github_check_state"], "bypassed_asia")
        public_json = json.dumps({"status": first.status, "metadata": first.metadata})
        self.assertNotIn("fake-secret-alpha", public_json)
        self.assertNotIn("fingerprint", public_json)
        self.assertNotIn("raw.githubusercontent.com", public_json)

    def test_validator_rejects_hash_mismatch_and_orphan_metadata(self) -> None:
        node = proxy("node", "node.example", "fake-secret")
        source = task("community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml")
        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        bad_status = copy.deepcopy(snapshot.status)
        bad_status["profile_sha256"] = "0" * 64
        with self.assertRaises(CandidateSnapshotError):
            validate_candidate_snapshot(
                snapshot.profile_bytes,
                bad_status,
                snapshot.metadata,
                settings=IDENTITY,
            )

        orphan = copy.deepcopy(snapshot.metadata)
        candidate_id = next(iter(orphan["candidates"]))
        orphan["candidates"]["c1_" + "0" * 24] = copy.deepcopy(orphan["candidates"][candidate_id])
        bad_status = copy.deepcopy(snapshot.status)
        bad_status["candidate_metadata_sha256"] = __import__("hashlib").sha256(
            (json.dumps(orphan, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        bad_status["candidate_metadata_count"] += 1
        with self.assertRaises(CandidateSnapshotError):
            validate_candidate_snapshot(
                snapshot.profile_bytes,
                bad_status,
                orphan,
                settings=IDENTITY,
            )

        forged_gate = copy.deepcopy(snapshot.status)
        forged_gate["publish_gate"]["reasons"] = ["forged"]
        with self.assertRaises(CandidateSnapshotError):
            validate_candidate_snapshot(
                snapshot.profile_bytes,
                forged_gate,
                snapshot.metadata,
                settings=IDENTITY,
            )

    def test_writes_json_and_yaml_that_round_trip_in_task_temp(self) -> None:
        node = proxy("node", "node.example", "fake-secret")
        source = task("community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml")
        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        with tempfile.TemporaryDirectory(dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None) as directory:
            write_candidate_snapshot(directory, snapshot)
            root = Path(directory)
            self.assertIsInstance(yaml.safe_load((root / "clash.yaml").read_bytes()), dict)
            self.assertEqual(json.loads((root / "status.json").read_text()), snapshot.status)
            self.assertEqual(json.loads((root / "candidate-metadata.json").read_text()), snapshot.metadata)

    def test_proxy_credentials_cannot_be_repeated_as_public_aliases(self) -> None:
        node = proxy("fake-secret", "node.example", "fake-secret")
        source = task("community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml")
        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )

        metadata = snapshot.ordered_candidates[0].metadata
        self.assertEqual(metadata["aliases"], [])
        self.assertNotIn("fake-secret", json.dumps(snapshot.metadata))


class CandidateLegacyBootstrapTests(unittest.TestCase):
    def test_valid_legacy_profile_is_a_counts_only_retention_baseline(self) -> None:
        old_jp = proxy("JP legacy", "old-jp.example", "old-secret")
        old_global = proxy("legacy global", "old-global.example", "old-global-secret")
        old_bytes = legacy_profile_bytes(
            [old_jp, old_global],
            [{"name": "legacy-select", "type": "select", "proxies": ["JP legacy", "DIRECT"]}],
        )
        baseline = validate_legacy_candidate_baseline(
            old_bytes,
            legacy_status(old_bytes, protected_asia_count=1),
        )
        self.assertEqual(baseline["state"], "legacy_v1")
        self.assertEqual(baseline["candidate_count"], 2)
        self.assertEqual(baseline["protected_asia_count"], 1)
        self.assertEqual(baseline["region_hint_counts"]["JP"], 1)
        self.assertEqual(baseline["profile_sha256"], hashlib.sha256(old_bytes).hexdigest())

        new_jp = proxy("JP current", "new-jp.example", "new-secret")
        new_global = proxy("current global", "new-global.example", "new-global-secret")
        source = task("current", "https://raw.githubusercontent.com/acme/current/main/sub.yaml")
        sources, records = provenance_for_task(
            source,
            [new_jp, new_global],
            observed_at="2026-08-02T00:00:00Z",
        )
        identity_input = prepare_candidate_identity_input(
            legacy_profile_bytes([new_jp, new_global]),
            {"sources": sources, "records": records},
            run_at="2026-08-02T00:00:00Z",
            mode="collect",
            main_sha="b" * 40,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="legacy_v1",
            previous_status=legacy_status(old_bytes, protected_asia_count=1),
            previous_profile_bytes=old_bytes,
            resolver=public_resolver,
        )
        self.assertIsNone(identity_input["previous_profile"])
        self.assertIsNone(identity_input["previous_status"])
        self.assertIsNone(identity_input["previous_metadata"])
        self.assertEqual(identity_input["previous_baseline"], baseline)
        self.assertNotIn("old-secret", json.dumps(identity_input))
        snapshot = build_candidate_snapshot(identity_input, settings=IDENTITY)

        self.assertEqual(
            snapshot.status["previous"],
            {name: baseline[name] for name in ("state", "snapshot_id", "candidate_count", "protected_asia_count", "region_hint_counts")},
        )
        self.assertEqual(snapshot.status["changes"]["candidate_count"], 0)
        aliases = [alias for entry in snapshot.ordered_candidates for alias in entry.metadata["aliases"]]
        self.assertNotIn("JP legacy", aliases)
        self.assertNotIn("legacy global", aliases)
        self.assertTrue(all(entry.metadata["first_seen_at"] == "2026-08-02T00:00:00Z" for entry in snapshot.ordered_candidates))
        self.assertTrue(all(item["health_state"] == "healthy" for item in snapshot.metadata["sources"].values()))

    def test_legacy_status_without_asia_count_recomputes_regions(self) -> None:
        nodes = [
            proxy("KR legacy", "kr.example", "secret-kr"),
            proxy("plain", "plain.example", "secret-plain"),
        ]
        profile_bytes = legacy_profile_bytes(nodes)
        baseline = validate_legacy_candidate_baseline(profile_bytes, legacy_status(profile_bytes))
        self.assertEqual(baseline["protected_asia_count"], 1)
        self.assertEqual(baseline["region_hint_counts"]["KR"], 1)
        self.assertEqual(baseline["region_hint_counts"]["unknown"], 1)

    def test_legacy_prepare_does_not_resolve_old_endpoints(self) -> None:
        old_nodes = [
            proxy(f"JP legacy {index}", f"old-{index}.invalid", f"old-secret-{index}")
            for index in range(64)
        ]
        old_bytes = legacy_profile_bytes(old_nodes)
        current = proxy("JP current", "current.example", "current-secret")
        source = task("current", "https://raw.githubusercontent.com/acme/current/main/sub.yaml")
        sources, records = provenance_for_task(source, [current], observed_at=RUN0)
        resolved: list[str] = []

        def resolver(host: str, _port: int) -> list[str]:
            resolved.append(host)
            if host.startswith("old-"):
                raise AssertionError("legacy endpoint was unexpectedly resolved")
            return ["8.8.8.8"]

        identity_input = prepare_candidate_identity_input(
            legacy_profile_bytes([current]),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="legacy_v1",
            previous_status=legacy_status(old_bytes, protected_asia_count=64),
            previous_profile_bytes=old_bytes,
            resolver=resolver,
        )

        self.assertEqual(set(resolved), {"current.example"})
        self.assertNotIn("proxies", identity_input["previous_baseline"])
        self.assertNotIn("old-secret", json.dumps(identity_input))

    def test_legacy_baseline_summary_tampering_fails_closed(self) -> None:
        old = proxy("JP legacy", "old.example", "old-secret")
        old_bytes = legacy_profile_bytes([old])
        current = proxy("JP current", "current.example", "current-secret")
        source = task("current", "https://raw.githubusercontent.com/acme/current/main/sub.yaml")
        sources, records = provenance_for_task(source, [current], observed_at=RUN0)
        identity_input = prepare_candidate_identity_input(
            legacy_profile_bytes([current]),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="legacy_v1",
            previous_status=legacy_status(old_bytes, protected_asia_count=1),
            previous_profile_bytes=old_bytes,
            resolver=public_resolver,
        )

        tampered_count = copy.deepcopy(identity_input)
        tampered_count["previous_baseline"]["candidate_count"] = 2
        with self.assertRaisesRegex(CandidateSnapshotError, "region counts are inconsistent|binding mismatch"):
            build_candidate_snapshot(tampered_count, settings=IDENTITY)

        tampered_hash = copy.deepcopy(identity_input)
        tampered_hash["previous_baseline"]["profile_sha256"] = "0" * 64
        with self.assertRaisesRegex(CandidateSnapshotError, "binding mismatch"):
            build_candidate_snapshot(tampered_hash, settings=IDENTITY)

    def test_legacy_baseline_rejects_hash_count_proxy_and_group_corruption(self) -> None:
        node = proxy("JP legacy", "jp.example", "secret-jp")
        good_bytes = legacy_profile_bytes([node])
        cases: list[tuple[bytes, dict, str]] = []

        bad_hash = legacy_status(good_bytes, protected_asia_count=1)
        bad_hash["profile_sha256"] = "0" * 64
        cases.append((good_bytes, bad_hash, "hash mismatch"))

        bad_count = legacy_status(good_bytes, protected_asia_count=1)
        bad_count["proxy_count"] = 2
        cases.append((good_bytes, bad_count, "count mismatch"))

        unknown_status = dict(
            legacy_status(good_bytes, protected_asia_count=1),
            unexpected_contract_marker=True,
        )
        cases.append((good_bytes, unknown_status, "fields are unsupported"))

        duplicate_bytes = legacy_profile_bytes([node, dict(node)])
        cases.append((duplicate_bytes, legacy_status(duplicate_bytes, protected_asia_count=2), "invalid or duplicate"))

        invalid_proxy = dict(node)
        invalid_proxy["port"] = 0
        invalid_bytes = legacy_profile_bytes([invalid_proxy])
        cases.append((invalid_bytes, legacy_status(invalid_bytes, protected_asia_count=1), "proxy"))

        duplicate_groups = legacy_profile_bytes(
            [node],
            [
                {"name": "select", "type": "select", "proxies": ["JP legacy"]},
                {"name": "select", "type": "select", "proxies": ["DIRECT"]},
            ],
        )
        cases.append((duplicate_groups, legacy_status(duplicate_groups, protected_asia_count=1), "group names"))

        dangling = legacy_profile_bytes(
            [node],
            [{"name": "select", "type": "select", "proxies": ["missing"]}],
        )
        cases.append((dangling, legacy_status(dangling, protected_asia_count=1), "dangling"))

        for profile_bytes, status, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(CandidateSnapshotError, message):
                validate_legacy_candidate_baseline(profile_bytes, status)

    def test_legacy_state_rejects_v2_or_mixed_previous_artifacts(self) -> None:
        node = proxy("JP legacy", "jp.example", "secret-jp")
        profile_bytes = legacy_profile_bytes([node])
        source = task("current", "https://raw.githubusercontent.com/acme/current/main/sub.yaml")
        sources, records = provenance_for_task(source, [node], observed_at=RUN0)
        status = legacy_status(profile_bytes, protected_asia_count=1)

        v2_looking = dict(status, kind="github-candidate-status")
        with self.assertRaisesRegex(CandidateSnapshotError, "fields are unsupported"):
            prepare_candidate_identity_input(
                profile_bytes,
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="legacy_v1",
                previous_status=v2_looking,
                previous_profile_bytes=profile_bytes,
                resolver=public_resolver,
            )

        with self.assertRaisesRegex(CandidateSnapshotError, "artifacts are inconsistent"):
            prepare_candidate_identity_input(
                profile_bytes,
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="legacy_v1",
                previous_status=status,
                previous_metadata={"kind": "github-candidate-metadata"},
                previous_profile_bytes=profile_bytes,
                resolver=public_resolver,
            )

        with self.assertRaisesRegex(CandidateSnapshotError, "incomplete"):
            prepare_candidate_identity_input(
                profile_bytes,
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="present",
                previous_profile=yaml.safe_load(profile_bytes),
                previous_status=status,
                previous_metadata=None,
                resolver=public_resolver,
            )


class CandidateSourceHealthTests(unittest.TestCase):
    def test_downstream_filtering_is_not_mistaken_for_source_missing(self) -> None:
        source = task("source", "https://raw.githubusercontent.com/acme/source/main/sub.yaml")
        nodes = [proxy(f"node-{index}", f"node-{index}.example", f"secret-{index}") for index in range(5)]
        initial = build_candidate_snapshot(
            staging(nodes, [(source, nodes, None)], run_at=RUN0),
            settings=IDENTITY,
        )

        current = build_candidate_snapshot(
            staging(
                nodes[1:],
                [(source, nodes, None)],
                run_at="2026-08-02T00:00:00Z",
                previous=initial,
            ),
            settings=IDENTITY,
        )

        self.assertEqual(len(current.ordered_candidates), 4)
        source_id = safe_source_descriptor(
            source.sub,
            task_name=source.name,
            publish_derivatives=True,
        )["source_id"]
        self.assertEqual(current.metadata["sources"][source_id]["health_state"], "healthy")
        self.assertEqual(current.metadata["sources"][source_id]["missing_candidates"], {})

    def test_failure_uses_fresh_last_good_and_three_successful_misses_remove(self) -> None:
        source_a = task("source-a", "https://raw.githubusercontent.com/acme/a/main/sub.yaml")
        source_b = task("source-b", "https://raw.githubusercontent.com/acme/b/main/sub.yaml")
        node_a = proxy("global-a", "a.example", "secret-a")
        node_b = proxy("global-b", "b.example", "secret-b")
        node_c = proxy("global-c", "c.example", "secret-c")
        initial = build_candidate_snapshot(
            staging(
                [node_a, node_b, node_c],
                [(source_a, [node_a], None), (source_b, [node_b, node_c], None)],
                run_at=RUN0,
            ),
            settings=IDENTITY,
        )

        failed = build_candidate_snapshot(
            staging(
                [node_b, node_c],
                [(source_a, [], "timeout"), (source_b, [node_b, node_c], None)],
                run_at="2026-08-02T00:00:00Z",
                previous=initial,
            ),
            settings=IDENTITY,
        )
        self.assertEqual(len(failed.ordered_candidates), 3)
        source_a_id = safe_source_descriptor(
            source_a.sub,
            task_name=source_a.name,
            publish_derivatives=True,
        )["source_id"]
        self.assertEqual(failed.metadata["sources"][source_a_id]["health_state"], "using_last_good")

        previous = initial
        for run_at in (
            "2026-08-03T00:00:00Z",
            "2026-08-03T06:00:00Z",
            "2026-08-03T12:00:00Z",
        ):
            previous = build_candidate_snapshot(
                staging(
                    [node_b, node_c],
                    [(source_a, [], "success"), (source_b, [node_b, node_c], None)],
                    run_at=run_at,
                    previous=previous,
                ),
                settings=IDENTITY,
            )
        self.assertEqual(len(previous.ordered_candidates), 2)
        source_state = previous.metadata["sources"][source_a_id]
        self.assertEqual(source_state["health_state"], "confirmed_missing")
        missing = next(iter(source_state["missing_candidates"].values()))
        self.assertEqual(missing["confirmations"], 3)
        self.assertTrue(missing["confirmed_missing"])


class CandidatePublishGateTests(unittest.TestCase):
    def _previous(self) -> dict:
        return {
            "state": "present",
            "snapshot_id": "candidate_" + "1" * 24,
            "candidate_count": 100,
            "protected_asia_count": 10,
            "region_hint_counts": {"HK": 2, "JP": 2, "KR": 2, "SG": 2, "TW": 2, "unknown": 90},
        }

    def _sources(self, healthy: int) -> dict:
        return {
            f"source-{index}": {"visibility": "public", "health_state": "healthy" if index < healthy else "observing_failure"}
            for index in range(5)
        }

    def test_exact_60_70_50_and_80_percent_boundaries_pass(self) -> None:
        _, _, gate = evaluate_candidate_publish_gate(
            candidate_count=60,
            protected_asia_count=7,
            region_counts={"HK": 1, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 55},
            sources=self._sources(4),
            previous=self._previous(),
        )
        self.assertTrue(gate["passed"])

    def test_below_each_boundary_fails_closed(self) -> None:
        _, _, gate = evaluate_candidate_publish_gate(
            candidate_count=59,
            protected_asia_count=6,
            region_counts={"HK": 0, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 55},
            sources=self._sources(3),
            previous=self._previous(),
        )
        self.assertFalse(gate["passed"])
        self.assertIn("candidate_retention_below_60", gate["reasons"])
        self.assertIn("asia_retention_below_70", gate["reasons"])
        self.assertIn("region_HK_retention_below_50", gate["reasons"])
        self.assertIn("region_HK_dropped_to_zero", gate["reasons"])
        self.assertIn("source_quorum_below_80", gate["reasons"])

if __name__ == "__main__":
    unittest.main()
