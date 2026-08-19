from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import socket
import stat
import tempfile
import traceback
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from scripts.candidate_snapshot import (
    CandidateSnapshot,
    CandidateSnapshotError,
    build_candidate_snapshot,
    evaluate_candidate_publish_gate,
    prepare_candidate_identity_input,
    validate_candidate_snapshot,
    validate_legacy_candidate_baseline,
    write_candidate_snapshot,
    write_candidate_identity_input,
)
from scripts import candidate_snapshot
from scripts.candidate_sources import (
    EndpointResolutionInfrastructureError,
    EndpointSafetyError,
    provenance_for_task,
    safe_source_descriptor,
    validate_proxy_endpoint,
)
from scripts.sanitize_candidate_endpoints import (
    build_endpoint_safety_evidence,
    rebuild_candidate_profile,
)
from scripts.proxy_identity import IdentitySettings, canonical_proxy_fingerprint


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


def tuic_proxy(name: str, server: str, password: str, *, ip: str) -> dict:
    return {
        "name": name,
        "type": "tuic",
        "server": server,
        "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "password": password,
        "ip": ip,
    }


def task(name: str, source: str) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        sub=source,
        domain="",
        publish_derivatives=True,
        candidate_source_role="fixed",
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
        previous_profile_bytes=previous.profile_bytes if previous else None,
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
    def _sanitized_evidence(self, sources: list[dict], records: list[dict]):
        provenance = {"sources": sources, "records": records}
        result = rebuild_candidate_profile(provenance, resolver=public_resolver)
        sanitized_bytes = yaml.safe_dump(
            result.profile,
            allow_unicode=True,
            sort_keys=False,
        ).encode()
        evidence = build_endpoint_safety_evidence(
            result,
            profile_bytes=sanitized_bytes,
            provenance=provenance,
        )
        return result, sanitized_bytes, evidence

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
        self.assertEqual(result["policy_version"], "endpoint-safety-v2")
        self.assertEqual(result["resolved_address_count"], 2)
        tuic_result = validate_proxy_endpoint(
            tuic_proxy("TUIC public", "8.8.8.8", "fake", ip="1.1.1.1"),
            checked_at=RUN0,
        )
        self.assertEqual(tuic_result["resolved_address_count"], 1)

    def test_rejects_non_public_tuic_ip_override(self) -> None:
        for override in (
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "ff02::1",
            "2001:4860:4860::8888%eth0",
            "not-an-ip",
        ):
            candidate = tuic_proxy("TUIC override", "8.8.8.8", "fake", ip=override)
            with self.subTest(override=override), self.assertRaises(EndpointSafetyError):
                validate_proxy_endpoint(candidate)

    def test_prepare_does_not_reuse_tuic_override_safety_for_same_server(self) -> None:
        public = tuic_proxy("JP public override", "8.8.8.8", "public-secret", ip="1.1.1.1")
        private = tuic_proxy("KR private override", "8.8.8.8", "private-secret", ip="10.0.0.1")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [public, private], observed_at=RUN0)

        identity_input = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": [public, private]}, allow_unicode=True).encode(),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
        )

        self.assertEqual(len(identity_input["profile"]["proxies"]), 1)
        self.assertEqual(identity_input["profile"]["proxies"][0]["ip"], "1.1.1.1")
        self.assertEqual(len(identity_input["records"]), 1)
        self.assertEqual(len(identity_input["quarantined_records"]), 1)

    def test_distinguishes_definitive_candidate_dns_failure_from_infrastructure(self) -> None:
        def missing(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        with self.assertRaises(EndpointSafetyError):
            validate_proxy_endpoint(proxy("missing", "missing.example", "fake"), resolver=missing)

        def transient(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_AGAIN, "try again")

        with self.assertRaises(EndpointResolutionInfrastructureError):
            validate_proxy_endpoint(proxy("transient", "transient.example", "fake"), resolver=transient)

    def test_prepare_quarantines_invalid_endpoints_without_losing_source_observation(self) -> None:
        good = proxy("JP good", "good.example", "good-secret")
        missing = proxy("KR missing", "missing.example", "missing-secret")
        rebound = proxy("SG rebound", "rebound.example", "rebound-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [good, missing, rebound], observed_at=RUN0)
        calls: dict[str, int] = {}

        def resolver(host: str, _port: int) -> list[str]:
            calls[host] = calls.get(host, 0) + 1
            if host == "missing.example":
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            if host == "rebound.example":
                return ["8.8.8.8", "169.254.169.254"]
            return ["8.8.8.8"]

        identity_input = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": [good, missing, rebound]}, allow_unicode=True).encode(),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
            resolver=resolver,
        )

        self.assertEqual(identity_input["schema_version"], 5)
        self.assertEqual(len(identity_input["profile"]["proxies"]), 1)
        self.assertEqual(len(identity_input["records"]), 1)
        self.assertEqual(len(identity_input["quarantined_records"]), 2)
        self.assertTrue(
            all(set(item) == {"fingerprint", "source_id", "region_hints"} for item in identity_input["quarantined_records"])
        )
        private_handoff = json.dumps(identity_input["quarantined_records"])
        self.assertNotIn("missing.example", private_handoff)
        self.assertNotIn("missing-secret", private_handoff)
        self.assertEqual(calls, {"good.example": 1, "missing.example": 1, "rebound.example": 1})
        snapshot = build_candidate_snapshot(identity_input, settings=IDENTITY)
        self.assertEqual(snapshot.status["candidate_count"], 1)
        source_metadata = next(iter(snapshot.metadata["sources"].values()))
        self.assertEqual(source_metadata["candidate_count"], 3)
        self.assertEqual(source_metadata["last_success_candidate_count"], 3)
        self.assertEqual(source_metadata["missing_candidates"], {})
        public_text = snapshot.profile_bytes.decode("utf-8") + json.dumps(snapshot.metadata)
        self.assertNotIn("missing-secret", public_text)
        self.assertNotIn("rebound-secret", public_text)

        tampered = copy.deepcopy(identity_input)
        source_metadata_key = next(iter(item["source_id"] for item in sources))
        tampered["quarantined_records"].append(
            {
                "fingerprint": "0" * 64,
                "source_id": source_metadata_key,
                "region_hints": ["KR"],
            }
        )
        tampered["raw_count"] += 1
        with self.assertRaisesRegex(
            CandidateSnapshotError,
            "count is inconsistent|not bound to provenance|overlap",
        ):
            build_candidate_snapshot(tampered, settings=IDENTITY)

    def test_identity_input_preserves_duplicate_observations_and_counts_invalid_records(self) -> None:
        node = proxy("JP duplicate", "duplicate.example", "duplicate-secret")
        invalid = dict(node, name="invalid", port=0)
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, duplicate_records = provenance_for_task(
            source,
            [node, dict(node), invalid],
            observed_at=RUN0,
        )
        identity_input = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": [node]}, allow_unicode=True).encode(),
            {"sources": sources, "records": duplicate_records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
            resolver=public_resolver,
        )

        self.assertEqual(identity_input["raw_count"], 3)
        self.assertEqual(identity_input["valid_config_count"], 2)
        self.assertEqual(identity_input["invalid_record_count"], 1)
        self.assertEqual(len(identity_input["observed_records"]), 2)
        snapshot = build_candidate_snapshot(identity_input, settings=IDENTITY)
        self.assertEqual(snapshot.status["candidate_count"], 1)
        source_metadata = next(iter(snapshot.metadata["sources"].values()))
        self.assertEqual(source_metadata["candidate_count"], 1)

    def test_identity_input_rejects_forged_or_cross_class_observation_bindings(self) -> None:
        node = proxy("JP safe", "safe.example", "safe-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        identity_input = staging([node], [(source, [node], None)], run_at=RUN0)

        forged = copy.deepcopy(identity_input)
        forged["observed_records"][0]["fingerprint"] = "0" * 64
        with self.assertRaisesRegex(CandidateSnapshotError, "not bound to provenance"):
            build_candidate_snapshot(forged, settings=IDENTITY)

        overlapping = copy.deepcopy(identity_input)
        overlapping["quarantined_records"].append(
            copy.deepcopy(overlapping["observed_records"][0])
        )
        with self.assertRaisesRegex(CandidateSnapshotError, "overlap"):
            build_candidate_snapshot(overlapping, settings=IDENTITY)

    def test_previous_quarantine_must_belong_to_the_previous_profile(self) -> None:
        node = proxy("JP current", "current.example", "current-secret")
        source = task("source", "https://raw.githubusercontent.com/acme/source/main/sub.yaml")
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        current = staging(
            [node],
            [(source, [node], None)],
            run_at="2026-08-02T00:00:00Z",
            previous=initial,
        )
        current["previous_quarantined_fingerprints"] = ["0" * 64]
        with self.assertRaisesRegex(CandidateSnapshotError, "not bound to the previous profile"):
            build_candidate_snapshot(current, settings=IDENTITY)

    def test_prepare_fails_closed_on_transient_dns_infrastructure_error(self) -> None:
        node = proxy("JP transient", "transient.example", "transient-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [node], observed_at=RUN0)

        def resolver(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_AGAIN, "try again")

        with self.assertRaises(EndpointResolutionInfrastructureError):
            prepare_candidate_identity_input(
                yaml.safe_dump({"proxies": [node]}, allow_unicode=True).encode(),
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="confirmed_absent",
                resolver=resolver,
            )

    def test_prepare_rejects_a_profile_when_every_endpoint_is_quarantined(self) -> None:
        node = proxy("JP missing", "missing.example", "missing-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [node], observed_at=RUN0)

        def resolver(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_NONAME, "not found")

        with self.assertRaisesRegex(CandidateSnapshotError, "no safe proxies"):
            prepare_candidate_identity_input(
                yaml.safe_dump({"proxies": [node]}, allow_unicode=True).encode(),
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="confirmed_absent",
                resolver=resolver,
            )

    def test_prepare_consumes_sanitizer_evidence_without_resolving_current_nodes(self) -> None:
        first = proxy("JP first", "first.example", "first-secret")
        second = proxy("KR second", "second.example", "second-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [first, second], observed_at=RUN0)
        result, sanitized_bytes, evidence = self._sanitized_evidence(sources, records)
        retained = result.profile["proxies"][0]

        identity_input = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": [retained]}, sort_keys=False).encode(),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
            resolver=lambda host, _port: (_ for _ in ()).throw(
                AssertionError(f"unexpected current DNS: {host}")
            ),
            endpoint_safety_evidence=evidence,
            sanitized_profile_bytes=sanitized_bytes,
        )

        self.assertEqual(len(identity_input["profile"]["proxies"]), 1)
        self.assertEqual(len(identity_input["records"]), 2)

    def test_prepare_rejects_evidence_addition_and_config_change(self) -> None:
        first = proxy("JP first", "first.example", "first-secret")
        second = proxy("KR second", "second.example", "second-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        sources, records = provenance_for_task(source, [first], observed_at=RUN0)
        result, sanitized_bytes, evidence = self._sanitized_evidence(sources, records)
        common = dict(
            provenance={"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="confirmed_absent",
            endpoint_safety_evidence=evidence,
            sanitized_profile_bytes=sanitized_bytes,
        )
        for changed in (
            second,
            {**result.profile["proxies"][0], "password": "changed-secret"},
        ):
            with self.subTest(changed=changed["name"]), self.assertRaisesRegex(
                CandidateSnapshotError,
                "does not cover a candidate",
            ):
                prepare_candidate_identity_input(
                    yaml.safe_dump({"proxies": [changed]}, sort_keys=False).encode(),
                    **common,
                )

    def test_current_evidence_quarantine_cannot_be_rechecked_and_restored_from_previous(self) -> None:
        isolated = proxy("JP isolated", "isolated.example", "isolated-secret")
        retained = [
            proxy(f"JP retained {index}", f"8.8.8.{index}", f"safe-secret-{index}")
            for index in range(1, 5)
        ]
        source_current = task(
            "Asia current",
            "https://raw.githubusercontent.com/acme/current/main/sub.yaml",
        )
        source_last_good = task(
            "Asia last-good",
            "https://raw.githubusercontent.com/acme/last-good/main/sub.yaml",
        )
        initial = build_candidate_snapshot(
            staging(
                [isolated, *retained],
                [
                    (source_current, [isolated, *retained], None),
                    (source_last_good, [isolated], None),
                ],
                run_at=RUN0,
            ),
            settings=IDENTITY,
        )
        current_sources, current_records = provenance_for_task(
            source_current,
            [isolated, *retained],
            observed_at="2026-08-02T00:00:00Z",
        )
        failed_sources, failed_records = provenance_for_task(
            source_last_good,
            [],
            observed_at="2026-08-02T00:00:00Z",
            outcome="timeout",
        )
        sanitizer_calls: dict[str, int] = {}

        def sanitizer_resolver(host: str, _port: int) -> list[str]:
            sanitizer_calls[host] = sanitizer_calls.get(host, 0) + 1
            if host == "isolated.example":
                raise socket.gaierror(socket.EAI_AGAIN, "temporary target failure")
            return ["8.8.8.8"]

        combined = {
            "sources": current_sources + failed_sources,
            "records": current_records + failed_records,
        }
        sanitized = rebuild_candidate_profile(
            combined,
            resolver=sanitizer_resolver,
            sleeper=lambda _delay: None,
        )
        sanitized_bytes = yaml.safe_dump(
            sanitized.profile,
            allow_unicode=True,
            sort_keys=False,
        ).encode()
        evidence = build_endpoint_safety_evidence(
            sanitized,
            profile_bytes=sanitized_bytes,
            provenance=combined,
        )

        prepared = prepare_candidate_identity_input(
            yaml.safe_dump({"proxies": retained}, sort_keys=False).encode(),
            combined,
            run_at="2026-08-02T00:00:00Z",
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="present",
            previous_profile=yaml.safe_load(initial.profile_bytes),
            previous_profile_bytes=initial.profile_bytes,
            previous_status=initial.status,
            previous_metadata=initial.metadata,
            resolver=lambda host, _port: (_ for _ in ()).throw(
                AssertionError(f"quarantined evidence was re-resolved: {host}")
            ),
            endpoint_safety_evidence=evidence,
            sanitized_profile_bytes=sanitized_bytes,
        )

        isolated_fingerprint = canonical_proxy_fingerprint(isolated)
        self.assertIn(
            isolated_fingerprint,
            prepared["previous_quarantined_fingerprints"],
        )
        snapshot = build_candidate_snapshot(prepared, settings=IDENTITY)
        self.assertEqual(len(snapshot.ordered_candidates), 4)
        self.assertNotIn("isolated-secret", snapshot.profile_bytes.decode("utf-8"))

    def test_previous_endpoint_policy_v1_migrates_once_to_v2(self) -> None:
        node = proxy("JP migration", "migration.example", "migration-secret")
        source = task("Asia source", "https://raw.githubusercontent.com/acme/asia/main/sub.yaml")
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        previous_status = copy.deepcopy(initial.status)
        previous_metadata = copy.deepcopy(initial.metadata)
        previous_status["endpoint_safety_policy_version"] = "endpoint-safety-v1"
        previous_metadata["endpoint_safety_policy_version"] = "endpoint-safety-v1"
        for item in previous_metadata["candidates"].values():
            item["endpoint_safety_policy_version"] = "endpoint-safety-v1"
        previous_status["candidate_metadata_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    previous_metadata,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        sources, records = provenance_for_task(
            source,
            [node],
            observed_at="2026-08-02T00:00:00Z",
        )
        prepared = prepare_candidate_identity_input(
            initial.profile_bytes,
            {"sources": sources, "records": records},
            run_at="2026-08-02T00:00:00Z",
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="present",
            previous_profile=yaml.safe_load(initial.profile_bytes),
            previous_profile_bytes=initial.profile_bytes,
            previous_status=previous_status,
            previous_metadata=previous_metadata,
            resolver=public_resolver,
        )

        migrated = build_candidate_snapshot(prepared, settings=IDENTITY)
        self.assertEqual(
            migrated.status["endpoint_safety_policy_version"],
            "endpoint-safety-v2",
        )
        self.assertTrue(
            all(
                item["endpoint_safety_policy_version"] == "endpoint-safety-v2"
                for item in migrated.metadata["candidates"].values()
            )
        )

        future_status = copy.deepcopy(previous_status)
        future_metadata = copy.deepcopy(previous_metadata)
        future_status["endpoint_safety_policy_version"] = "endpoint-safety-v3"
        future_metadata["endpoint_safety_policy_version"] = "endpoint-safety-v3"
        for item in future_metadata["candidates"].values():
            item["endpoint_safety_policy_version"] = "endpoint-safety-v3"
        future_status["candidate_metadata_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    future_metadata,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        prepared["previous_status"] = future_status
        prepared["previous_metadata"] = future_metadata
        with self.assertRaisesRegex(CandidateSnapshotError, "endpoint safety policy"):
            build_candidate_snapshot(prepared, settings=IDENTITY)

    def test_previous_endpoint_drift_is_quarantined_without_invalidating_previous_snapshot(self) -> None:
        nodes = [
            proxy(f"global-{index}", f"node-{index}.example", f"secret-{index}")
            for index in range(5)
        ]
        source = task("source", "https://raw.githubusercontent.com/acme/source/main/sub.yaml")
        initial = build_candidate_snapshot(
            staging(nodes, [(source, nodes, None)], run_at=RUN0),
            settings=IDENTITY,
        )
        current_nodes = nodes[1:]
        sources, records = provenance_for_task(
            source,
            current_nodes,
            observed_at="2026-08-02T00:00:00Z",
        )

        def resolver(host: str, _port: int) -> list[str]:
            if host == "node-0.example":
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            return ["8.8.8.8"]

        identity_input = prepare_candidate_identity_input(
            yaml.safe_dump(
                {"proxies": current_nodes}, allow_unicode=True, sort_keys=False
            ).encode(),
            {"sources": sources, "records": records},
            run_at="2026-08-02T00:00:00Z",
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="present",
            previous_profile=yaml.safe_load(initial.profile_bytes),
            previous_profile_bytes=initial.profile_bytes,
            previous_status=initial.status,
            previous_metadata=initial.metadata,
            resolver=resolver,
        )

        self.assertEqual(len(identity_input["previous_quarantined_fingerprints"]), 1)
        private_quarantine = json.dumps(
            identity_input["previous_quarantined_fingerprints"]
        )
        self.assertNotIn("node-0.example", private_quarantine)
        self.assertNotIn("secret-0", private_quarantine)
        current = build_candidate_snapshot(identity_input, settings=IDENTITY)
        self.assertEqual(current.status["candidate_count"], 4)
        self.assertNotIn("node-0.example", current.profile_bytes.decode("utf-8"))


class CandidateProvenanceSnapshotTests(unittest.TestCase):
    def test_oversized_pool_is_trimmed_deterministically_with_asia_and_history(self) -> None:
        source_id = "public_" + "1" * 24
        sources = {
            source_id: {
                "source_kind": "fixed",
                "health_state": "healthy",
            }
        }

        def entry(index: int, *, region: str = "", protected: bool = False) -> tuple[str, dict]:
            candidate_id = f"c1_{index:024x}"
            metadata = {
                "source_ids": [source_id],
                "source_last_success_at": RUN0,
                "region_hints": [region] if region else [],
                "protected_asia": protected,
                "endpoint_id": f"e1_{index:024x}",
                "server_id": f"s1_{index:024x}",
            }
            return candidate_id, {"proxy": {}, "metadata": metadata}

        entries = dict(entry(index) for index in range(4996))
        protected_ids: set[str] = set()
        for offset, region in enumerate(("HK", "JP", "KR", "SG", "TW"), start=4996):
            candidate_id, value = entry(offset, region=region, protected=True)
            entries[candidate_id] = value
            protected_ids.add(candidate_id)
        low_quality_old = {f"c1_{index:024x}" for index in (4994, 4995)}
        current_ids = set(entries) - low_quality_old - {f"c1_{5000:024x}"}
        previous_ids = low_quality_old | {f"c1_{5000:024x}"}

        selected = candidate_snapshot._trim_entries_to_capacity(
            entries,
            current_ids=current_ids,
            previous_ids=previous_ids,
            sources=sources,
        )
        reversed_selected = candidate_snapshot._trim_entries_to_capacity(
            dict(reversed(list(entries.items()))),
            current_ids=current_ids,
            previous_ids=previous_ids,
            sources=sources,
        )

        self.assertEqual(len(selected), 4999)
        self.assertEqual(set(selected), set(reversed_selected))
        self.assertTrue(protected_ids.issubset(selected))
        self.assertTrue(low_quality_old.isdisjoint(selected))

    def test_build_trims_before_rendering_and_records_policy_v4(self) -> None:
        nodes = [
            proxy(f"JP node {index}", f"node-{index}.example", f"secret-{index}")
            for index in range(6)
        ]
        source = task(
            "asia",
            "https://raw.githubusercontent.com/acme/asia/main/sub.yaml",
        )
        identity_input = staging(nodes, [(source, nodes, None)], run_at=RUN0)

        with patch("scripts.candidate_snapshot._candidate_capacity_limit", return_value=4):
            snapshot = build_candidate_snapshot(identity_input, settings=IDENTITY)

        self.assertEqual(snapshot.status["candidate_count"], 4)
        self.assertEqual(snapshot.metadata["candidate_count"], 4)
        self.assertEqual(snapshot.status["policy_version"], "candidate-publish-v4")
        self.assertEqual(
            snapshot.status["publish_gate"]["policy_version"],
            "candidate-publish-v4",
        )

    def test_previous_publish_policy_v3_is_read_only_and_migrates_to_v4(self) -> None:
        node = proxy("JP stable", "stable.example", "stable-secret")
        source = task(
            "asia",
            "https://raw.githubusercontent.com/acme/asia/main/sub.yaml",
        )
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        previous_status = copy.deepcopy(initial.status)
        previous_status["policy_version"] = "candidate-publish-v3"
        previous_status["publish_gate"]["policy_version"] = "candidate-publish-v3"
        with self.assertRaisesRegex(CandidateSnapshotError, "publish gate"):
            validate_candidate_snapshot(
                initial.profile_bytes,
                previous_status,
                initial.metadata,
                settings=IDENTITY,
            )

        prepared = staging(
            [node],
            [(source, [node], None)],
            run_at="2026-08-02T00:00:00Z",
            previous=CandidateSnapshot(
                profile_bytes=initial.profile_bytes,
                status=previous_status,
                metadata=initial.metadata,
                ordered_candidates=initial.ordered_candidates,
                snapshot_id=initial.snapshot_id,
                main_sha=initial.main_sha,
                profile_sha256=initial.profile_sha256,
                metadata_sha256=initial.metadata_sha256,
                identity_key_version=initial.identity_key_version,
                identity_epoch=initial.identity_epoch,
            ),
        )
        migrated = build_candidate_snapshot(prepared, settings=IDENTITY)
        self.assertEqual(migrated.status["policy_version"], "candidate-publish-v4")

    def test_numeric_authentication_and_reality_survive_snapshot_serialization(self) -> None:
        numeric_auth = {
            "name": "JP numeric auth",
            "type": "http",
            "server": "numeric.example",
            "port": 443,
            "username": "08",
            "password": "521314",
            "tls": True,
        }
        reality = {
            "name": "KR numeric reality",
            "type": "vless",
            "server": "reality.example",
            "port": 443,
            "uuid": "12345678-1234-1234-1234-123456789abc",
            "network": "tcp",
            "tls": True,
            "reality-opts": {
                "public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "short-id": "08",
            },
        }
        source = task(
            "asia-numeric",
            "https://raw.githubusercontent.com/acme/asia/main/numeric.yaml",
        )

        snapshot = build_candidate_snapshot(
            staging(
                [numeric_auth, reality],
                [(source, [numeric_auth, reality], None)],
                run_at=RUN0,
            ),
            settings=IDENTITY,
        )

        rendered = snapshot.profile_bytes.decode("utf-8")
        self.assertIn('username: "08"', rendered)
        self.assertIn('password: "521314"', rendered)
        self.assertIn('short-id: "08"', rendered)
        parsed = yaml.safe_load(snapshot.profile_bytes)["proxies"]
        by_type = {item["type"]: item for item in parsed}
        self.assertEqual(by_type["http"]["username"], "08")
        self.assertEqual(by_type["http"]["password"], "521314")
        self.assertEqual(by_type["vless"]["reality-opts"]["short-id"], "08")

    def test_snapshot_serialization_error_is_fixed_and_suppresses_secret_context(self) -> None:
        secret = "serialization-fake-secret-521314"
        node = proxy("JP node", "node.example", "normal-password")
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )
        identity_input = staging([node], [(source, [node], None)], run_at=RUN0)

        with patch(
            "scripts.candidate_snapshot.dump_clash_yaml",
            side_effect=yaml.representer.RepresenterError(secret),
        ):
            with self.assertRaises(CandidateSnapshotError) as raised:
                build_candidate_snapshot(identity_input, settings=IDENTITY)

        self.assertEqual(str(raised.exception), "candidate profile serialization failed")
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn(secret, "".join(traceback.format_exception(raised.exception)))

    def test_candidate_cli_redacts_snapshot_serialization_error(self) -> None:
        secret = "cli-serialization-fake-secret-08"
        node = proxy("JP node", "node.example", "normal-password")
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )
        identity_input = staging([node], [(source, [node], None)], run_at=RUN0)

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            input_path = root / "identity-input.json"
            output_dir = root / "public"
            write_candidate_identity_input(input_path, identity_input)
            environment = {
                "GMGN_IDENTITY_HMAC_KEY": IDENTITY.key.decode("utf-8"),
                "GMGN_IDENTITY_KEY_VERSION": IDENTITY.identity_key_version,
                "GMGN_IDENTITY_EPOCH": IDENTITY.identity_epoch,
            }
            stderr = __import__("io").StringIO()
            with (
                patch.dict(os.environ, environment),
                patch(
                    "scripts.candidate_snapshot.dump_clash_yaml",
                    side_effect=yaml.representer.RepresenterError(secret),
                ),
                patch("sys.stderr", stderr),
            ):
                result = candidate_snapshot._run_cli(
                    ["build", "--input", str(input_path), "--output-dir", str(output_dir)]
                )

            self.assertFalse(output_dir.exists())

        self.assertEqual(result, 1)
        self.assertEqual(stderr.getvalue().strip(), "ERROR: candidate profile serialization failed")
        self.assertNotIn(secret, stderr.getvalue())

    def test_private_identity_input_is_created_with_restrictive_mode(self) -> None:
        node = proxy("JP private", "node.example", "private-secret")
        source = task(
            "community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml"
        )
        payload = staging([node], [(source, [node], None)], run_at=RUN0)

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            path = Path(directory, "identity-input.json")
            write_candidate_identity_input(path, payload)

            self.assertTrue(path.is_file())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_sorted_private_handoff_preserves_exact_previous_profile(self) -> None:
        node = proxy("JP previous", "previous.example", "previous-secret")
        source = task(
            "community", "https://raw.githubusercontent.com/acme/community/main/sub.yaml"
        )
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        identity_input = staging(
            [node],
            [(source, [node], None)],
            run_at="2026-08-02T00:00:00Z",
            previous=initial,
        )

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            path = Path(directory, "identity-input.json")
            write_candidate_identity_input(path, identity_input)
            restored = json.loads(path.read_text(encoding="utf-8"))

        self.assertNotEqual(
            list(restored["previous_profile"]),
            list(yaml.safe_load(initial.profile_bytes)),
        )
        self.assertEqual(
            base64.b64decode(restored["previous_profile_b64"], validate=True),
            initial.profile_bytes,
        )
        current = build_candidate_snapshot(restored, settings=IDENTITY)
        self.assertEqual(current.status["candidate_count"], 1)

        tampered = copy.deepcopy(restored)
        tampered["previous_profile_b64"] = base64.b64encode(
            initial.profile_bytes + b"\n"
        ).decode("ascii")
        with self.assertRaisesRegex(CandidateSnapshotError, "profile hash mismatch"):
            build_candidate_snapshot(tampered, settings=IDENTITY)

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

    def test_current_alias_without_region_keeps_previous_asia_protection(self) -> None:
        asia = proxy("JP stable", "node.example", "fake-secret-alpha")
        ordinary = {**asia, "name": "ordinary alias"}
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )
        initial = build_candidate_snapshot(
            staging([asia], [(source, [asia], None)], run_at=RUN0),
            settings=IDENTITY,
        )

        current = build_candidate_snapshot(
            staging(
                [ordinary],
                [(source, [ordinary], None)],
                run_at="2026-08-02T00:00:00Z",
                previous=initial,
            ),
            settings=IDENTITY,
        )

        self.assertEqual(len(current.ordered_candidates), 1)
        metadata = current.ordered_candidates[0].metadata
        self.assertEqual(metadata["region_hints"], ["JP"])
        self.assertTrue(metadata["protected_asia"])
        self.assertEqual(metadata["github_check_state"], "bypassed_asia")

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

    def test_anytls_tls_fingerprint_survives_full_snapshot_and_keeps_distinct_ids(self) -> None:
        first = {
            "name": "JP AnyTLS Chrome",
            "type": "anytls",
            "server": "anytls.example",
            "port": 443,
            "password": "anytls-secret",
            "fingerprint": "chrome",
        }
        second = {**first, "name": "KR AnyTLS Firefox", "fingerprint": "firefox"}
        source = task(
            "asia-anytls",
            "https://raw.githubusercontent.com/acme/asia/main/anytls.yaml",
        )

        snapshot = build_candidate_snapshot(
            staging([first, second], [(source, [first, second], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        validated = validate_candidate_snapshot(
            snapshot.profile_bytes,
            snapshot.status,
            snapshot.metadata,
            settings=IDENTITY,
        )
        parsed = yaml.safe_load(snapshot.profile_bytes)

        self.assertEqual(len(validated.ordered_candidates), 2)
        self.assertEqual(len(snapshot.metadata["candidates"]), 2)
        self.assertEqual(
            {item["fingerprint"] for item in parsed["proxies"]},
            {"chrome", "firefox"},
        )

    def test_tampered_historical_alias_is_rejected_before_it_can_be_reused(self) -> None:
        node = proxy("JP safe", "node.example", "top-secret")
        node["plugin"] = "obfs"
        node["plugin-opts"] = {"mode": "tls", "host": "front.example"}
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        candidate_id_value = next(iter(initial.metadata["candidates"]))
        previous_metadata = copy.deepcopy(initial.metadata)
        previous_metadata["candidates"][candidate_id_value]["aliases"] = [
            "JP runner 10.0.0.5"
        ]
        previous_status = copy.deepcopy(initial.status)
        previous_status["candidate_metadata_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    previous_metadata,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        identity_input = prepare_candidate_identity_input(
                initial.profile_bytes,
                {
                    "sources": provenance_for_task(source, [node], observed_at="2026-08-02T00:00:00Z")[0],
                    "records": provenance_for_task(source, [node], observed_at="2026-08-02T00:00:00Z")[1],
                },
                run_at="2026-08-02T00:00:00Z",
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="present",
                previous_profile=yaml.safe_load(initial.profile_bytes),
                previous_profile_bytes=initial.profile_bytes,
                previous_status=previous_status,
                previous_metadata=previous_metadata,
                resolver=public_resolver,
            )
        with self.assertRaises(CandidateSnapshotError):
            build_candidate_snapshot(identity_input, settings=IDENTITY)

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

    def test_nested_proxy_credentials_cannot_be_repeated_as_public_aliases(self) -> None:
        node = proxy("JP nested-secret-987654", "node.example", "top-secret")
        node["plugin"] = "shadow-tls"
        node["plugin-opts"] = {
            "host": "front.example",
            "password": "nested-secret-987654",
        }
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )

        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )

        metadata = snapshot.ordered_candidates[0].metadata
        self.assertEqual(metadata["aliases"], [])
        self.assertNotIn("nested-secret-987654", json.dumps(snapshot.metadata))

    def test_case_varied_xhttp_and_vless_encryption_secrets_use_structured_names(self) -> None:
        encryption_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        node = {
            "name": f"JP {encryption_key.lower()}",
            "type": "vless",
            "server": "node.example",
            "port": 443,
            "uuid": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
            "encryption": f"mlkem768x25519plus.native.1rtt.{encryption_key}",
            "network": "xhttp",
            "xhttp-opts": {
                "path": "/",
                "x-padding-key": "padding-secret-123456",
                "session-key": "session-secret-123456",
                "seq-key": "sequence-secret-123456",
                "uplink-data-key": "uplink-secret-123456",
            },
        }
        source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )

        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        parsed = yaml.safe_load(snapshot.profile_bytes)

        self.assertEqual(snapshot.ordered_candidates[0].metadata["aliases"], [])
        self.assertEqual(parsed["proxies"][0]["name"], "ASIA-KEEP JP VLESS")
        public_metadata = json.dumps(snapshot.metadata)
        for secret in (
            encryption_key.lower(),
            "padding-secret-123456",
            "session-secret-123456",
            "sequence-secret-123456",
            "uplink-secret-123456",
        ):
            self.assertNotIn(secret, public_metadata)

    def test_private_subscription_token_alias_is_absent_from_public_snapshot(self) -> None:
        token = "SUBSCRIPTIONTOKENABC123"
        node = proxy(f"JP {token}", "node.example", "proxy-secret")
        source = task(
            "opaque-source",
            f"https://private.example/sub?token={token}",
        )

        snapshot = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        parsed = yaml.safe_load(snapshot.profile_bytes)

        self.assertEqual(snapshot.ordered_candidates[0].metadata["aliases"], [])
        self.assertEqual(parsed["proxies"][0]["name"], "CANDIDATE SS")
        self.assertNotIn(
            token,
            json.dumps(snapshot.metadata) + snapshot.profile_bytes.decode("utf-8"),
        )

    def test_fresh_private_source_evidence_drops_historical_token_alias(self) -> None:
        token = "SUBSCRIPTIONTOKENABC123"
        node = proxy("JP safe", "node.example", "proxy-secret")
        source = task(
            "opaque-source",
            f"https://private.example/sub?token={token}",
        )
        initial = build_candidate_snapshot(
            staging([node], [(source, [node], None)], run_at=RUN0),
            settings=IDENTITY,
        )
        candidate_id_value = next(iter(initial.metadata["candidates"]))
        previous_metadata = copy.deepcopy(initial.metadata)
        previous_metadata["candidates"][candidate_id_value]["aliases"] = [
            f"JP {token}"
        ]
        previous_status = copy.deepcopy(initial.status)
        previous_status["candidate_metadata_sha256"] = hashlib.sha256(
            (
                json.dumps(
                    previous_metadata,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode()
        ).hexdigest()
        safe_previous = CandidateSnapshot(
            profile_bytes=initial.profile_bytes,
            status=previous_status,
            metadata=previous_metadata,
            ordered_candidates=initial.ordered_candidates,
            snapshot_id=initial.snapshot_id,
            main_sha=initial.main_sha,
            profile_sha256=initial.profile_sha256,
            metadata_sha256=previous_status["candidate_metadata_sha256"],
            identity_key_version=initial.identity_key_version,
            identity_epoch=initial.identity_epoch,
        )

        current = build_candidate_snapshot(
            staging(
                [node],
                [(source, [node], None)],
                run_at="2026-08-02T00:00:00Z",
                previous=safe_previous,
            ),
            settings=IDENTITY,
        )

        public = json.dumps(current.metadata) + current.profile_bytes.decode("utf-8")
        self.assertNotIn(token, public)
        self.assertEqual(current.ordered_candidates[0].metadata["aliases"], ["JP safe"])

    def test_last_good_keeps_policy_validated_alias_and_clash_name_stable(self) -> None:
        node = proxy("KR Seoul Stable", "node.example", "proxy-secret")
        source = task(
            "opaque-source",
            "https://private.example/sub?token=UNRELATEDTOKENABC123",
        )
        companion = proxy("global companion", "companion.example", "companion-secret")
        companion_source = task(
            "community",
            "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
        )
        initial = build_candidate_snapshot(
            staging(
                [node, companion],
                [
                    (source, [node], None),
                    (companion_source, [companion], None),
                ],
                run_at=RUN0,
            ),
            settings=IDENTITY,
        )

        carried = build_candidate_snapshot(
            staging(
                [companion],
                [
                    (source, [], "timeout"),
                    (companion_source, [companion], None),
                ],
                run_at="2026-08-02T00:00:00Z",
                previous=initial,
            ),
            settings=IDENTITY,
        )

        initial_names = {
            item["server"]: item["name"]
            for item in yaml.safe_load(initial.profile_bytes)["proxies"]
        }
        carried_names = {
            item["server"]: item["name"]
            for item in yaml.safe_load(carried.profile_bytes)["proxies"]
        }
        initial_name = initial_names["node.example"]
        carried_name = carried_names["node.example"]
        self.assertEqual(initial_name, "KR Seoul Stable")
        self.assertEqual(carried_name, initial_name)
        carried_entry = next(
            entry
            for entry in carried.ordered_candidates
            if entry.proxy["server"] == "node.example"
        )
        self.assertEqual(carried_entry.metadata["aliases"], ["KR Seoul Stable"])

    def test_endpoint_material_cannot_be_repeated_as_public_aliases(self) -> None:
        aliases = (
            "node.example:443",
            "backup 203.0.113.10",
            "[2001:4860:4860::8888]:443",
        )
        for index, alias in enumerate(aliases):
            with self.subTest(alias=alias):
                node = proxy(alias, "node.example", f"secret-{index}")
                source = task(
                    "community",
                    "https://raw.githubusercontent.com/acme/community/main/sub.yaml",
                )
                snapshot = build_candidate_snapshot(
                    staging([node], [(source, [node], None)], run_at=RUN0),
                    settings=IDENTITY,
                )

                metadata = snapshot.ordered_candidates[0].metadata
                self.assertEqual(metadata["aliases"], [])
                public_metadata = json.dumps(snapshot.metadata)
                self.assertNotIn("node.example", public_metadata)
                self.assertNotIn("203.0.113.10", public_metadata)
                self.assertNotIn("2001:4860:4860::8888", public_metadata)


class CandidateLegacyBootstrapTests(unittest.TestCase):
    def test_legacy_baseline_accepts_protected_asia_without_specific_region_hint(self) -> None:
        for name in ("ASIA-KEEP generic legacy", "🇰🇷 剩余流量 10 GB"):
            with self.subTest(name=name):
                old = proxy(name, "old.example", "old-secret")
                old_bytes = legacy_profile_bytes([old])
                current = proxy(name, "current.example", "current-secret")
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
                baseline = identity_input["previous_baseline"]
                self.assertEqual(baseline["protected_asia_count"], 1)
                self.assertEqual(
                    sum(baseline["region_hint_counts"][region] for region in ("HK", "JP", "KR", "SG", "TW")),
                    0,
                )
                self.assertEqual(baseline["region_hint_counts"]["unknown"], 1)

                snapshot = build_candidate_snapshot(identity_input, settings=IDENTITY)
                self.assertTrue(snapshot.status["publish_gate"]["passed"])
                self.assertEqual(snapshot.status["previous"]["protected_asia_count"], 1)

    def test_legacy_unassigned_asia_still_enforces_total_and_specific_region_floors(self) -> None:
        old_jp = proxy("JP legacy", "old-jp.example", "old-jp-secret")
        old_unassigned = proxy("ASIA-KEEP generic legacy", "old-asia.example", "old-asia-secret")
        old_global = proxy("global legacy", "old-global.example", "old-global-secret")
        old_bytes = legacy_profile_bytes([old_jp, old_unassigned, old_global])

        current_unassigned = proxy("ASIA-KEEP generic current", "current-asia.example", "current-asia-secret")
        current_global = proxy("global current", "current-global.example", "current-global-secret")
        source = task("current", "https://raw.githubusercontent.com/acme/current/main/sub.yaml")
        sources, records = provenance_for_task(
            source,
            [current_unassigned, current_global],
            observed_at=RUN0,
        )
        identity_input = prepare_candidate_identity_input(
            legacy_profile_bytes([current_unassigned, current_global]),
            {"sources": sources, "records": records},
            run_at=RUN0,
            mode="collect",
            main_sha=MAIN_SHA,
            profile_url="https://example.invalid/clash.yaml",
            candidate_metadata_url="https://example.invalid/candidate-metadata.json",
            previous_state="legacy_v1",
            previous_status=legacy_status(old_bytes, protected_asia_count=2),
            previous_profile_bytes=old_bytes,
            resolver=public_resolver,
        )

        with self.assertRaisesRegex(CandidateSnapshotError, "publish gate rejected") as raised:
            build_candidate_snapshot(identity_input, settings=IDENTITY)

        diagnostic = json.loads(
            str(raised.exception).removeprefix("candidate publish gate rejected: ")
        )
        self.assertIn("asia_retention_below_70", diagnostic["reason_codes"])
        self.assertIn("region_JP_dropped_to_zero", diagnostic["reason_codes"])
        self.assertEqual(diagnostic["candidate"], {"current": 2, "minimum": 2})
        self.assertEqual(diagnostic["protected_asia"], {"current": 1, "minimum": 2})
        serialized = json.dumps(diagnostic, sort_keys=True)
        for sensitive in (
            "old-jp.example",
            "current-asia.example",
            "old-jp-secret",
            "current-asia-secret",
            "raw.githubusercontent.com",
        ):
            self.assertNotIn(sensitive, serialized)

        baseline = identity_input["previous_baseline"]
        _, _, gate = evaluate_candidate_publish_gate(
            candidate_count=2,
            protected_asia_count=1,
            region_counts={"HK": 0, "JP": 0, "KR": 0, "SG": 0, "TW": 0, "unknown": 2},
            sources={"source": {"visibility": "public", "health_state": "healthy"}},
            previous=baseline,
        )
        self.assertFalse(gate["passed"])
        self.assertIn("asia_retention_below_70", gate["reasons"])
        self.assertIn("region_JP_dropped_to_zero", gate["reasons"])

    def test_candidate_cli_gate_rejection_is_aggregate_only_and_creates_no_output(self) -> None:
        source_id_sentinel = "public_deadbeefdeadbeefdeadbeef"
        alias_sentinel = "credential-sentinel-alias"
        token_url_sentinel = "https://private.invalid/sub?token=credential-sentinel"
        old_jp = proxy("JP old sensitive alias", "old-sensitive.example", "old-secret-521314")
        old_global = proxy("old global", "old-global.example", "old-global-secret")
        old_bytes = legacy_profile_bytes([old_jp, old_global])
        current = proxy(
            "ASIA-KEEP current sensitive alias",
            "current-sensitive.example",
            "current-secret-08",
        )
        source = task(
            "current",
            "https://raw.githubusercontent.com/acme/current/main/sub.yaml",
        )
        sources, records = provenance_for_task(source, [current], observed_at=RUN0)
        original_source_id = sources[0]["source_id"]
        sources[0]["source_id"] = source_id_sentinel
        sources[0]["alias"] = alias_sentinel
        records[0]["source_id"] = source_id_sentinel
        records[0]["alias"] = token_url_sentinel
        self.assertNotEqual(original_source_id, source_id_sentinel)
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

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            input_path = root / "identity-input.json"
            output_dir = root / "public"
            write_candidate_identity_input(input_path, identity_input)
            environment = {
                "GMGN_IDENTITY_HMAC_KEY": IDENTITY.key.decode("utf-8"),
                "GMGN_IDENTITY_KEY_VERSION": IDENTITY.identity_key_version,
                "GMGN_IDENTITY_EPOCH": IDENTITY.identity_epoch,
            }
            stderr = __import__("io").StringIO()
            with patch.dict(os.environ, environment), patch("sys.stderr", stderr):
                result = candidate_snapshot._run_cli(
                    ["build", "--input", str(input_path), "--output-dir", str(output_dir)]
                )

            self.assertEqual(result, 1)
            self.assertFalse(output_dir.exists())
            message = stderr.getvalue().strip()
            self.assertTrue(message.startswith("ERROR: candidate publish gate rejected: "))
            diagnostic = json.loads(
                message.removeprefix("ERROR: candidate publish gate rejected: ")
            )
            self.assertEqual(
                set(diagnostic),
                {"reason_codes", "candidate", "protected_asia", "regions", "source_quorum"},
            )
            self.assertIn("region_JP_dropped_to_zero", diagnostic["reason_codes"])
            for sensitive in (
                source_id_sentinel,
                alias_sentinel,
                token_url_sentinel,
                "old-sensitive.example",
                "current-sensitive.example",
                "old-secret-521314",
                "current-secret-08",
                "aes-128-gcm",
            ):
                self.assertNotIn(sensitive, message)

    def test_legacy_baseline_accepts_v1_fields_that_candidate_v2_rejects(self) -> None:
        legacy_nodes = [
            {
                "name": "legacy HTTP",
                "type": "http",
                "server": "http.example",
                "port": 443,
                "udp": True,
            },
            {
                "name": "JP legacy gRPC",
                "type": "vless",
                "server": "grpc.example",
                "port": 443,
                "uuid": "00000000-0000-4000-8000-000000000001",
                "tls": True,
                "network": "grpc",
                "grpc-opts": {
                    "grpc-service-name": "legacy",
                    "grpc-mode": "gun",
                },
            },
        ]
        profile_bytes = legacy_profile_bytes(legacy_nodes)

        baseline = validate_legacy_candidate_baseline(
            profile_bytes,
            legacy_status(profile_bytes, protected_asia_count=1),
        )

        self.assertEqual(baseline["candidate_count"], 2)
        self.assertEqual(baseline["protected_asia_count"], 1)

        source = task(
            "legacy-shaped-current",
            "https://raw.githubusercontent.com/acme/current/main/sub.yaml",
        )
        sources, records = provenance_for_task(source, legacy_nodes, observed_at=RUN0)
        with self.assertRaisesRegex(CandidateSnapshotError, "schema is unsupported"):
            prepare_candidate_identity_input(
                profile_bytes,
                {"sources": sources, "records": records},
                run_at=RUN0,
                mode="collect",
                main_sha=MAIN_SHA,
                profile_url="https://example.invalid/clash.yaml",
                candidate_metadata_url="https://example.invalid/candidate-metadata.json",
                previous_state="confirmed_absent",
                resolver=public_resolver,
            )

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
        self.assertIsNone(identity_input["previous_profile_b64"])
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

        tampered_asia = copy.deepcopy(identity_input)
        tampered_asia["previous_baseline"]["protected_asia_count"] = 0
        with self.assertRaisesRegex(CandidateSnapshotError, "Asia counts are inconsistent"):
            build_candidate_snapshot(tampered_asia, settings=IDENTITY)

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

        bad_asia_count = legacy_status(good_bytes, protected_asia_count=0)
        cases.append((good_bytes, bad_asia_count, "protected Asia count is invalid"))

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
                previous_profile_bytes=profile_bytes,
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

    def test_source_missing_last_seen_does_not_follow_other_source_observations(self) -> None:
        source_a = task("source-a", "https://raw.githubusercontent.com/acme/a/main/sub.yaml")
        source_b = task("source-b", "https://raw.githubusercontent.com/acme/b/main/sub.yaml")
        shared = proxy("shared", "shared.example", "secret")
        previous = build_candidate_snapshot(
            staging(
                [shared],
                [(source_a, [shared], None), (source_b, [shared], None)],
                run_at=RUN0,
            ),
            settings=IDENTITY,
        )

        for run_at in (
            "2026-08-02T00:00:00Z",
            "2026-08-02T06:00:00Z",
            "2026-08-02T12:00:00Z",
        ):
            previous = build_candidate_snapshot(
                staging(
                    [shared],
                    [(source_a, [], "success"), (source_b, [shared], None)],
                    run_at=run_at,
                    previous=previous,
                ),
                settings=IDENTITY,
            )

        source_a_id = safe_source_descriptor(
            source_a.sub,
            task_name=source_a.name,
            publish_derivatives=True,
        )["source_id"]
        missing = next(
            iter(previous.metadata["sources"][source_a_id]["missing_candidates"].values())
        )
        self.assertEqual(missing["last_seen_at"], RUN0)
        self.assertEqual(missing["first_missing_at"], "2026-08-02T00:00:00Z")
        self.assertEqual(missing["last_missing_at"], "2026-08-02T12:00:00Z")
        self.assertEqual(missing["confirmations"], 3)


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
            f"source-{index}": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "success" if index < healthy else "timeout",
                "health_state": "healthy" if index < healthy else "observing_failure",
            }
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

    def test_dynamic_sources_do_not_pollute_fixed_source_quorum(self) -> None:
        sources = self._sources(4)
        sources.update(
            {
                f"dynamic-{index}": {
                    "source_kind": "dynamic",
                    "configured_this_run": True,
                    "last_event": "timeout",
                    "health_state": "observing_failure",
                }
                for index in range(200)
            }
        )

        _, quorum, gate = evaluate_candidate_publish_gate(
            candidate_count=60,
            protected_asia_count=7,
            region_counts={"HK": 1, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 55},
            sources=sources,
            previous=self._previous(),
        )

        self.assertTrue(gate["passed"])
        self.assertEqual(quorum["eligible"], 5)
        self.assertEqual(quorum["healthy_or_last_good"], 4)

    def test_zero_configured_fixed_sources_fails_closed(self) -> None:
        _, quorum, gate = evaluate_candidate_publish_gate(
            candidate_count=60,
            protected_asia_count=7,
            region_counts={"HK": 1, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 55},
            sources={
                "dynamic": {
                    "source_kind": "dynamic",
                    "configured_this_run": True,
                    "last_event": "success",
                    "health_state": "healthy",
                }
            },
            previous=self._previous(),
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(quorum["eligible"], 0)
        self.assertEqual(quorum["ratio"], 0.0)
        self.assertIn("source_quorum_below_80", gate["reasons"])

    def test_quorum_accepts_success_confirmed_missing_and_last_good_only(self) -> None:
        sources = {
            "success": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "success",
                "health_state": "healthy",
            },
            "confirmed": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "success",
                "health_state": "confirmed_missing",
            },
            "last-good": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "timeout",
                "health_state": "using_last_good",
            },
            "empty": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "empty",
                "health_state": "observing_failure",
            },
            "failure": {
                "source_kind": "fixed",
                "configured_this_run": True,
                "last_event": "network_error",
                "health_state": "observing_failure",
            },
        }

        _, quorum, gate = evaluate_candidate_publish_gate(
            candidate_count=60,
            protected_asia_count=7,
            region_counts={"HK": 1, "JP": 1, "KR": 1, "SG": 1, "TW": 1, "unknown": 55},
            sources=sources,
            previous=self._previous(),
        )

        self.assertFalse(gate["passed"])
        self.assertEqual(quorum["eligible"], 5)
        self.assertEqual(quorum["healthy_or_last_good"], 3)
        self.assertEqual(quorum["ratio"], 0.6)

if __name__ == "__main__":
    unittest.main()
