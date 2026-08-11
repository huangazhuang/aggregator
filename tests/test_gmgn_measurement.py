import copy
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from collections import defaultdict
from types import SimpleNamespace

from scripts.gmgn_measurement import (
    ERROR_CATEGORIES,
    MINIMUM_OBSERVATION_WINDOW_SECONDS,
    MeasurementError,
    benchmark_recommendation,
    build_private_fragment,
    build_redacted_fragment,
    build_manifest_v3,
    candidate_ids_sha256,
    classify_error,
    normalize_outcome,
    partition_candidates,
    run_measurement_schedule,
    summarize_candidate_samples,
    summarize_control,
    write_private_fragment,
)
from scripts.gmgn_validity import (
    accepted_measurement,
    canonical_json_sha256,
    validate_redacted_fragment,
    validate_run,
)
from scripts.probe_network_guard import (
    NETWORK_GUARD_POLICY_VERSION,
    RESOLVER_POLICY_VERSION,
    build_guarded_launch,
    guard_preflight,
    resolve_and_pin_candidates,
)
from scripts.proxy_identity import candidate_id, exit_id


TEST_KEY = b"measurement-test-key"
KEY_VERSION = "test-k1"
EPOCH = "identity-v1"


def proxy(index: int) -> dict:
    return {
        "name": f"fake-{index}",
        "type": "ss",
        "server": f"node-{index}.example.test",
        "port": 10000 + index,
        "cipher": "aes-128-gcm",
        "password": f"fake-secret-{index}",
    }


def candidate(index: int) -> dict:
    value = proxy(index)
    return {
        "candidate_id": candidate_id(
            value,
            key=TEST_KEY,
            identity_key_version=KEY_VERSION,
            identity_epoch=EPOCH,
        ),
        "proxy": value,
    }


class FakeClock:
    def __init__(self) -> None:
        self.value = 1000.0
        self.lock = threading.Lock()

    def now(self) -> float:
        with self.lock:
            return self.value

    def sleep(self, seconds: float) -> None:
        with self.lock:
            self.value += seconds


def fake_snapshot(count: int = 4, *, run_at: str = "2026-08-11T00:00:00Z"):
    entries = tuple(SimpleNamespace(**candidate(index)) for index in range(count))
    snapshot_id_value = "candidate_" + "f" * 24
    metadata_sha256 = "c" * 64
    return SimpleNamespace(
        ordered_candidates=entries,
        snapshot_id=snapshot_id_value,
        main_sha="a" * 40,
        profile_sha256="b" * 64,
        metadata_sha256=metadata_sha256,
        identity_key_version=KEY_VERSION,
        identity_epoch=EPOCH,
        metadata={"schema_version": 1, "candidate_count": count},
        status={
            "snapshot_id": snapshot_id_value,
            "run_at": run_at,
            "main_sha": "a" * 40,
            "profile_sha256": "b" * 64,
            "candidate_metadata_sha256": metadata_sha256,
            "candidate_metadata_schema_version": 1,
            "candidate_metadata_count": count,
            "candidate_count": count,
            "identity_key_version": KEY_VERSION,
            "identity_epoch": EPOCH,
        },
    )


def manifest_and_shards(count: int = 4):
    return build_manifest_v3(
        fake_snapshot(count),
        run_id="gmgnv2_test_run_0001",
        created_at="2026-08-11T00:00:00Z",
        trigger_type="manual",
        attempt_id="1" * 24,
        retry_of=None,
        source_run_at="2026-08-11T00:00:00Z",
        source_sha256="d" * 64,
        canary_set=["canary-a"],
        python_version="3.12.0",
        pyyaml_version="6.0.3",
        mihomo_version="test-mihomo",
        mihomo_sha256="e" * 64,
        resolver_policy_version="gmgn-resolver-v1",
        network_guard_policy_version=NETWORK_GUARD_POLICY_VERSION,
        controller_secret_sha256s=[f"{index + 1:064x}" for index in range(4)],
    )


def zero_errors() -> dict:
    return {category: 0 for category in ERROR_CATEGORIES}


def result_summary(candidate_id_value: str, *, response_count: int = 20, span: float = 900.0) -> dict:
    within = response_count
    no_result = 20 - response_count
    errors = zero_errors()
    errors["client_timeout"] = no_result
    blocks = [within // 4] * 4
    for index in range(within - sum(blocks)):
        blocks[index] += 1
    return {
        "candidate_id": candidate_id_value,
        "attempt_count": 20,
        "response_count": response_count,
        "within_1000_count": within,
        "slow_response_count": 0,
        "no_result_count": no_result,
        "min_delay_ms": 100 if response_count else None,
        "median_delay_ms": 100.0 if response_count else None,
        "p90_delay_ms": 100.0 if response_count else None,
        "max_delay_ms": 100 if response_count else None,
        "jitter_ms": 0.0 if response_count else None,
        "first_half_within_1000_count": sum(blocks[:2]),
        "second_half_within_1000_count": sum(blocks[2:]),
        "five_round_within_1000_counts": blocks,
        "observation_span_seconds": span,
        "error_counts": errors,
    }


def valid_fragments(manifest: dict, shards: list[list[dict]], *, response_count: int = 20) -> list[dict]:
    manifest_hash = canonical_json_sha256(manifest)
    egress = exit_id(
        "8.8.8.8",
        key=TEST_KEY,
        identity_key_version=KEY_VERSION,
        identity_epoch=EPOCH,
    )
    fragments = []
    for index, shard in enumerate(shards):
        summaries = [result_summary(item["candidate_id"], response_count=response_count) for item in shard]
        round_trends = []
        for round_number in range(1, 21):
            errors = zero_errors()
            errors["client_timeout"] = len(shard) if response_count == 0 else 0
            round_trends.append(
                {
                    "round": round_number,
                    "attempt_count": len(shard),
                    "within_1000_count": len(shard) if response_count else 0,
                    "slow_response_count": 0,
                    "no_result_count": len(shard) if response_count == 0 else 0,
                    "error_counts": errors,
                }
            )
        fragments.append(
            {
                "kind": "cnb-gmgn-redacted-fragment",
                "schema_version": 3,
                "manifest_sha256": manifest_hash,
                "run_id": manifest["run_id"],
                "source_sha256": manifest["source_sha256"],
                "main_sha": manifest["main_sha"],
                "profile_sha256": manifest["profile_sha256"],
                "candidate_metadata_sha256": manifest["candidate_metadata_sha256"],
                "candidate_metadata_schema_version": manifest[
                    "candidate_metadata_schema_version"
                ],
                "candidate_metadata_count": manifest["candidate_metadata_count"],
                "identity_key_version": manifest["identity_key_version"],
                "identity_epoch": manifest["identity_epoch"],
                "request_timeout_ms": manifest["request_timeout_ms"],
                "qualified_delay_ms": manifest["qualified_delay_ms"],
                "total_rounds": manifest["total_rounds"],
                "minimum_observation_window_seconds": manifest[
                    "minimum_observation_window_seconds"
                ],
                "shard_count": manifest["shard_count"],
                "workers_per_shard": manifest["workers_per_shard"],
                "stagger_seconds": manifest["shards"][index]["stagger_seconds"],
                "validity_policy_version": manifest["validity_policy_version"],
                "scheduler_policy_version": manifest["scheduler_policy_version"],
                "canary_policy_version": manifest["canary_policy_version"],
                "canary_set_sha256": manifest["canary_set_sha256"],
                "python_version": manifest["python_version"],
                "pyyaml_version": manifest["pyyaml_version"],
                "mihomo_version": manifest["mihomo_version"],
                "mihomo_sha256": manifest["mihomo_sha256"],
                "resolver_policy_version": manifest["resolver_policy_version"],
                "network_guard_policy_version": manifest[
                    "network_guard_policy_version"
                ],
                "shard_index": index,
                "candidate_count": len(shard),
                "candidate_ids_sha256": candidate_ids_sha256(item["candidate_id"] for item in shard),
                "results": summaries,
                "round_trends": round_trends,
                "controller": {
                    "healthy_check_count": 40,
                    "unhealthy_count": 0,
                    "version": "test-mihomo",
                    "mihomo_sha256": manifest["mihomo_sha256"],
                },
                "control": {
                    "attempt_count": 20,
                    "success_count": 20,
                    "failure_count": 0,
                    "max_consecutive_failures": 0,
                    "median_delay_ms": 80.0,
                },
                "canaries": [
                    {
                        "canary_id": "canary-a",
                        "attempt_count": 20,
                        "success_count": 20,
                        "failure_count": 0,
                        "max_consecutive_failures": 0,
                        "median_delay_ms": 100.0,
                    }
                ],
                "egress": {
                    "before": {"country": "CN", "region": "Shanghai", "org": "fake", "exit_id": egress},
                    "after": {"country": "CN", "region": "Shanghai", "org": "fake", "exit_id": egress},
                },
            }
        )
    return fragments


class PartitionAndManifestTests(unittest.TestCase):
    def test_partition_is_stable_complete_and_balanced_for_required_sizes(self):
        for count in (4, 5, 2260, 5000):
            original = [candidate(index) for index in range(count)]
            reversed_input = list(reversed(copy.deepcopy(original)))
            first = partition_candidates(original)
            second = partition_candidates(reversed_input)
            first_ids = [[item["candidate_id"] for item in shard] for shard in first]
            second_ids = [[item["candidate_id"] for item in shard] for shard in second]
            self.assertEqual(first_ids, second_ids)
            flattened = [value for shard in first_ids for value in shard]
            self.assertEqual(len(flattened), count)
            self.assertEqual(len(set(flattened)), count)
            self.assertLessEqual(max(map(len, first)) - min(map(len, first)), 1)

    def test_manifest_v3_binds_identity_snapshot_runtime_and_four_shards(self):
        manifest, shards = manifest_and_shards(5)
        self.assertEqual(manifest["schema_version"], 3)
        self.assertEqual(manifest["candidate_count"], 5)
        self.assertEqual([len(shard) for shard in shards], [2, 1, 1, 1])
        self.assertEqual(manifest["shard_stagger_seconds"], [0, 15, 30, 45])
        self.assertEqual(manifest["workers_per_shard"], 16)
        self.assertEqual(
            {shard["controller_port"] for shard in manifest["shards"]},
            {19090, 19091, 19092, 19093},
        )
        self.assertEqual(
            {shard["mixed_port"] for shard in manifest["shards"]},
            {17890, 17891, 17892, 17893},
        )
        self.assertEqual(
            len({shard["controller_secret_sha256"] for shard in manifest["shards"]}),
            4,
        )

    def test_manifest_supports_small_fake_cohorts_and_rejects_stale_or_ambiguous_inputs(self):
        for count in (1, 2, 3):
            with self.subTest(count=count):
                manifest, shards = manifest_and_shards(count)
                self.assertEqual(manifest["candidate_metadata_count"], count)
                self.assertEqual(sum(len(shard) for shard in shards), count)

        with self.assertRaisesRegex(MeasurementError, "canary set"):
            build_manifest_v3(
                fake_snapshot(4, run_at="2026-08-11T12:00:00Z"),
                run_id="gmgnv2_test_run_0002",
                created_at="2026-08-11T12:00:00Z",
                trigger_type="manual",
                attempt_id="1" * 24,
                retry_of=None,
                source_run_at="2026-08-11T12:00:00Z",
                source_sha256="d" * 64,
                canary_set=["duplicate", "duplicate"],
                python_version="3.12.0",
                pyyaml_version="6.0.3",
                mihomo_version="test-mihomo",
                mihomo_sha256="e" * 64,
                resolver_policy_version=RESOLVER_POLICY_VERSION,
                network_guard_policy_version=NETWORK_GUARD_POLICY_VERSION,
                controller_secret_sha256s=[f"{index + 1:064x}" for index in range(4)],
            )
        with self.assertRaisesRegex(MeasurementError, "stale or from the future"):
            build_manifest_v3(
                fake_snapshot(4),
                run_id="gmgnv2_test_run_0003",
                created_at="2026-08-11T12:00:00Z",
                trigger_type="manual",
                attempt_id="1" * 24,
                retry_of=None,
                source_run_at="2026-08-11T00:00:00Z",
                source_sha256="d" * 64,
                canary_set=["canary-a"],
                python_version="3.12.0",
                pyyaml_version="6.0.3",
                mihomo_version="test-mihomo",
                mihomo_sha256="e" * 64,
                resolver_policy_version=RESOLVER_POLICY_VERSION,
                network_guard_policy_version=NETWORK_GUARD_POLICY_VERSION,
                controller_secret_sha256s=[f"{index + 1:064x}" for index in range(4)],
            )


class SchedulerTests(unittest.TestCase):
    def test_every_candidate_gets_exactly_twenty_terminal_samples_over_900_seconds(self):
        clock = FakeClock()
        calls = defaultdict(list)

        def attempt(item: dict, round_number: int) -> dict:
            calls[item["candidate_id"]].append(round_number)
            if round_number == 2:
                return {"error": "client timeout"}
            if round_number == 3:
                return {"delay_ms": 1001}
            if round_number == 4:
                return {"target_status": 429}
            return {"delay_ms": 1000}

        run = run_measurement_schedule(
            [candidate(0), candidate(1), candidate(2)],
            attempt,
            workers=3,
            clock=clock.now,
            sleeper=clock.sleep,
        )
        self.assertEqual(len(run.samples), 60)
        self.assertTrue(all(rounds == list(range(1, 21)) for rounds in calls.values()))
        by_candidate = defaultdict(list)
        for sample in run.samples:
            by_candidate[sample["candidate_id"]].append(sample)
        for samples in by_candidate.values():
            self.assertGreaterEqual(samples[-1]["started_at"] - samples[0]["started_at"], 900.0)
            summary = summarize_candidate_samples(samples)
            self.assertEqual(summary["attempt_count"], 20)
            self.assertEqual(summary["within_1000_count"], 17)
            self.assertEqual(summary["slow_response_count"], 1)
            self.assertEqual(summary["no_result_count"], 2)
            self.assertEqual(summary["error_counts"]["client_timeout"], 1)
            self.assertEqual(summary["error_counts"]["target_429"], 1)

    def test_candidates_can_run_concurrently_but_rounds_have_a_barrier(self):
        active = 0
        maximum = 0
        lock = threading.Lock()

        def attempt(_item: dict, _round: int) -> dict:
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.001)
            with lock:
                active -= 1
            return {"delay_ms": 10}

        run_measurement_schedule(
            [candidate(0), candidate(1), candidate(2)],
            attempt,
            workers=3,
            minimum_observation_window_seconds=0.001,
        )
        self.assertGreater(maximum, 1)

    def test_shard_stagger_does_not_replace_the_nine_hundred_second_window(self):
        clock = FakeClock()
        run = run_measurement_schedule(
            [candidate(0)],
            lambda _item, _round: {"delay_ms": 10},
            workers=1,
            clock=clock.now,
            sleeper=clock.sleep,
            stagger_seconds=45,
        )
        self.assertGreaterEqual(run.samples[0]["started_at"], 1045.0)
        self.assertGreaterEqual(
            run.samples[-1]["started_at"] - run.samples[0]["started_at"],
            MINIMUM_OBSERVATION_WINDOW_SECONDS,
        )

    def test_error_classification_is_safe_and_complete(self):
        self.assertEqual(classify_error("certificate handshake failed"), "tls")
        self.assertEqual(classify_error("no such host"), "dns")
        self.assertEqual(classify_error("proxy auth failed"), "proxy_auth")
        self.assertEqual(classify_error(target_status=403), "target_403")
        self.assertEqual(classify_error(controller_healthy=False), "controller_unhealthy")
        self.assertEqual(normalize_outcome({"delay_ms": 80, "target_status": 429}), (None, "target_429"))
        self.assertEqual(normalize_outcome({"delay_ms": 1000.01}), (1001, None))

    def test_control_summary_requires_each_round_exactly_once(self):
        samples = [
            {"round": round_number, "delay_ms": 80, "error_category": None}
            for round_number in range(1, 21)
        ]
        samples[-1]["round"] = 19
        with self.assertRaisesRegex(MeasurementError, "rounds 1 through 20"):
            summarize_control(samples)


class ValidityTests(unittest.TestCase):
    def test_high_candidate_timeout_alone_is_still_a_valid_run(self):
        manifest, shards = manifest_and_shards()
        fragments = valid_fragments(manifest, shards, response_count=0)
        result = validate_run(manifest, fragments)
        self.assertTrue(result["valid_run"], result)
        accepted = accepted_measurement(manifest, fragments)
        self.assertEqual(accepted["run_id"], manifest["run_id"])

    def test_short_window_control_canary_egress_and_incident_fail_closed(self):
        manifest, shards = manifest_and_shards()
        cases = []
        fragments = valid_fragments(manifest, shards)
        fragments[0]["results"][0]["observation_span_seconds"] = 899.999
        cases.append((fragments, "observation_window_short"))
        fragments = valid_fragments(manifest, shards)
        fragments[0]["control"]["success_count"] = 17
        fragments[0]["control"]["failure_count"] = 3
        cases.append((fragments, "control_below_threshold"))
        fragments = valid_fragments(manifest, shards)
        fragments[0]["canaries"][0]["success_count"] = 15
        fragments[0]["canaries"][0]["failure_count"] = 5
        cases.append((fragments, "canary_below_threshold"))
        fragments = valid_fragments(manifest, shards)
        fragments[0]["egress"]["after"]["country"] = "US"
        cases.append((fragments, "egress_not_cn"))
        fragments = valid_fragments(manifest, shards)
        for fragment in fragments:
            result = fragment["results"][0]
            result["response_count"] = 19
            result["within_1000_count"] = 19
            result["no_result_count"] = 1
            result["first_half_within_1000_count"] = 9
            result["five_round_within_1000_counts"][0] = 4
            result["error_counts"]["target_429"] = 1
            fragment["round_trends"][0]["within_1000_count"] = 0
            fragment["round_trends"][0]["no_result_count"] = fragment["candidate_count"]
            fragment["round_trends"][0]["error_counts"]["target_429"] = fragment["candidate_count"]
        cases.append((fragments, "target_status_round_incident"))
        for fragments, reason in cases:
            result = validate_run(manifest, fragments)
            self.assertFalse(result["valid_run"])
            self.assertIn(reason, result["reasons"])
            with self.assertRaises(MeasurementError):
                accepted_measurement(manifest, fragments)

    def test_fragment_rejects_drift_between_node_summaries_and_round_trends(self):
        manifest, shards = manifest_and_shards()
        fragment = valid_fragments(manifest, shards)[0]
        result = fragment["results"][0]
        result["within_1000_count"] = 19
        result["slow_response_count"] = 1
        result["first_half_within_1000_count"] = 9
        result["five_round_within_1000_counts"][0] = 4
        with self.assertRaisesRegex(MeasurementError, "do not conserve totals"):
            validate_redacted_fragment(manifest, fragment)

    def test_controller_and_canary_evidence_are_strictly_bound(self):
        manifest, shards = manifest_and_shards()
        fragment = valid_fragments(manifest, shards)[0]
        fragment["controller"]["healthy_check_count"] = 39
        with self.assertRaisesRegex(MeasurementError, "controller evidence"):
            validate_redacted_fragment(manifest, fragment)

        fragment = valid_fragments(manifest, shards)[0]
        fragment["canaries"][0]["canary_id"] = "different-canary"
        with self.assertRaisesRegex(MeasurementError, "canary set hash"):
            validate_redacted_fragment(manifest, fragment)

    def test_egress_region_rejects_ipv4_and_ipv6_shaped_values(self):
        manifest, shards = manifest_and_shards()
        for leaked_region in ("edge-1.2.3.4", "[2001:db8::1]"):
            fragment = valid_fragments(manifest, shards)[0]
            fragment["egress"]["before"]["region"] = leaked_region
            fragment["egress"]["after"]["region"] = leaked_region
            with self.assertRaisesRegex(MeasurementError, "IP address"):
                validate_redacted_fragment(manifest, fragment)

    def test_control_and_canary_threshold_boundaries_are_exact(self):
        manifest, shards = manifest_and_shards()
        fragments = valid_fragments(manifest, shards)
        fragments[0]["control"].update(
            {"success_count": 18, "failure_count": 2, "max_consecutive_failures": 2}
        )
        fragments[0]["canaries"][0].update(
            {"success_count": 16, "failure_count": 4, "max_consecutive_failures": 4}
        )
        fragments[1]["canaries"][0]["median_delay_ms"] = 400.0
        self.assertTrue(validate_run(manifest, fragments)["valid_run"])

        fragments = valid_fragments(manifest, shards)
        fragments[0]["control"].update(
            {"success_count": 17, "failure_count": 3, "max_consecutive_failures": 3}
        )
        self.assertIn("control_consecutive_failures", validate_run(manifest, fragments)["reasons"])

        fragments = valid_fragments(manifest, shards)
        fragments[0]["canaries"][0].update(
            {"success_count": 16, "failure_count": 4, "max_consecutive_failures": 4}
        )
        fragments[1]["canaries"][0]["median_delay_ms"] = 401.0
        self.assertIn("canary_latency_skew", validate_run(manifest, fragments)["reasons"])


class FragmentPrivacyTests(unittest.TestCase):
    def test_private_fragment_is_0600_and_public_projection_contains_no_proxy_or_ip(self):
        manifest, shards = manifest_and_shards()
        clock = FakeClock()
        scheduled = run_measurement_schedule(
            shards[0],
            lambda _item, _round: {"delay_ms": 100},
            workers=1,
            clock=clock.now,
            sleeper=clock.sleep,
            health_check=lambda _phase, _round: {"healthy": True, "version": "test-mihomo"},
            control_probe=lambda _round: {"delay_ms": 80},
            canary_probe=lambda _canary, _round: {"delay_ms": 100},
            canary_ids=["canary-a"],
            egress_probe=lambda _phase: {
                "public_ip": "8.8.8.8",
                "country": "CN",
                "region": "Shanghai",
                "org": "fake",
            },
        )
        private = build_private_fragment(
            manifest,
            shard_index=0,
            shard_candidates=shards[0],
            scheduled=scheduled,
        )
        redacted = build_redacted_fragment(
            manifest,
            private,
            exit_id_resolver=lambda public_ip: exit_id(
                public_ip,
                key=TEST_KEY,
                identity_key_version=KEY_VERSION,
                identity_epoch=EPOCH,
            ),
        )
        public_text = json.dumps(redacted, ensure_ascii=False)
        self.assertNotIn('"proxy"', public_text)
        self.assertNotIn("8.8.8.8", public_text)
        self.assertNotIn("fake-secret", public_text)
        self.assertNotIn("node-0.example.test", public_text)
        self.assertNotIn("controller_secret_sha256", public_text)
        self.assertNotIn("private_fragment_file", public_text)
        self.assertNotIn("runtime_subdir", public_text)

        task_temp = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=task_temp or None) as temp_dir:
            private_root = os.path.join(temp_dir, ".cnb-runtime", "gmgn-v2")
            target = os.path.join(private_root, "shard-0.json")
            write_private_fragment(target, private, private_root=private_root)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
            with self.assertRaises(MeasurementError):
                write_private_fragment(
                    os.path.join(temp_dir, "escaped.json"),
                    private,
                    private_root=private_root,
                )


class NetworkGuardTests(unittest.TestCase):
    def test_private_metadata_and_rebinding_addresses_are_rejected(self):
        item = candidate(0)
        with self.assertRaises(MeasurementError):
            resolve_and_pin_candidates([item], resolver=lambda _host, _port: ["169.254.169.254"])

        calls = 0

        def resolver(_host: str, _port: int):
            nonlocal calls
            calls += 1
            return ["8.8.8.8"] if calls == 1 else ["127.0.0.1"]

        def backend(pinned: dict):
            return {
                "backend": "container-deny-v1",
                "backend_version": "test",
                "policy_version": NETWORK_GUARD_POLICY_VERSION,
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
                "available": True,
                "deny_self_test_passed": True,
                "controller_isolated": True,
                "fixed_resolution_enforced": True,
                "candidate_ids_sha256": candidate_ids_sha256(sorted(pinned)),
            }

        with self.assertRaises(MeasurementError):
            guard_preflight([item], backend=backend, resolver=resolver)

    def test_missing_or_failed_guard_backend_fails_closed(self):
        item = candidate(0)

        def backend(pinned: dict):
            return {
                "backend": "missing",
                "backend_version": "",
                "policy_version": NETWORK_GUARD_POLICY_VERSION,
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
                "available": False,
                "deny_self_test_passed": False,
                "controller_isolated": False,
                "fixed_resolution_enforced": False,
                "candidate_ids_sha256": candidate_ids_sha256(sorted(pinned)),
            }

        with self.assertRaises(MeasurementError):
            guard_preflight([item], backend=backend, resolver=lambda _host, _port: ["8.8.8.8"])

    def test_all_private_address_classes_and_duplicate_candidates_fail_closed(self):
        forbidden = (
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
        )
        for address in forbidden:
            with self.subTest(address=address), self.assertRaises(MeasurementError):
                resolve_and_pin_candidates(
                    [candidate(0)], resolver=lambda _host, _port, value=address: [value]
                )
        with self.assertRaisesRegex(MeasurementError, "duplicate IDs"):
            resolve_and_pin_candidates(
                [candidate(0), candidate(0)],
                resolver=lambda _host, _port: ["8.8.8.8"],
            )

    def test_guarded_launch_requires_complete_bound_evidence(self):
        item = candidate(0)
        candidate_ids = [item["candidate_id"]]
        evidence = {
            "backend": "container-deny-v1",
            "backend_version": "test",
            "policy_version": NETWORK_GUARD_POLICY_VERSION,
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
            "available": True,
            "deny_self_test_passed": True,
            "controller_isolated": True,
            "fixed_resolution_enforced": True,
            "candidate_ids_sha256": candidate_ids_sha256(candidate_ids),
        }
        self.assertEqual(
            build_guarded_launch(["mihomo", "-f", "shard.yaml"], evidence=evidence, candidate_ids=candidate_ids),
            ["mihomo", "-f", "shard.yaml"],
        )
        evidence["backend_version"] = None
        with self.assertRaises(MeasurementError):
            build_guarded_launch(["mihomo"], evidence=evidence, candidate_ids=candidate_ids)


class BenchmarkTests(unittest.TestCase):
    def evidence(self, workers: int, wall: float) -> dict:
        return {
            "run_id": f"gmgnv2_benchmark_{workers}_{int(wall * 10):05d}",
            "workers": workers,
            "valid_run": True,
            "cohort_sha256": "a" * 64,
            "runtime_sha256": "b" * 64,
            "wall_seconds": wall,
            "throughput_attempts_per_second": 100.0,
            "candidate_no_result_rate": 0.10,
            "target_403_429_rate": 0.0,
            "controller_request_rate": 0.001,
            "controller_unhealthy_count": 0,
            "control_canary_passed": True,
            "shard_duration_skew": 0.05,
            "cpu_percent_peak": 150.0,
            "memory_bytes_peak": 1024,
        }

    def test_benchmark_keeps_16_without_two_runs_per_required_level(self):
        with self.assertRaises(MeasurementError):
            benchmark_recommendation([self.evidence(16, 100.0)])

    def test_benchmark_recommends_only_quantified_improvement(self):
        evidence = []
        for workers, wall in ((8, 130.0), (16, 100.0), (24, 95.0), (32, 85.0)):
            evidence.extend([self.evidence(workers, wall), self.evidence(workers, wall + 1)])
        self.assertEqual(benchmark_recommendation(evidence), "eligible_for_policy_change:32")

    def test_benchmark_rejects_duplicate_runs_and_unhealthy_baseline(self):
        evidence = []
        for workers, wall in ((8, 130.0), (16, 100.0), (24, 95.0), (32, 85.0)):
            evidence.extend([self.evidence(workers, wall), self.evidence(workers, wall + 1)])
        evidence[1]["run_id"] = evidence[0]["run_id"]
        with self.assertRaisesRegex(MeasurementError, "duplicate run_id"):
            benchmark_recommendation(evidence)

        evidence = []
        for workers, wall in ((8, 130.0), (16, 100.0), (24, 95.0), (32, 85.0)):
            evidence.extend([self.evidence(workers, wall), self.evidence(workers, wall + 1)])
        evidence[2]["control_canary_passed"] = False
        with self.assertRaisesRegex(MeasurementError, "baseline control"):
            benchmark_recommendation(evidence)


if __name__ == "__main__":
    unittest.main()
