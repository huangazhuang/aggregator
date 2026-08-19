from __future__ import annotations

import json
import os
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import yaml

from scripts import cnb_gmgn_v2
from scripts.gmgn_measurement import RESOLVER_POLICY_VERSION, normalize_outcome
from scripts.gmgn_processed_state import build_attempt
from scripts.publish_transaction import PreviousState


SOURCE_SHA = "1" * 64
CANDIDATE_COMMIT = "a" * 40


def auxiliary_targets() -> dict[str, dict]:
    addresses = {
        "control-gmgn-v1": "1.1.1.1",
        "canary-gstatic-v1": "8.8.4.4",
        "canary-cloudflare-v1": "1.0.0.1",
        "egress-provider-v1": "9.9.9.9",
    }
    return {
        name: {
            "server": value["server"],
            "port": value["port"],
            "addresses": [addresses[name]],
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        }
        for name, value in cnb_gmgn_v2.DIRECT_TARGETS.items()
    }


class TriggerAndPreflightTests(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    def test_full_sha_tags_are_strict_and_retry_is_explicit(self) -> None:
        normal = cnb_gmgn_v2.parse_trigger_tag(
            f"cnb-gmgn-v2-{SOURCE_SHA}-{CANDIDATE_COMMIT}"
        )
        self.assertEqual(normal["source_sha256"], SOURCE_SHA)
        self.assertEqual(normal["candidate_commit"], CANDIDATE_COMMIT)
        self.assertEqual(normal["schema_version"], 2)
        self.assertFalse(normal["retry"])
        retry = cnb_gmgn_v2.parse_trigger_tag(
            f"cnb-gmgn-v2-retry-{SOURCE_SHA}-{CANDIDATE_COMMIT}-infra-2"
        )
        self.assertTrue(retry["retry"])
        self.assertEqual(retry["retry_token"], "infra-2")
        for malformed in (
            "cnb-gmgn-v2-1234",
            f"cnb-gmgn-v2-{SOURCE_SHA}",
            f"cnb-gmgn-v2-retry-{SOURCE_SHA}-infra-2",
        ):
            with self.subTest(tag=malformed), self.assertRaisesRegex(
                cnb_gmgn_v2.CoordinatorError, "malformed"
            ):
                cnb_gmgn_v2.parse_trigger_tag(malformed)

    def test_mihomo_version_probe_uses_a_minimal_secret_free_environment(self) -> None:
        captured = {}

        def runner(command, **kwargs):
            captured["command"] = command
            captured.update(kwargs)
            return SimpleNamespace(returncode=0, stdout="Mihomo v1.19.9", stderr="")

        secrets = {
            "CNB_TOKEN": "cnb-secret",
            "GITHUB_TOKEN": "github-secret",
            "GMGN_IDENTITY_HMAC_KEY": "identity-secret",
            "GIT_ASKPASS": "askpass-secret",
        }
        with self.temporary_directory() as directory:
            binary = Path(directory) / "mihomo"
            runtime = Path(directory) / "runtime"
            with patch.dict(os.environ, secrets, clear=False):
                version = cnb_gmgn_v2._mihomo_version(
                    binary,
                    work_dir=runtime,
                    runner=runner,
                )

        self.assertEqual(version, "1.19.9")
        self.assertTrue(set(secrets).isdisjoint(captured["env"]))
        self.assertEqual(captured["stdout"], cnb_gmgn_v2.subprocess.PIPE)
        self.assertEqual(captured["stderr"], cnb_gmgn_v2.subprocess.PIPE)
        self.assertFalse(captured["check"])
        for key in ("HOME", "TEMP", "TMP", "TMPDIR"):
            self.assertEqual(captured["env"][key], str(runtime.resolve()))

    def test_candidate_fetch_hash_failure_leaves_no_staging_directory(self) -> None:
        profile = b"proxies: []\n"
        status = json.dumps(
            {
                "kind": cnb_gmgn_v2.CANDIDATE_STATUS_KIND,
                "profile_sha256": "0" * 64,
                "candidate_metadata_sha256": "0" * 64,
            }
        ).encode("utf-8")
        metadata = json.dumps({"kind": cnb_gmgn_v2.CANDIDATE_METADATA_KIND}).encode(
            "utf-8"
        )
        payloads = [status, profile, metadata]

        with self.temporary_directory() as directory:
            output = Path(directory) / "candidate-staging"
            args = Namespace(
                expected_source_sha=SOURCE_SHA,
                expected_candidate_commit=CANDIDATE_COMMIT,
                output_dir=str(output),
                status_url=f"https://example.invalid/{CANDIDATE_COMMIT}/status.json",
                profile_url=f"https://example.invalid/{CANDIDATE_COMMIT}/clash.yaml",
                metadata_url=f"https://example.invalid/{CANDIDATE_COMMIT}/candidate-metadata.json",
            )
            with (
                patch.object(cnb_gmgn_v2, "fetch_no_cache", side_effect=payloads),
                self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "manual trigger"),
            ):
                cnb_gmgn_v2._fetch_candidate(args)
            self.assertFalse(output.exists())

    def test_candidate_fetch_rejects_a_moving_or_different_revision_before_network(self) -> None:
        args = Namespace(
            expected_source_sha=SOURCE_SHA,
            expected_candidate_commit=CANDIDATE_COMMIT,
            output_dir="unused",
            status_url="https://example.invalid/clash-verge-output/status.json",
            profile_url="https://example.invalid/clash-verge-output/clash.yaml",
            metadata_url="https://example.invalid/clash-verge-output/candidate-metadata.json",
        )
        with (
            patch.object(cnb_gmgn_v2, "fetch_no_cache") as fetch,
            self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "immutable revision"),
        ):
            cnb_gmgn_v2._fetch_candidate(args)
        fetch.assert_not_called()

    def test_mihomo_runtime_uses_a_minimal_secret_free_environment(self) -> None:
        captured = {}
        process = MagicMock()

        def runner(command, **kwargs):
            captured["command"] = command
            captured.update(kwargs)
            return process

        secrets = {
            "CNB_TOKEN": "cnb-secret",
            "GITHUB_TOKEN": "github-secret",
            "GMGN_IDENTITY_HMAC_KEY": "identity-secret",
            "GIT_ASKPASS": "askpass-secret",
        }
        with self.temporary_directory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir()
            config = runtime / "mihomo-runtime.yaml"
            with patch.dict(os.environ, secrets, clear=False):
                actual = cnb_gmgn_v2._start_mihomo(
                    Path(directory) / "mihomo",
                    work_dir=runtime,
                    config=config,
                    log="private-log-handle",
                    runner=runner,
                )

        self.assertIs(actual, process)
        self.assertTrue(set(secrets).isdisjoint(captured["env"]))
        self.assertEqual(captured["stdout"], "private-log-handle")
        self.assertEqual(captured["stderr"], cnb_gmgn_v2.subprocess.STDOUT)
        for key in ("HOME", "TEMP", "TMP", "TMPDIR"):
            self.assertEqual(captured["env"][key], str(runtime.resolve()))

    def test_prepare_binds_retry_relation_without_trusting_caller_attempt_id(self) -> None:
        primary = build_attempt(SOURCE_SHA)
        retry = build_attempt(SOURCE_SHA, "infra-prepare")
        trigger = cnb_gmgn_v2.parse_trigger_tag(
            f"cnb-gmgn-v2-retry-{SOURCE_SHA}-{CANDIDATE_COMMIT}-infra-prepare"
        )
        preflight = {
            "kind": cnb_gmgn_v2.PREFLIGHT_KIND,
            "schema_version": cnb_gmgn_v2.PREFLIGHT_SCHEMA_VERSION,
            "source_sha256": SOURCE_SHA,
            "candidate_commit": CANDIDATE_COMMIT,
            "retry": True,
            "attempt_id": retry.attempt_id,
            "retry_of": primary.attempt_id,
            "retry_token_sha256": retry.retry_token_sha256,
            "decision": "retry_failed_infrastructure",
            "should_run": True,
            "observed_tip": "a" * 40,
            "processed_ref": cnb_gmgn_v2.processed_ref(SOURCE_SHA),
            "processed_tip": "b" * 40,
        }
        with self.temporary_directory() as directory:
            root = Path(directory)
            trigger_path = root / "trigger.json"
            preflight_path = root / "preflight.json"

            def write_inputs() -> None:
                trigger_path.write_text(
                    json.dumps(trigger), encoding="utf-8"
                )
                preflight_path.write_text(
                    json.dumps(preflight), encoding="utf-8"
                )

            write_inputs()
            bound = cnb_gmgn_v2._load_preflight_attempt(
                preflight_path,
                trigger_path,
                expected_source_sha256=SOURCE_SHA,
                expected_candidate_commit=CANDIDATE_COMMIT,
            )
            self.assertEqual(bound.attempt_id, retry.attempt_id)
            self.assertEqual(bound.retry_of, primary.attempt_id)
            self.assertEqual(bound.retry_token_sha256, retry.retry_token_sha256)

            preflight["schema_version"] = 1
            write_inputs()
            with self.assertRaisesRegex(
                cnb_gmgn_v2.CoordinatorError, "preflight fields|preflight contract"
            ):
                cnb_gmgn_v2._load_preflight_attempt(
                    preflight_path,
                    trigger_path,
                    expected_source_sha256=SOURCE_SHA,
                    expected_candidate_commit=CANDIDATE_COMMIT,
                )

            preflight["schema_version"] = cnb_gmgn_v2.PREFLIGHT_SCHEMA_VERSION
            trigger["schema_version"] = 1
            write_inputs()
            with self.assertRaisesRegex(
                cnb_gmgn_v2.CoordinatorError, "trigger fields|trigger contract"
            ):
                cnb_gmgn_v2._load_preflight_attempt(
                    preflight_path,
                    trigger_path,
                    expected_source_sha256=SOURCE_SHA,
                    expected_candidate_commit=CANDIDATE_COMMIT,
                )

            trigger["schema_version"] = cnb_gmgn_v2.TRIGGER_SCHEMA_VERSION

            preflight["candidate_commit"] = "b" * 40
            write_inputs()
            with self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "candidate commit"):
                cnb_gmgn_v2._load_preflight_attempt(
                    preflight_path,
                    trigger_path,
                    expected_source_sha256=SOURCE_SHA,
                    expected_candidate_commit=CANDIDATE_COMMIT,
                )

            preflight["candidate_commit"] = CANDIDATE_COMMIT
            preflight["attempt_id"] = "f" * 24
            write_inputs()
            with self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "attempt ID"):
                cnb_gmgn_v2._load_preflight_attempt(
                    preflight_path,
                    trigger_path,
                    expected_source_sha256=SOURCE_SHA,
                    expected_candidate_commit=CANDIDATE_COMMIT,
                )

            preflight["attempt_id"] = retry.attempt_id
            preflight["retry_of"] = retry.attempt_id
            write_inputs()
            with self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "retry_of"):
                cnb_gmgn_v2._load_preflight_attempt(
                    preflight_path,
                    trigger_path,
                    expected_source_sha256=SOURCE_SHA,
                    expected_candidate_commit=CANDIDATE_COMMIT,
                )

    def test_prepare_preserves_candidate_provenance_across_runtime_fixes(self) -> None:
        candidate_main_sha = "9" * 40
        snapshot = SimpleNamespace(
            snapshot_id="candidate_" + "8" * 24,
            main_sha=candidate_main_sha,
            profile_sha256=SOURCE_SHA,
            metadata_sha256="7" * 64,
            identity_key_version="gmgn-key-v1",
            identity_epoch="gmgn-epoch-v1",
            status={"run_at": "2026-08-13T10:17:11Z"},
            metadata={"sources": {}},
            ordered_candidates=[
                SimpleNamespace(
                    candidate_id="c1_" + "6" * 24,
                    proxy={"name": "candidate"},
                    metadata={"source_ids": ["source"]},
                )
            ],
        )
        attempt = SimpleNamespace(attempt_id="5" * 24, retry_of="4" * 24)
        with self.temporary_directory() as directory:
            root = Path(directory)
            profile = root / "clash.yaml"
            status = root / "status.json"
            metadata = root / "candidate-metadata.json"
            mihomo = root / "mihomo"
            profile.write_text("proxies: []\n", encoding="utf-8")
            status.write_text(
                json.dumps({"run_at": snapshot.status["run_at"]}),
                encoding="utf-8",
            )
            metadata.write_text("{}", encoding="utf-8")
            mihomo.write_bytes(b"fixed-binary")
            args = Namespace(
                profile=str(profile),
                status=str(status),
                metadata=str(metadata),
                expected_source_sha=SOURCE_SHA,
                expected_candidate_commit=CANDIDATE_COMMIT,
                mihomo=str(mihomo),
                identity_fixture=str(root / "identity-fixture.json"),
                preflight=str(root / "preflight.json"),
                trigger=str(root / "trigger.json"),
                output_dir=str(root / "prepared"),
                workers=16,
            )
            with (
                patch.object(
                    cnb_gmgn_v2.IdentitySettings,
                    "from_environment",
                    return_value=object(),
                ),
                patch.object(cnb_gmgn_v2, "verify_identity_test_vector"),
                patch.object(
                    cnb_gmgn_v2,
                    "validate_candidate_snapshot",
                    return_value=snapshot,
                ),
                patch.object(cnb_gmgn_v2, "_validate_runtime_capacity"),
                patch.object(
                    cnb_gmgn_v2,
                    "_load_preflight_attempt",
                    return_value=attempt,
                ),
                patch.object(
                    cnb_gmgn_v2,
                    "build_manifest_v3",
                    return_value=({"kind": "test-manifest"}, [[], [], [], []]),
                ),
                patch.object(cnb_gmgn_v2, "_mihomo_version", return_value="1.0.0"),
            ):
                self.assertEqual(cnb_gmgn_v2._prepare(args), 0)

            prepared = json.loads(
                (Path(args.output_dir) / "snapshot.json").read_text(encoding="utf-8")
            )
            self.assertEqual(prepared["main_sha"], candidate_main_sha)

    def test_history_accepted_source_outside_last_five_is_still_noop(self) -> None:
        bundle = SimpleNamespace(
            source_sha256="2" * 64,
            files={
                "status.json": json.dumps(
                    {"source_sha256": "2" * 64}
                ).encode("utf-8")
            },
        )
        previous = PreviousState(True, "a" * 40, bundle)
        run_index = {"entries": [{"source_sha256": str(index) * 64} for index in range(2, 7)]}
        history = {
            "recent_accepted_runs": [
                {
                    "run_id": "old-run",
                    "source_sha256": SOURCE_SHA,
                    "accepted_at": "2026-08-01T00:00:00Z",
                }
            ]
        }
        with self.temporary_directory() as directory:
            root = Path(directory)
            args = Namespace(
                source_sha=SOURCE_SHA,
                candidate_commit=CANDIDATE_COMMIT,
                remote="https://example.invalid/repo.git",
                work_dir=str(root / "work"),
                output=str(root / "decision.json"),
                noop_file=str(root / "noop"),
                retry=True,
                retry_token="infra-accepted",
            )
            with patch.object(
                cnb_gmgn_v2,
                "_remote_previous",
                return_value=(previous, history, run_index),
            ):
                self.assertEqual(cnb_gmgn_v2._preflight(args), 0)
            decision = json.loads((root / "decision.json").read_text(encoding="utf-8"))
            self.assertEqual(decision["decision"], "noop_accepted")
            self.assertFalse(decision["should_run"])
            self.assertTrue((root / "noop").is_file())

    def test_queued_primary_allows_explicit_infrastructure_retry(self) -> None:
        with self.temporary_directory() as directory:
            root = Path(directory)
            args = Namespace(
                source_sha=SOURCE_SHA,
                candidate_commit=CANDIDATE_COMMIT,
                remote="https://example.invalid/repo.git",
                work_dir=str(root / "work"),
                output=str(root / "decision.json"),
                noop_file=str(root / "noop"),
                retry=True,
                retry_token="infra-2",
            )
            commands = []

            def git_command(command, **kwargs):
                commands.append(command)
                if command[-1] == f"refs/tags/cnb-gmgn-v2-{SOURCE_SHA}":
                    return SimpleNamespace(
                        returncode=0,
                        stdout=(
                            f"{'b' * 40} refs/tags/cnb-gmgn-v2-{SOURCE_SHA}\n"
                        ),
                    )
                return SimpleNamespace(
                    returncode=0,
                    stdout="",
                )

            with patch.object(
                cnb_gmgn_v2,
                "_remote_previous",
                return_value=(PreviousState(False, None, None), None, None),
            ), patch.object(
                cnb_gmgn_v2,
                "_read_processed_state",
                return_value=(None, None),
            ), patch.object(
                cnb_gmgn_v2,
                "_git_command",
                side_effect=git_command,
            ):
                self.assertEqual(cnb_gmgn_v2._preflight(args), 0)
            decision = json.loads((root / "decision.json").read_text(encoding="utf-8"))
            self.assertEqual(decision["schema_version"], 2)
            self.assertEqual(decision["decision"], "retry_failed_infrastructure")
            self.assertTrue(decision["should_run"])
            self.assertFalse((root / "noop").exists())
            self.assertIn(
                f"refs/tags/cnb-gmgn-v2-{SOURCE_SHA}-{CANDIDATE_COMMIT}",
                commands[0],
            )
            self.assertIn(
                f"refs/tags/cnb-gmgn-v2-{SOURCE_SHA}",
                commands[1],
            )


class GuardedRuntimeTests(unittest.TestCase):
    def test_http_probe_runtime_allocates_one_isolated_listener_per_worker(self) -> None:
        slots, groups, listeners = cnb_gmgn_v2._http_probe_runtime(
            ["candidate-a", "candidate-b"],
            shard_index=2,
            workers=8,
        )

        self.assertEqual(len(slots), 8)
        self.assertEqual(
            [slot.port for slot in slots],
            list(
                range(
                    cnb_gmgn_v2.HTTP_PROBE_PORT_BASE
                    + 2 * cnb_gmgn_v2.HTTP_PROBE_PORT_STRIDE,
                    cnb_gmgn_v2.HTTP_PROBE_PORT_BASE
                    + 2 * cnb_gmgn_v2.HTTP_PROBE_PORT_STRIDE
                    + 8,
                )
            ),
        )
        self.assertEqual(
            [group["name"] for group in groups],
            [slot.group_name for slot in slots],
        )
        self.assertTrue(
            all(group["proxies"] == ["candidate-a", "candidate-b"] for group in groups)
        )
        self.assertEqual(
            [listener["proxy"] for listener in listeners],
            [slot.group_name for slot in slots],
        )
        self.assertTrue(all(listener["listen"] == "127.0.0.1" for listener in listeners))

    def test_probe_guard_allows_the_full_fixed_listener_port_budget(self) -> None:
        context = cnb_gmgn_v2._http_probe_slots(3, 16)
        ports = {
            cnb_gmgn_v2.HTTP_PROBE_PORT_BASE
            + 3 * cnb_gmgn_v2.HTTP_PROBE_PORT_STRIDE
            + offset
            for offset in range(cnb_gmgn_v2.HTTP_PROBE_PORTS_PER_SHARD)
        }
        self.assertEqual(len(ports), cnb_gmgn_v2.HTTP_PROBE_PORTS_PER_SHARD)
        self.assertEqual({slot.port for slot in context}.issubset(ports), True)

    def test_browser_http_probe_sends_fixed_browser_headers_through_its_slot(self) -> None:
        response = MagicMock()
        response.status = 200
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        slot = cnb_gmgn_v2._http_probe_slots(0, 1)[0]

        with (
            patch.object(cnb_gmgn_v2, "_controller_request") as controller_request,
            patch.object(
                cnb_gmgn_v2.urllib.request,
                "build_opener",
                return_value=opener,
            ) as build_opener,
            patch.object(cnb_gmgn_v2.time, "monotonic", side_effect=[10.0, 10.075]),
            patch.dict(os.environ, {"NO_PROXY": "gmgn.ai", "no_proxy": "gmgn.ai"}),
        ):
            outcome = cnb_gmgn_v2._browser_http_outcome(
                "127.0.0.1:19090",
                "test-secret",
                slot=slot,
                proxy_name="candidate-a",
                target_url="https://gmgn.ai/",
                timeout_ms=3000,
            )

        self.assertEqual(outcome, {"delay_ms": 75, "target_status": 200})
        controller_request.assert_called_once_with(
            "127.0.0.1:19090",
            "test-secret",
            "PUT",
            f"/proxies/{slot.group_name}",
            body={"name": "candidate-a"},
            timeout=cnb_gmgn_v2.CONTROLLER_SELECTION_TIMEOUT_SECONDS,
        )
        proxy_handler = build_opener.call_args.args[0]
        self.assertIsInstance(proxy_handler, cnb_gmgn_v2._ForcedLoopbackProxyHandler)
        self.assertEqual(
            proxy_handler.proxies,
            {
                "http": f"http://127.0.0.1:{slot.port}",
                "https": f"http://127.0.0.1:{slot.port}",
            },
        )
        request = opener.open.call_args.args[0]
        self.assertEqual(
            request.get_header("User-agent"), cnb_gmgn_v2.GMGN_BROWSER_USER_AGENT
        )
        proxy_handler.proxy_open(request, proxy_handler.proxies["https"], "https")
        self.assertEqual(request.host, f"127.0.0.1:{slot.port}")
        self.assertEqual(request._tunnel_host, "gmgn.ai")
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 3.0)

    def test_browser_http_probe_preserves_target_403_for_scoring(self) -> None:
        opener = MagicMock()
        opener.open.side_effect = cnb_gmgn_v2.urllib.error.HTTPError(
            "https://gmgn.ai/", 403, "Forbidden", {}, None
        )
        slot = cnb_gmgn_v2._http_probe_slots(0, 1)[0]

        with (
            patch.object(cnb_gmgn_v2, "_controller_request"),
            patch.object(
                cnb_gmgn_v2.urllib.request,
                "build_opener",
                return_value=opener,
            ),
            patch.object(cnb_gmgn_v2.time, "monotonic", side_effect=[20.0, 20.1]),
        ):
            outcome = cnb_gmgn_v2._browser_http_outcome(
                "127.0.0.1:19090",
                "test-secret",
                slot=slot,
                proxy_name="candidate-a",
                target_url="https://gmgn.ai/",
                timeout_ms=3000,
            )

        self.assertEqual(outcome, {"target_status": 403})
        self.assertEqual(normalize_outcome(outcome), (None, "target_403"))

    def test_browser_probe_pool_returns_a_slot_after_probe_failure(self) -> None:
        pool = cnb_gmgn_v2._BrowserProbePool(
            "127.0.0.1:19090",
            "test-secret",
            cnb_gmgn_v2._http_probe_slots(0, 1),
        )
        candidate = {"proxy": {"name": "candidate-a"}}
        with patch.object(
            cnb_gmgn_v2,
            "_browser_http_outcome",
            side_effect=[RuntimeError("boom"), {"delay_ms": 80, "target_status": 200}],
        ):
            with self.assertRaisesRegex(RuntimeError, "boom"):
                pool.probe(candidate, "https://gmgn.ai/", 3000)
            self.assertEqual(
                pool.probe(candidate, "https://gmgn.ai/", 3000),
                {"delay_ms": 80, "target_status": 200},
            )

    def test_mihomo_direct_probe_uses_the_same_delay_contract_as_candidates(self) -> None:
        target_url = "https://www.gstatic.com/generate_204"
        with patch.object(
            cnb_gmgn_v2,
            "_controller_request",
            side_effect=[
                {"delay": 87},
                {
                    "extra": {
                        target_url: {
                            "alive": True,
                            "history": [{"delay": 87}],
                        }
                    }
                },
            ],
        ) as request:
            outcome = cnb_gmgn_v2._mihomo_delay_outcome(
                "127.0.0.1:19090",
                "test-secret",
                proxy_name="DIRECT",
                target_url=target_url,
                timeout_ms=5000,
                expected_status=204,
            )

        self.assertEqual(outcome, {"delay_ms": 87, "controller_status": 200})
        self.assertEqual(request.call_count, 2)
        request.assert_any_call(
            "127.0.0.1:19090",
            "test-secret",
            "GET",
            "/proxies/DIRECT",
            timeout=cnb_gmgn_v2.CONTROLLER_HEALTH_TIMEOUT_SECONDS,
        )

    def test_mihomo_direct_probe_preserves_safe_target_error_classification(self) -> None:
        with patch.object(
            cnb_gmgn_v2,
            "_controller_request",
            side_effect=cnb_gmgn_v2.CoordinatorError(
                "unexpected target status code: 403 (controller status 400)"
            ),
        ):
            outcome = cnb_gmgn_v2._mihomo_delay_outcome(
                "127.0.0.1:19090",
                "test-secret",
                proxy_name="DIRECT",
                target_url="https://gmgn.ai/",
                timeout_ms=5000,
                expected_status=200,
            )

        self.assertEqual(normalize_outcome(outcome), (None, "target_403"))

    def test_candidate_probe_remains_strict_http_200(self) -> None:
        with patch.object(
            cnb_gmgn_v2,
            "_mihomo_delay_outcome",
            return_value={"delay_ms": 75},
        ) as probe:
            outcome = cnb_gmgn_v2._delay_attempt(
                "127.0.0.1:19090",
                "test-secret",
                {"proxy": {"name": "candidate-a"}},
                "https://gmgn.ai/",
                3000,
            )

        self.assertEqual(outcome, {"delay_ms": 75})
        probe.assert_called_once_with(
            "127.0.0.1:19090",
            "test-secret",
            proxy_name="candidate-a",
            target_url="https://gmgn.ai/",
            timeout_ms=3000,
            expected_status=200,
        )

    def test_control_probe_can_request_any_complete_http_response(self) -> None:
        with patch.object(
            cnb_gmgn_v2,
            "_mihomo_delay_outcome",
            return_value={"delay_ms": 1},
        ) as probe:
            outcome = cnb_gmgn_v2._delay_attempt(
                "127.0.0.1:19090",
                "test-secret",
                {"proxy": {"name": "candidate-a"}},
                "https://gmgn.ai/",
                5000,
                expected_status="100-599",
            )

        self.assertEqual(outcome, {"delay_ms": 1})
        probe.assert_called_once_with(
            "127.0.0.1:19090",
            "test-secret",
            proxy_name="candidate-a",
            target_url="https://gmgn.ai/",
            timeout_ms=5000,
            expected_status="100-599",
        )

    def test_shard_inputs_bind_only_the_public_github_check_state(self) -> None:
        passed_id = "c1_" + "1" * 24
        bypassed_id = "c1_" + "2" * 24
        shards = [
            [{"candidate_id": passed_id, "proxy": {"name": "passed"}}],
            [{"candidate_id": bypassed_id, "proxy": {"name": "bypassed"}}],
        ]
        snapshot_candidates = [
            SimpleNamespace(
                candidate_id=passed_id,
                metadata={"github_check_state": "passed", "source_ids": ["private"]},
            ),
            SimpleNamespace(
                candidate_id=bypassed_id,
                metadata={
                    "github_check_state": "bypassed_asia",
                    "source_ids": ["private"],
                },
            ),
        ]

        bound = cnb_gmgn_v2._bind_shard_control_states(
            shards, snapshot_candidates
        )

        self.assertEqual(bound[0][0]["github_check_state"], "passed")
        self.assertEqual(bound[1][0]["github_check_state"], "bypassed_asia")
        self.assertNotIn("metadata", bound[0][0])
        self.assertNotIn("source_ids", bound[1][0])

    def test_shard_input_v2_round_trips_the_control_state(self) -> None:
        candidate_id = "c1_" + "3" * 24
        candidate = {
            "candidate_id": candidate_id,
            "proxy": {"name": "candidate-a"},
            "github_check_state": "passed",
        }
        manifest = {
            "run_id": "gmgnv2_test_shard_state",
            "shards": [
                {
                    "candidate_count": 1,
                    "candidate_ids_sha256": cnb_gmgn_v2.candidate_ids_sha256(
                        [candidate_id]
                    ),
                }
            ],
        }
        payload = {
            "kind": cnb_gmgn_v2.SHARD_INPUT_KIND,
            "schema_version": cnb_gmgn_v2.SHARD_INPUT_SCHEMA_VERSION,
            "manifest_sha256": cnb_gmgn_v2.canonical_json_sha256(manifest),
            "run_id": manifest["run_id"],
            "shard_index": 0,
            "candidates": [candidate],
        }
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        with tempfile.TemporaryDirectory(dir=preferred or None) as directory:
            path = Path(directory) / "shard.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            loaded = cnb_gmgn_v2._load_shard(manifest, path, 0)

        self.assertEqual(loaded, [candidate])

    def test_mihomo_url_test_uses_alive_state_to_accept_the_complete_http_range(self) -> None:
        target_url = "https://gmgn.ai/"
        with patch.object(
            cnb_gmgn_v2,
            "_controller_request",
            side_effect=[
                cnb_gmgn_v2.CoordinatorError(
                    "An error occurred in the delay test (controller status 503)"
                ),
                {
                    "extra": {
                        target_url: {
                            "alive": True,
                            "history": [{"delay": 0}],
                        }
                    }
                },
            ],
        ) as request:
            outcome = cnb_gmgn_v2._mihomo_delay_outcome(
                "127.0.0.1:19090",
                "test-secret",
                proxy_name="DIRECT",
                target_url=target_url,
                timeout_ms=5000,
                expected_status="100-599",
            )

        self.assertEqual(normalize_outcome(outcome), (1, None))
        self.assertEqual(request.call_count, 2)

    def test_mihomo_url_test_rejects_a_delay_when_expected_status_did_not_match(self) -> None:
        target_url = "https://gmgn.ai/"
        with patch.object(
            cnb_gmgn_v2,
            "_controller_request",
            side_effect=[
                {"delay": 91},
                {
                    "extra": {
                        target_url: {
                            "alive": False,
                            "history": [{"delay": 0}],
                        }
                    }
                },
            ],
        ):
            outcome = cnb_gmgn_v2._mihomo_delay_outcome(
                "127.0.0.1:19090",
                "test-secret",
                proxy_name="candidate-a",
                target_url=target_url,
                timeout_ms=5000,
                expected_status=200,
            )

        self.assertEqual(normalize_outcome(outcome), (None, "other"))

    def test_control_discovery_balances_candidate_states_and_keeps_live_panel(self) -> None:
        candidates = [
            {
                "candidate_id": f"candidate-{state}-{index}",
                "github_check_state": state,
            }
            for state in ("passed", "bypassed_asia")
            for index in range(6)
        ]
        selected = cnb_gmgn_v2._select_control_candidates(candidates, limit=4)
        self.assertEqual(
            [candidate["github_check_state"] for candidate in selected].count("passed"),
            2,
        )
        self.assertEqual(
            [candidate["github_check_state"] for candidate in selected].count(
                "bypassed_asia"
            ),
            2,
        )
        live_ids = {
            selected[1]["candidate_id"]: 73,
            selected[3]["candidate_id"]: 51,
        }
        panel, diagnostics = cnb_gmgn_v2._discover_control_panel(
            selected,
            lambda candidate: (
                {"delay_ms": live_ids[candidate["candidate_id"]]}
                if candidate["candidate_id"] in live_ids
                else {"error_category": "connect"}
            ),
            panel_size=2,
            batch_size=4,
            workers=2,
        )
        self.assertEqual(
            [candidate["candidate_id"] for candidate in panel],
            [selected[3]["candidate_id"], selected[1]["candidate_id"]],
        )
        self.assertEqual(diagnostics["success_count"], 2)
        self.assertEqual(diagnostics["panel_size"], 2)
        outcome = cnb_gmgn_v2._control_panel_outcome(
            panel,
            lambda candidate: {"delay_ms": live_ids[candidate["candidate_id"]]},
            workers=2,
        )
        self.assertEqual(normalize_outcome(outcome), (51, None))

    def test_direct_probe_preflight_accepts_waf_control_but_fails_persistent_canary(self) -> None:
        diagnostics = cnb_gmgn_v2._require_direct_probe_preflight(
            control_probe=lambda _round: {"delay_ms": 80},
            canary_probe=lambda _canary, _round: {"delay_ms": 50},
            canary_ids=["canary-a"],
        )
        self.assertEqual(diagnostics["control"]["success_count"], 3)

        with self.assertRaisesRegex(
            cnb_gmgn_v2.CoordinatorError, "canary preflight"
        ):
            cnb_gmgn_v2._require_direct_probe_preflight(
                control_probe=lambda _round: {"delay_ms": 80},
                canary_probe=lambda _canary, _round: {
                    "error_category": "connect"
                },
                canary_ids=["canary-a"],
            )

    def test_safe_direct_probe_diagnostics_expose_only_aggregate_categories(self) -> None:
        control_samples = [
            {
                "round": round_number,
                "delay_ms": 100 if round_number <= 17 else None,
                "error_category": None if round_number <= 17 else "target_403",
            }
            for round_number in range(1, 21)
        ]
        canary_samples = [
            {
                "canary_id": canary_id,
                "round": round_number,
                "delay_ms": 50,
                "error_category": None,
            }
            for canary_id in cnb_gmgn_v2.CANARY_IDS
            for round_number in range(1, 21)
        ]
        controller_checks = [
            {
                "phase": phase,
                "round": round_number,
                "healthy": True,
                "version": "test-mihomo",
            }
            for round_number in range(1, 21)
            for phase in ("before", "after")
        ]
        scheduled = SimpleNamespace(
            control_samples=tuple(control_samples),
            canary_samples=tuple(canary_samples),
            controller_checks=tuple(controller_checks),
        )
        # This is the actual private-fragment shape.  The public/redacted
        # projection has ``controller`` instead, and must not be used here.
        private_fragment = {
            "kind": "cnb-gmgn-private-fragment",
            "schema_version": 2,
            "controller_checks": controller_checks,
        }
        diagnostics = cnb_gmgn_v2._safe_direct_probe_diagnostics(
            2,
            scheduled,
            private_fragment,
        )

        self.assertEqual(
            diagnostics["clients"],
            {
                "control": "browser-http-proxy-panel-strict-200",
                "canaries": "mihomo-direct-exact-state",
            },
        )
        self.assertEqual(diagnostics["controller_unhealthy_count"], 0)
        self.assertEqual(diagnostics["control"]["success_count"], 17)
        self.assertEqual(diagnostics["control"]["max_consecutive_failures"], 3)
        self.assertEqual(diagnostics["control"]["error_counts"], {"target_403": 3})
        serialized = json.dumps(diagnostics)
        for private_value in ("test-secret", "gmgn.ai", "1.1.1.1", '"server"'):
            self.assertNotIn(private_value, serialized)

    def test_probe_resolution_strictly_binds_guarded_and_dns_failed_partition(self) -> None:
        guarded = "c1_" + "1" * 24
        dns_failed = "c1_" + "2" * 24
        candidates = [{"candidate_id": guarded}, {"candidate_id": dns_failed}]
        manifest = {
            "run_id": "gmgnv2_test_partition",
            "shards": [
                {
                    "candidate_count": 2,
                    "candidate_ids_sha256": cnb_gmgn_v2.candidate_ids_sha256(
                        [guarded, dns_failed]
                    ),
                }
            ],
        }
        resolution = cnb_gmgn_v2._build_probe_resolution(
            manifest,
            candidates,
            0,
            pinned_candidate_ids=[guarded],
            dns_failed_candidate_ids=[dns_failed],
            ipv6_unavailable_candidate_ids=[],
        )
        self.assertEqual(resolution["guarded_candidate_ids"], [guarded])
        self.assertEqual(resolution["dns_failed_candidate_ids"], [dns_failed])
        self.assertEqual(
            cnb_gmgn_v2._validate_probe_resolution(
                manifest, candidates, 0, resolution
            ),
            resolution,
        )

        tampered = dict(resolution)
        tampered["dns_failed_candidate_ids"] = [guarded]
        with self.assertRaisesRegex(
            cnb_gmgn_v2.CoordinatorError, "partition"
        ):
            cnb_gmgn_v2._validate_probe_resolution(
                manifest, candidates, 0, tampered
            )

    def test_ipv4_probe_partition_filters_dual_stack_and_separates_ipv6_only(self) -> None:
        dual_stack = "c1_" + "3" * 24
        ipv6_only = "c1_" + "4" * 24
        pinned = {
            dual_stack: {
                "server": "dual.example",
                "port": 443,
                "addresses": ["2001:4860:4860::8888", "8.8.8.8"],
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
            },
            ipv6_only: {
                "server": "v6.example",
                "port": 443,
                "addresses": ["2606:4700:4700::1111"],
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
            },
        }

        selected, unavailable = cnb_gmgn_v2._select_ipv4_pinned_candidates(
            pinned
        )

        self.assertEqual(selected[dual_stack]["addresses"], ["8.8.8.8"])
        self.assertEqual(unavailable, (ipv6_only,))
        self.assertNotIn(ipv6_only, selected)

    def test_auxiliary_resolution_uses_only_public_ipv4_answers(self) -> None:
        with patch.object(
            cnb_gmgn_v2,
            "default_resolver",
            return_value=["2001:4860:4860::8888", "8.8.8.8"],
        ):
            self.assertEqual(
                cnb_gmgn_v2._public_addresses("example.test", 443),
                ["8.8.8.8"],
            )

    def test_public_region_label_rejects_ip_disguised_as_region(self) -> None:
        self.assertEqual(cnb_gmgn_v2._public_region_label(" Guangdong "), "Guangdong")
        for leaked_region in ("runner-8.8.8.8", "2001:db8::1"):
            with self.assertRaisesRegex(
                cnb_gmgn_v2.CoordinatorError, "IP address"
            ):
                cnb_gmgn_v2._public_region_label(leaked_region)

    def test_runtime_hosts_cover_every_dns_name_used_after_guard_activation(self) -> None:
        pinned = {
            "c1_" + "1" * 24: {
                "server": "node.example",
                "port": 443,
                "addresses": ["8.8.8.8"],
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
            }
        }
        auxiliary = auxiliary_targets()
        hosts = cnb_gmgn_v2._runtime_hosts(
            pinned,
            auxiliary,
            target_url="https://gmgn.ai/",
        )
        self.assertEqual(hosts["node.example"], "8.8.8.8")
        for target in cnb_gmgn_v2.DIRECT_TARGETS.values():
            self.assertIn(target["server"], hosts)
        region_target = cnb_gmgn_v2._operational_target(
            cnb_gmgn_v2.REGION_PROVIDER_TARGET, auxiliary
        )
        self.assertEqual(region_target["path"], "/geoip")
        self.assertEqual(region_target["expected_status"], 200)

    def test_runtime_host_collision_fails_closed_instead_of_rebinding(self) -> None:
        pinned = {
            "c1_" + "1" * 24: {
                "server": "gmgn.ai",
                "port": 443,
                "addresses": ["8.8.8.8"],
                "resolver_policy_version": RESOLVER_POLICY_VERSION,
            }
        }
        with self.assertRaisesRegex(
            cnb_gmgn_v2.CoordinatorError, "mapping is inconsistent"
        ):
            cnb_gmgn_v2._runtime_hosts(
                pinned,
                auxiliary_targets(),
                target_url="https://gmgn.ai/",
            )

    def test_cnb_capability_smoke_mutates_netns_and_shard_budget_covers_policy(self) -> None:
        document = yaml.safe_load(
            (Path(__file__).resolve().parents[1] / ".cnb.yml").read_text(
                encoding="utf-8"
            )
        )
        pipeline = document["main"]["web_trigger_gmgn_v2_shadow"][0]
        serialized = json.dumps(pipeline, ensure_ascii=False)
        self.assertIn("--exercise-netns", serialized)
        self.assertIn("scripts.probe_network_guard_linux", serialized)
        self.assertEqual(pipeline["env"]["V2_DOCKER_CLI_VERSION"], "27.5.1")
        self.assertIn("download.docker.com/linux/static/stable/x86_64", serialized)
        self.assertIn(
            "4f798b3ee1e0140eab5bf30b0edc4e84f4cdb53255a429dc3bbae9524845d640",
            serialized,
        )
        self.assertNotIn("--privileged", serialized)
        self.assertNotIn("seccomp=unconfined", serialized)
        probe_stage = next(
            stage
            for stage in pipeline["stages"]
            if stage["name"] == "Probe four guarded GMGN V2 shards in parallel"
        )
        self.assertEqual(len(probe_stage["jobs"]), 4)
        self.assertTrue(
            all(job["timeout"] == "300m" for job in probe_stage["jobs"].values())
        )
        self.assertEqual(pipeline["lock"]["expires"], 28800)
        self.assertEqual(pipeline["lock"]["timeout"], 28800)

        capacity = cnb_gmgn_v2._validate_runtime_capacity(
            4999, workers_per_shard=16
        )
        self.assertEqual(capacity["estimated_upper_seconds"], 14325.0)
        with self.assertRaisesRegex(cnb_gmgn_v2.CoordinatorError, "hard limit"):
            cnb_gmgn_v2._validate_runtime_capacity(
                5000, workers_per_shard=16
            )

    def test_region_selection_uses_the_budgeted_loopback_timeout(self) -> None:
        response = MagicMock()
        response.status = 200
        response.read.return_value = (
            b'{"ip":"1.1.1.1","country_code":"US",'
            b'"region_code":"CA","asn":"AS13335"}'
        )
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response

        with (
            patch.object(cnb_gmgn_v2, "_controller_request") as controller_request,
            patch.object(cnb_gmgn_v2.urllib.request, "build_opener", return_value=opener),
        ):
            result = cnb_gmgn_v2._proxy_region(
                controller="127.0.0.1:19090",
                secret="test-secret",
                mixed_port=19091,
                proxy_name="proxy-a",
                provider_target={"server": "region.example", "path": "/json"},
            )

        self.assertEqual(result["country_code"], "US")
        self.assertEqual(result["region_code"], "CA")
        controller_request.assert_called_once_with(
            "127.0.0.1:19090",
            "test-secret",
            "PUT",
            "/proxies/__gmgn_v2_probe__",
            body={"name": "proxy-a"},
            timeout=cnb_gmgn_v2.CONTROLLER_SELECTION_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            opener.open.call_args.kwargs["timeout"],
            cnb_gmgn_v2.REGION_LOOKUP_TIMEOUT_SECONDS,
        )


if __name__ == "__main__":
    unittest.main()
