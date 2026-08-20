from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path
from unittest.mock import patch

from scripts.candidate_contract import CANDIDATE_METADATA_SCHEMA_VERSION
from scripts.candidate_snapshot import CANDIDATE_STATUS_SCHEMA_VERSION
from scripts.publish_transaction import PublicationError, write_publish_bundle
from scripts.validate_public_outputs import (
    MihomoValidationError,
    RemoteNotFoundError,
    RemoteReadError,
    fetch_no_cache,
    main,
    validate_migration,
    validate_mihomo_profile,
    validate_remote_candidate_snapshot,
    validate_remote_candidate_publication,
    validate_remote_bundle,
    validate_series,
)
from tests.test_publication_transaction import bundle_fixture


class FakeResponse:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return self.content


def candidate_publication_fixture(main_sha: str = "b" * 40):
    profile = b"proxies:\n  - name: fixture\n"
    profile_sha = hashlib.sha256(profile).hexdigest()
    metadata = {
        "kind": "github-candidate-metadata",
        "schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
        "candidate_count": 1,
        "profile_sha256": profile_sha,
    }
    metadata_bytes = (
        json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    status = {
        "kind": "github-candidate-status",
        "schema_version": CANDIDATE_STATUS_SCHEMA_VERSION,
        "snapshot_id": "candidate_" + "1" * 24,
        "main_sha": main_sha,
        "candidate_count": 1,
        "candidate_metadata_count": 1,
        "profile_sha256": profile_sha,
        "candidate_metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
    }
    status_bytes = (
        json.dumps(status, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    return {
        "clash.yaml": profile,
        "status.json": status_bytes,
        "candidate-metadata.json": metadata_bytes,
    }


class RemoteValidatorTests(unittest.TestCase):
    def test_candidate_snapshot_validation_failure_leaves_no_evidence_directory(self) -> None:
        files = {
            "clash.yaml": b"proxies: []\n",
            "status.json": b"{}\n",
            "candidate-metadata.json": b"{}\n",
        }

        def opener(request, timeout):
            del timeout
            name = Path(urllib.parse.urlsplit(request.full_url).path).name
            return FakeResponse(files[name])

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            evidence = Path(directory) / "candidate-evidence"
            with (
                patch(
                    "scripts.validate_public_outputs.validate_candidate_snapshot",
                    side_effect=PublicationError("candidate contract rejected"),
                ),
                self.assertRaisesRegex(PublicationError, "contract rejected"),
            ):
                validate_remote_candidate_snapshot(
                    profile_url="https://example.invalid/clash.yaml",
                    status_url="https://example.invalid/status.json",
                    metadata_url="https://example.invalid/candidate-metadata.json",
                    evidence_dir=evidence,
                    opener=opener,
                )
            self.assertFalse(evidence.exists())

    def test_candidate_publication_smoke_reads_one_exact_revision_no_cache(self) -> None:
        revision = "a" * 40
        main_sha = "b" * 40
        files = candidate_publication_fixture(main_sha)
        requests = []

        def opener(request, timeout):
            del timeout
            requests.append(request)
            name = Path(urllib.parse.urlsplit(request.full_url).path).name
            return FakeResponse(files[name])

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            for name, content in files.items():
                (root / name).write_bytes(content)
            result = validate_remote_candidate_publication(
                profile=root / "clash.yaml",
                status=root / "status.json",
                metadata=root / "candidate-metadata.json",
                profile_url=f"https://raw.githubusercontent.com/o/r/{revision}/clash.yaml",
                status_url=f"https://raw.githubusercontent.com/o/r/{revision}/status.json",
                metadata_url=f"https://raw.githubusercontent.com/o/r/{revision}/candidate-metadata.json",
                expected_revision=revision,
                expected_main_sha=main_sha,
                scope="staging",
                evidence_dir=root / "evidence",
                opener=opener,
                sleeper=lambda _seconds: None,
            )
            evidence = json.loads(
                (root / "evidence" / "candidate-smoke-evidence.json").read_text(
                    encoding="utf-8"
                )
            )
        self.assertEqual(result["scope"], "staging")
        self.assertEqual(evidence["revision"], revision)
        self.assertEqual(len(requests), 3)
        nonces = {
            urllib.parse.parse_qs(urllib.parse.urlsplit(item.full_url).query)[
                "gmgn_v2_nonce"
            ][0]
            for item in requests
        }
        self.assertEqual(len(nonces), 1)
        for request in requests:
            headers = {key.casefold(): value for key, value in request.header_items()}
            self.assertEqual(headers["cache-control"], "no-cache")
            self.assertEqual(headers["pragma"], "no-cache")

    def test_candidate_publication_smoke_retries_reads_but_rejects_mismatch(self) -> None:
        revision = "a" * 40
        main_sha = "b" * 40
        files = candidate_publication_fixture(main_sha)
        calls = 0
        sleeps = []

        def flaky(request, timeout):
            nonlocal calls
            del timeout
            calls += 1
            if calls == 1:
                raise urllib.error.URLError("not propagated")
            name = Path(urllib.parse.urlsplit(request.full_url).path).name
            return FakeResponse(files[name])

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            for name, content in files.items():
                (root / name).write_bytes(content)
            validate_remote_candidate_publication(
                profile=root / "clash.yaml",
                status=root / "status.json",
                metadata=root / "candidate-metadata.json",
                profile_url=f"https://raw.githubusercontent.com/o/r/{revision}/clash.yaml",
                status_url=f"https://raw.githubusercontent.com/o/r/{revision}/status.json",
                metadata_url=f"https://raw.githubusercontent.com/o/r/{revision}/candidate-metadata.json",
                expected_revision=revision,
                expected_main_sha=main_sha,
                scope="staging",
                evidence_dir=root / "evidence",
                attempts=2,
                retry_delay_seconds=0.25,
                opener=flaky,
                sleeper=sleeps.append,
            )
            self.assertEqual(sleeps, [0.25])

            def mismatched(request, timeout):
                del timeout
                name = Path(urllib.parse.urlsplit(request.full_url).path).name
                content = files[name]
                if name == "status.json":
                    content += b" "
                return FakeResponse(content)

            with self.assertRaisesRegex(PublicationError, "differs"):
                validate_remote_candidate_publication(
                    profile=root / "clash.yaml",
                    status=root / "status.json",
                    metadata=root / "candidate-metadata.json",
                    profile_url=f"https://raw.githubusercontent.com/o/r/{revision}/clash.yaml",
                    status_url=f"https://raw.githubusercontent.com/o/r/{revision}/status.json",
                    metadata_url=f"https://raw.githubusercontent.com/o/r/{revision}/candidate-metadata.json",
                    expected_revision=revision,
                    expected_main_sha=main_sha,
                    scope="staging",
                    evidence_dir=root / "mismatch",
                    opener=mismatched,
                    sleeper=lambda _seconds: None,
                )

    def test_candidate_publication_smoke_requires_revision_bound_urls(self) -> None:
        files = candidate_publication_fixture()
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            for name, content in files.items():
                (root / name).write_bytes(content)
            with self.assertRaisesRegex(PublicationError, "expected revision"):
                validate_remote_candidate_publication(
                    profile=root / "clash.yaml",
                    status=root / "status.json",
                    metadata=root / "candidate-metadata.json",
                    profile_url="https://raw.githubusercontent.com/o/r/main/clash.yaml",
                    status_url="https://raw.githubusercontent.com/o/r/main/status.json",
                    metadata_url="https://raw.githubusercontent.com/o/r/main/candidate-metadata.json",
                    expected_revision="a" * 40,
                    expected_main_sha="b" * 40,
                    scope="staging",
                    evidence_dir=root / "evidence",
                )

    def test_fetch_uses_nonce_and_no_cache_headers(self) -> None:
        requests = []

        def opener(request, timeout):
            requests.append((request, timeout))
            return FakeResponse(b"ok")

        self.assertEqual(
            fetch_no_cache("https://example.invalid/status.json", nonce="abc", opener=opener),
            b"ok",
        )
        request, timeout = requests[0]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
        self.assertEqual(query["gmgn_v2_nonce"], ["abc"])
        headers = {key.casefold(): value for key, value in request.header_items()}
        self.assertEqual(headers["cache-control"], "no-cache")
        self.assertEqual(headers["pragma"], "no-cache")
        self.assertEqual(timeout, 30)

    def test_404_and_transient_errors_are_distinct(self) -> None:
        def missing(request, timeout):
            del request, timeout
            raise urllib.error.HTTPError("https://x", 404, "missing", {}, io.BytesIO())

        def unavailable(request, timeout):
            del request, timeout
            raise urllib.error.URLError("offline")

        with self.assertRaises(RemoteNotFoundError):
            fetch_no_cache("https://example.invalid/a", nonce="x", opener=missing)
        with self.assertRaises(RemoteReadError):
            fetch_no_cache("https://example.invalid/a", nonce="x", opener=unavailable)

    def test_remote_bundle_download_validates_all_files_and_mihomo(self) -> None:
        bundle, binary = bundle_fixture()
        requested = []
        commit = "a" * 40

        def opener(request, timeout):
            del timeout
            requested.append(request)
            path = urllib.parse.urlsplit(request.full_url).path
            marker = f"/raw/{commit}/"
            relative = path.split(marker, 1)[1]
            return FakeResponse(bundle.files[relative])

        def runner(command, **kwargs):
            del kwargs
            return subprocess.CompletedProcess(command, 0, "ok", "")

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            binary_path = Path(directory) / "mihomo"
            binary_path.write_bytes(binary)
            validated = validate_remote_bundle(
                base_url=f"https://example.invalid/raw/{commit}",
                expected_commit=commit,
                expected_revision=commit,
                scope="staging",
                expected_bundle_hash=bundle.bundle_hash,
                expected_source_sha=bundle.source_sha256,
                evidence_dir=Path(directory) / "evidence",
                mihomo=binary_path,
                opener=opener,
                mihomo_runner=runner,
            )
            self.assertEqual(validated.files, bundle.files)
            self.assertEqual(len(requested), len(bundle.files))
            self.assertTrue((Path(directory) / "evidence" / "bundle" / "status.json").is_file())
            evidence = json.loads(
                (Path(directory) / "evidence" / "smoke-evidence.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(evidence["scope"], "staging")
            self.assertEqual(evidence["expected_commit"], commit)

    def test_remote_bundle_requires_revision_bound_url(self) -> None:
        bundle, binary = bundle_fixture()
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            binary_path = Path(directory) / "mihomo"
            binary_path.write_bytes(binary)
            with self.assertRaisesRegex(PublicationError, "expected revision"):
                validate_remote_bundle(
                    base_url="https://example.invalid/raw/main",
                    expected_commit="a" * 40,
                    expected_revision="clash-cn-gmgn-v2-shadow",
                    scope="current",
                    expected_bundle_hash=bundle.bundle_hash,
                    expected_source_sha=bundle.source_sha256,
                    evidence_dir=Path(directory) / "evidence",
                    mihomo=binary_path,
                )

    def test_mihomo_hash_and_exit_status_fail_closed(self) -> None:
        bundle, binary = bundle_fixture()
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            binary_path = Path(directory) / "mihomo"
            binary_path.write_bytes(binary + b"tampered")
            with self.assertRaisesRegex(MihomoValidationError, "hash"):
                validate_mihomo_profile(
                    bundle, mihomo=binary_path, evidence_dir=directory
                )
            binary_path.write_bytes(binary)

            def rejected(command, **kwargs):
                del kwargs
                return subprocess.CompletedProcess(command, 1, "", "bad config")

            with self.assertRaisesRegex(MihomoValidationError, "rejected"):
                validate_mihomo_profile(
                    bundle,
                    mihomo=binary_path,
                    evidence_dir=directory,
                    runner=rejected,
                )

    def test_mihomo_validation_uses_a_minimal_secret_free_environment(self) -> None:
        bundle, binary = bundle_fixture()
        captured = {}

        def runner(command, **kwargs):
            captured["command"] = command
            captured.update(kwargs)
            return subprocess.CompletedProcess(command, 0, "", "")

        secrets = {
            "CNB_TOKEN": "cnb-secret",
            "GITHUB_TOKEN": "github-secret",
            "GMGN_IDENTITY_HMAC_KEY": "identity-secret",
            "GIT_ASKPASS": "askpass-secret",
        }
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            binary_path = Path(directory) / "mihomo"
            binary_path.write_bytes(binary)
            with patch.dict(os.environ, secrets, clear=False):
                validate_mihomo_profile(
                    bundle,
                    mihomo=binary_path,
                    evidence_dir=directory,
                    runner=runner,
                )

        child_env = captured["env"]
        self.assertTrue(set(secrets).isdisjoint(child_env))
        self.assertEqual(captured["stdout"], subprocess.PIPE)
        self.assertEqual(captured["stderr"], subprocess.PIPE)
        self.assertFalse(captured["check"])
        for key in ("HOME", "TEMP", "TMP", "TMPDIR"):
            self.assertIn("mihomo-check", child_env[key])


class RolloutValidatorTests(unittest.TestCase):
    def test_series_requires_distinct_spaced_runs_with_same_runtime(self) -> None:
        bundles = []
        previous_run_index = None
        previous_history = None
        for index in (1, 2, 3):
            bundle = bundle_fixture(
                source_sha=str(index) * 64,
                accepted_at=f"2026-08-{10 + index:02d}T00:00:00Z",
                source_run_at=f"2026-08-{9 + index:02d}T23:45:00Z",
                run_id=f"run-{index}",
                previous_run_index=previous_run_index,
                previous_history=previous_history,
            )[0]
            bundles.append(bundle)
            previous_run_index = json.loads(bundle.files["runs/index.json"])
            previous_history = json.loads(bundle.files["history.json"])
            previous_history.pop("bundle_hash")
        result = validate_series(
            bundles,
            required_valid_runs=3,
            min_spacing_seconds=21_600,
        )
        self.assertEqual(result["valid_runs"], 3)
        with self.assertRaisesRegex(PublicationError, "duplicate"):
            validate_series(
                [bundles[0], bundles[0], bundles[2]],
                required_valid_runs=3,
                require_distinct_source_sha=True,
            )

        legacy_region_files = dict(bundles[2].files)
        legacy_region_status = json.loads(legacy_region_files["status.json"])
        legacy_region_status["region_policy_version"] = "gmgn-region-v1"
        legacy_region_files["status.json"] = (
            json.dumps(
                legacy_region_status,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        legacy_region = copy.copy(bundles[2])
        object.__setattr__(legacy_region, "files", legacy_region_files)
        with self.assertRaisesRegex(PublicationError, "changed policy"):
            validate_series(
                [bundles[0], bundles[1], legacy_region],
                required_valid_runs=3,
                min_spacing_seconds=21_600,
            )

        changed_files = dict(bundles[2].files)
        run_index = json.loads(changed_files["runs/index.json"])
        run_index["entries"][0]["attempt_id"] = "f" * 24
        changed_files["runs/index.json"] = (
            json.dumps(
                run_index,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        changed = copy.copy(bundles[2])
        object.__setattr__(changed, "files", changed_files)
        with self.assertRaisesRegex(PublicationError, "retry relation"):
            validate_series(
                [bundles[0], bundles[1], changed],
                required_valid_runs=3,
                min_spacing_seconds=21_600,
            )

    def test_migration_requires_byte_identical_bundle_and_frozen_legacy(self) -> None:
        bundle, _binary = bundle_fixture()
        validate_migration(
            shadow=bundle,
            formal=bundle,
            expected_bundle_hash=bundle.bundle_hash,
            legacy_status={"frozen": True},
            expect_legacy_frozen=True,
        )
        changed_files = dict(bundle.files)
        changed_files["clash.yaml"] += b"\n"
        changed = copy.copy(bundle)
        object.__setattr__(changed, "files", changed_files)
        with self.assertRaisesRegex(PublicationError, "byte-identical"):
            validate_migration(
                shadow=bundle,
                formal=changed,
                expected_bundle_hash=bundle.bundle_hash,
            )
        with self.assertRaisesRegex(PublicationError, "frozen"):
            validate_migration(
                shadow=bundle,
                formal=bundle,
                expected_bundle_hash=bundle.bundle_hash,
                legacy_status={"frozen": False},
                expect_legacy_frozen=True,
            )

    def test_cli_local_bundle_fixture_is_loadable(self) -> None:
        bundle, _binary = bundle_fixture()
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            write_publish_bundle(directory, bundle)
            self.assertTrue(Path(directory, "bundle.json").is_file())
            self.assertEqual(json.loads(Path(directory, "bundle.json").read_text())["bundle_hash"], bundle.bundle_hash)

    def test_migration_cli_reuses_remote_no_cache_and_fixed_mihomo_validation(self) -> None:
        bundle, binary = bundle_fixture()
        shadow_commit = "a" * 40
        formal_commit = "b" * 40
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            binary_path = Path(directory) / "mihomo"
            binary_path.write_bytes(binary)
            with patch(
                "scripts.validate_public_outputs.validate_remote_bundle",
                side_effect=[bundle, bundle],
            ) as remote:
                self.assertEqual(
                    main(
                        [
                            "migration",
                            "--shadow-bundle-base-url",
                            f"https://example.invalid/raw/{shadow_commit}",
                            "--shadow-expected-commit",
                            shadow_commit,
                            "--shadow-expected-revision",
                            shadow_commit,
                            "--formal-bundle-base-url",
                            f"https://example.invalid/raw/{formal_commit}",
                            "--formal-expected-commit",
                            formal_commit,
                            "--formal-expected-revision",
                            formal_commit,
                            "--expected-bundle-hash",
                            bundle.bundle_hash,
                            "--expected-source-sha",
                            bundle.source_sha256,
                            "--mihomo",
                            str(binary_path),
                            "--evidence-dir",
                            str(Path(directory) / "evidence"),
                        ]
                    ),
                    0,
                )
            self.assertEqual(remote.call_count, 2)
            for call in remote.call_args_list:
                self.assertEqual(call.kwargs["scope"], "current")
                self.assertEqual(call.kwargs["mihomo"], str(binary_path))


if __name__ == "__main__":
    unittest.main()
