import argparse
import copy
import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.cnb_gmgn_publish import (
    GROUP_ASIA_FLEXIBLE,
    GROUP_AUTO,
    GROUP_MANUAL,
    GROUP_OBSERVATION,
    GROUP_STABLE,
    HISTORY_IDENTITY_MAP_KIND,
    HISTORY_IDENTITY_MAP_SCHEMA_VERSION,
    candidate_sort_key,
    load_previous_profile,
    load_selection_candidates,
    proxy_fingerprint,
    publish_gmgn,
    select_candidates,
    stage_history_adapter,
)
from scripts.gmgn_history import empty_history, load_history, write_history_atomic
from scripts.proxy_identity import IdentitySettings, candidate_id as public_candidate_id


def proxy(name: str, *, asia: bool, index: int) -> dict:
    prefix = "Japan" if asia else "United States"
    return {
        "name": f"{prefix} {name}",
        "type": "ss",
        "server": f"node-{index}.example",
        "port": 10000 + index,
        "cipher": "aes-128-gcm",
        "password": f"secret-{index}",
    }


def summary(
    within: int,
    *,
    asia: bool,
    first: int,
    second: int,
    response_count: int | None = None,
    p90: int = 800,
    median: int = 400,
    jitter: int = 20,
) -> dict:
    response_count = within if response_count is None else response_count
    slow = response_count - within
    no_result = 20 - response_count
    first_blocks = [min(first, 5), max(first - 5, 0)]
    second_blocks = [min(second, 5), max(second - 5, 0)]
    return {
        "preferred_asia": asia,
        "attempts": 20,
        "response_count": response_count,
        "within_limit_count": within,
        "first_half_within_limit_count": first,
        "second_half_within_limit_count": second,
        "five_round_block_counts": first_blocks + second_blocks,
        "slow_response_count": slow,
        "no_result_count": no_result,
        "response_rate": round(response_count / 20, 4),
        "within_limit_rate": round(within / 20, 4),
        "min_delay_ms": 100 if response_count else None,
        "median_delay_ms": median if response_count else None,
        "p90_delay_ms": p90 if response_count else None,
        "max_delay_ms": (1200 if slow else 900) if response_count else None,
        "jitter_ms": jitter if response_count else None,
    }


def candidate(
    name: str,
    *,
    asia: bool,
    index: int,
    within: int,
    first: int,
    second: int,
    response_count: int | None = None,
    p90: int = 800,
    median: int = 400,
    jitter: int = 20,
) -> dict:
    item_proxy = proxy(name, asia=asia, index=index)
    return {
        "proxy": item_proxy,
        "summary": summary(
            within,
            asia=asia,
            first=first,
            second=second,
            response_count=response_count,
            p90=p90,
            median=median,
            jitter=jitter,
        ),
        "fingerprint": proxy_fingerprint(item_proxy),
        "source_name": item_proxy["name"],
    }


class PublishTestCase(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    def write_bundle(self, root: Path, candidates: list[dict]):
        shards = [[] for _ in range(4)]
        for index, item in enumerate(candidates):
            shards[index % 4].append(item)
        shard_metadata = []
        for index, items in enumerate(shards):
            shard_metadata.append(
                {
                    "shard_index": index,
                    "proxy_count": len(items),
                    "preferred_asia_count": sum(
                        bool(item["summary"]["preferred_asia"]) for item in items
                    ),
                    "profile_sha256": f"profile-sha-{index}",
                }
            )
        manifest = {
            "kind": "cnb-gmgn-shadow-manifest",
            "schema_version": 2,
            "run_id": "shadow-test-run",
            "main_sha": "main-test-sha",
            "source_sha256": "source-test-sha",
            "target_url": "https://gmgn.ai/",
            "expected_status": 200,
            "request_timeout_ms": 3000,
            "qualified_delay_ms": 1000,
            "total_rounds": 20,
            "shard_count": 4,
            "source_count": len(candidates),
            "source_asia_count": sum(
                bool(item["summary"]["preferred_asia"]) for item in candidates
            ),
            "runner": {
                "runner_country": "China",
                "runner_region": "Shanghai",
                "runner_org": "example",
                "runner_geo_provider": "test",
            },
            "shards": shard_metadata,
        }
        manifest_path = root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        fragment_paths = []
        for index, items in enumerate(shards):
            fragment = {
                "kind": "cnb-gmgn-selection-fragment",
                "schema_version": 1,
                "run_id": manifest["run_id"],
                "main_sha": manifest["main_sha"],
                "source_sha256": manifest["source_sha256"],
                "target_url": manifest["target_url"],
                "expected_status": manifest["expected_status"],
                "request_timeout_ms": manifest["request_timeout_ms"],
                "qualified_delay_ms": manifest["qualified_delay_ms"],
                "total_rounds": manifest["total_rounds"],
                "shard_count": 4,
                "shard_index": index,
                "shard_profile_sha256": shard_metadata[index]["profile_sha256"],
                "proxy_count": len(items),
                "preferred_asia_count": shard_metadata[index][
                    "preferred_asia_count"
                ],
                "results": [
                    {
                        "proxy": item["proxy"],
                        "summary": item["summary"],
                    }
                    for item in items
                ],
            }
            path = root / f"selection-{index}.json"
            path.write_text(json.dumps(fragment), encoding="utf-8")
            fragment_paths.append(path)
        return manifest_path, fragment_paths

    def write_previous_profile(
        self,
        path: Path,
        proxies: list[dict],
        *,
        stable_names: list[str] | None = None,
        observation_names: list[str] | None = None,
    ) -> Path:
        stable_names = stable_names if stable_names is not None else [
            str(item["name"]) for item in proxies
        ]
        observation_names = observation_names or []
        profile = {
            "proxies": proxies,
            "proxy-groups": [
                {"name": GROUP_STABLE, "type": "select", "proxies": stable_names or ["DIRECT"]},
                {
                    "name": GROUP_OBSERVATION,
                    "type": "select",
                    "proxies": observation_names or ["DIRECT"],
                },
            ],
        }
        rendered = yaml.safe_dump(profile, allow_unicode=True, sort_keys=False)
        path.write_text(rendered, encoding="utf-8")
        status_path = path.with_name(f"{path.stem}-status.json")
        status_path.write_text(
            json.dumps(
                {
                    "kind": "cnb-gmgn-publish-status",
                    "schema_version": 1,
                    "published_count": len(proxies),
                    "profile_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        return status_path

    @staticmethod
    def args(
        manifest_path: Path,
        fragment_paths: list[Path],
        output_dir: Path,
        *,
        previous_profile: str = "",
        previous_status: str = "",
        previous_publication_exists: bool | None = None,
    ) -> argparse.Namespace:
        if previous_publication_exists is None:
            previous_publication_exists = bool(previous_profile or previous_status)
        return argparse.Namespace(
            manifest=str(manifest_path),
            fragments=[str(path) for path in fragment_paths],
            output_dir=str(output_dir),
            previous_profile=previous_profile,
            previous_status=previous_status,
            previous_publication_exists=previous_publication_exists,
            profile_url="https://example.invalid/clash.yaml",
        )


class SelectionPolicyTests(PublishTestCase):
    def test_asia_core_uses_halves_but_flexible_uses_only_total(self):
        candidates = [
            candidate("core", asia=True, index=1, within=14, first=5, second=9),
            candidate("core-burst", asia=True, index=2, within=14, first=4, second=10),
            candidate("flex", asia=True, index=3, within=10, first=3, second=7),
            candidate("flex-burst", asia=True, index=4, within=10, first=2, second=8),
            candidate("too-low", asia=True, index=5, within=9, first=4, second=5),
        ]

        selected = select_candidates(candidates)

        self.assertEqual(
            [item["source_name"] for item in selected["asia_core"]],
            ["Japan core"],
        )
        self.assertEqual(
            {item["source_name"] for item in selected["asia_flexible"]},
            {"Japan flex", "Japan flex-burst"},
        )
        self.assertEqual(len(selected["selected"]), 3)

    def test_non_asia_extra_slots_require_eighteen_and_cap_at_twenty(self):
        candidates = [
            candidate(
                f"elite-{index}",
                asia=False,
                index=index,
                within=18,
                first=9,
                second=9,
            )
            for index in range(25)
        ]
        candidates.append(
            candidate("seventeen", asia=False, index=100, within=17, first=8, second=9)
        )

        selected = select_candidates(candidates)

        self.assertEqual(len(selected["non_asia"]), 20)
        self.assertTrue(
            all(item["summary"]["within_limit_count"] == 18 for item in selected["non_asia"])
        )
        self.assertNotIn(
            "United States seventeen",
            {item["source_name"] for item in selected["non_asia"]},
        )

    def test_first_ten_non_asia_accept_sixteen_with_balanced_halves(self):
        candidates = [
            candidate(
                f"strict-{index}",
                asia=False,
                index=index,
                within=16,
                first=6,
                second=10,
            )
            for index in range(12)
        ]

        selected = select_candidates(candidates)

        self.assertEqual(len(selected["non_asia"]), 10)

    def test_sorting_uses_success_response_and_latency_order(self):
        better_success = candidate(
            "success",
            asia=True,
            index=1,
            within=15,
            first=7,
            second=8,
            p90=950,
        )
        better_response = candidate(
            "response",
            asia=True,
            index=2,
            within=14,
            first=7,
            second=7,
            response_count=20,
            p90=900,
        )
        lower_response = candidate(
            "lower-response",
            asia=True,
            index=3,
            within=14,
            first=7,
            second=7,
            response_count=14,
            p90=100,
        )
        lower_p90 = candidate(
            "lower-p90",
            asia=True,
            index=4,
            within=14,
            first=7,
            second=7,
            response_count=20,
            p90=700,
        )

        ranked = sorted(
            [lower_response, better_response, lower_p90, better_success],
            key=candidate_sort_key,
        )

        self.assertEqual(
            [item["source_name"] for item in ranked],
            [
                "Japan success",
                "Japan lower-p90",
                "Japan response",
                "Japan lower-response",
            ],
        )

    def test_total_cap_reserves_non_asia_then_prefers_core_over_flexible(self):
        candidates = [
            candidate(
                f"asia-core-{index}",
                asia=True,
                index=index,
                within=14,
                first=7,
                second=7,
            )
            for index in range(160)
        ]
        candidates.extend(
            candidate(
                f"non-asia-{index}",
                asia=False,
                index=1000 + index,
                within=18,
                first=9,
                second=9,
            )
            for index in range(20)
        )
        candidates.extend(
            candidate(
                f"flex-{index}",
                asia=True,
                index=2000 + index,
                within=10,
                first=5,
                second=5,
            )
            for index in range(20)
        )

        selected = select_candidates(candidates)

        self.assertEqual(len(selected["selected"]), 150)
        self.assertEqual(len(selected["non_asia"]), 20)
        self.assertEqual(len(selected["asia_core"]), 130)
        self.assertEqual(len(selected["asia_flexible"]), 0)

    def test_hysteresis_is_one_run_and_never_keeps_below_ten(self):
        retained = candidate(
            "retained", asia=True, index=1, within=12, first=2, second=10
        )
        old_observation = candidate(
            "old-observation", asia=True, index=2, within=12, first=6, second=6
        )
        too_low = candidate("too-low", asia=True, index=3, within=9, first=4, second=5)
        previous = {
            "stable_fingerprints": {
                retained["fingerprint"],
                old_observation["fingerprint"],
                too_low["fingerprint"],
            },
            "observation_fingerprints": {old_observation["fingerprint"]},
        }

        selected = select_candidates([retained, old_observation, too_low], previous)

        self.assertEqual(
            [item["source_name"] for item in selected["observation"]],
            ["Japan retained"],
        )
        self.assertEqual(
            [item["source_name"] for item in selected["asia_flexible"]],
            ["Japan old-observation"],
        )
        self.assertNotIn(
            "Japan too-low",
            {item["source_name"] for item in selected["selected"]},
        )


class FragmentValidationTests(PublishTestCase):
    def test_requires_exact_formal_shadow_manifest_kind_and_schema(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            item = candidate("core", asia=True, index=1, within=14, first=7, second=7)
            manifest, fragments = self.write_bundle(root, [item])
            original = json.loads(manifest.read_text(encoding="utf-8"))

            for field, value, message in (
                ("kind", "cnb-gmgn-selection-manifest", "manifest kind"),
                ("schema_version", 1, "manifest schema"),
                ("schema_version", 3, "manifest schema"),
            ):
                with self.subTest(field=field, value=value):
                    mutated = dict(original)
                    mutated[field] = value
                    manifest.write_text(json.dumps(mutated), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, message):
                        load_selection_candidates(manifest, fragments)

    def test_runner_metadata_accepts_only_four_redacted_string_fields(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            item = candidate("core", asia=True, index=1, within=14, first=7, second=7)
            manifest, fragments = self.write_bundle(root, [item])
            original = json.loads(manifest.read_text(encoding="utf-8"))

            mutations = []
            missing = copy.deepcopy(original)
            del missing["runner"]["runner_region"]
            mutations.append((missing, "incomplete or unexpected"))
            extra = copy.deepcopy(original)
            extra["runner"]["runner_ip"] = "192.0.2.1"
            mutations.append((extra, "incomplete or unexpected"))
            non_string = copy.deepcopy(original)
            non_string["runner"]["runner_org"] = 123
            mutations.append((non_string, "must contain strings"))

            for mutated, message in mutations:
                with self.subTest(message=message):
                    manifest.write_text(json.dumps(mutated), encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, message):
                        load_selection_candidates(manifest, fragments)

    def test_requires_all_four_private_fragments(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            items = [
                candidate("core", asia=True, index=1, within=14, first=7, second=7)
            ]
            manifest, fragments = self.write_bundle(root, items)

            with self.assertRaisesRegex(RuntimeError, "must be four"):
                load_selection_candidates(manifest, fragments[:3])

    def test_rejects_fragment_target_mismatch(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            items = [
                candidate("core", asia=True, index=1, within=14, first=7, second=7)
            ]
            manifest, fragments = self.write_bundle(root, items)
            fragment = json.loads(fragments[0].read_text(encoding="utf-8"))
            fragment["target_url"] = "https://www.gstatic.com/generate_204"
            fragments[0].write_text(json.dumps(fragment), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "target_url mismatch"):
                load_selection_candidates(manifest, fragments)

    def test_rejects_duplicate_source_names_across_shards(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            first = candidate("duplicate", asia=True, index=1, within=14, first=7, second=7)
            second = candidate("other", asia=True, index=2, within=14, first=7, second=7)
            second["proxy"]["name"] = first["proxy"]["name"]
            second["source_name"] = first["source_name"]
            manifest, fragments = self.write_bundle(root, [first, second])

            with self.assertRaisesRegex(RuntimeError, "duplicate source proxy names"):
                load_selection_candidates(manifest, fragments)

    def test_requires_fixed_three_second_sampling_timeout(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            item = candidate("core", asia=True, index=1, within=14, first=7, second=7)
            manifest, fragments = self.write_bundle(root, [item])
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["request_timeout_ms"] = 1500
            manifest.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "3000ms"):
                load_selection_candidates(manifest, fragments)

    def test_rejects_inconsistent_five_round_blocks(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            item = candidate("core", asia=True, index=1, within=14, first=7, second=7)
            item["summary"]["five_round_block_counts"] = [5, 2, 5, 1]
            manifest, fragments = self.write_bundle(root, [item])

            with self.assertRaisesRegex(RuntimeError, "block counts are inconsistent"):
                load_selection_candidates(manifest, fragments)

    def test_current_named_block_fields_are_also_supported(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            item = candidate("core", asia=True, index=1, within=14, first=7, second=7)
            blocks = item["summary"].pop("five_round_block_counts")
            for field, value in zip(
                (
                    "within_limit_count_rounds_1_5",
                    "within_limit_count_rounds_6_10",
                    "within_limit_count_rounds_11_15",
                    "within_limit_count_rounds_16_20",
                ),
                blocks,
            ):
                item["summary"][field] = value
            manifest, fragments = self.write_bundle(root, [item])

            _, loaded = load_selection_candidates(manifest, fragments)

            self.assertEqual(loaded[0]["summary"]["five_round_block_counts"], blocks)


class PreviousProfileTests(PublishTestCase):
    @staticmethod
    def http_error(request, code: int) -> urllib.error.HTTPError:
        url = request.full_url if hasattr(request, "full_url") else str(request)
        return urllib.error.HTTPError(
            url,
            code,
            "Not Found" if code == 404 else "Server Error",
            {},
            io.BytesIO(b""),
        )

    def test_confirmed_missing_branch_is_first_publish_without_fetching_raw_urls(self):
        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen"
        ) as urlopen:
            previous = load_previous_profile(
                "https://example.invalid/clash.yaml",
                "https://example.invalid/status.json",
                previous_publication_exists=False,
            )

        self.assertFalse(previous["exists"])
        self.assertEqual(previous["published_count"], 0)
        urlopen.assert_not_called()

    def test_existing_branch_404_is_fail_closed_immediately(self):
        def missing(request, timeout=None):
            raise self.http_error(request, 404)

        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen",
            side_effect=missing,
        ) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "output branch exists"):
                load_previous_profile(
                    "https://example.invalid/clash.yaml",
                    "https://example.invalid/status.json",
                    previous_publication_exists=True,
                )

        self.assertEqual(urlopen.call_count, 1)

    def test_one_sided_404_is_fail_closed(self):
        def inconsistent(request, timeout=None):
            if "clash.yaml" in request.full_url:
                raise self.http_error(request, 404)
            return io.BytesIO(b"{}")

        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen",
            side_effect=inconsistent,
        ):
            with self.assertRaisesRegex(RuntimeError, "output branch exists"):
                load_previous_profile(
                    "https://example.invalid/clash.yaml",
                    "https://example.invalid/status.json",
                    previous_publication_exists=True,
                )

    def test_non_404_network_failure_is_fail_closed(self):
        def failure(request, timeout=None):
            raise self.http_error(request, 500)

        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen", side_effect=failure
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 500"):
                load_previous_profile(
                    "https://example.invalid/clash.yaml",
                    "https://example.invalid/status.json",
                    previous_publication_exists=True,
                )

    def test_corrupt_previous_profile_is_rejected(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            path = root / "broken.yaml"
            content = b"proxies: ["
            path.write_bytes(content)
            status_path = root / "status.json"
            status_path.write_text(
                json.dumps(
                    {
                        "kind": "cnb-gmgn-publish-status",
                        "schema_version": 1,
                        "published_count": 1,
                        "profile_sha256": hashlib.sha256(content).hexdigest(),
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "invalid YAML"):
                load_previous_profile(
                    str(path),
                    str(status_path),
                    previous_publication_exists=True,
                )

    def test_previous_profile_sha_mismatch_is_fail_closed(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            profile_path = root / "previous.yaml"
            status_path = self.write_previous_profile(
                profile_path,
                [proxy("previous", asia=True, index=1)],
            )
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["profile_sha256"] = "0" * 64
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "SHA-256 does not match"):
                load_previous_profile(
                    str(profile_path),
                    str(status_path),
                    previous_publication_exists=True,
                )

    def test_previous_profile_count_mismatch_is_fail_closed(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            profile_path = root / "previous.yaml"
            status_path = self.write_previous_profile(
                profile_path,
                [proxy("previous", asia=True, index=1)],
            )
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["published_count"] = 2
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "count does not match"):
                load_previous_profile(
                    str(profile_path),
                    str(status_path),
                    previous_publication_exists=True,
                )

    def test_previous_profile_and_status_must_be_configured_together(self):
        with self.assertRaisesRegex(RuntimeError, "requires both"):
            load_previous_profile(
                "https://example.invalid/clash.yaml",
                "",
                previous_publication_exists=True,
            )


class PublicationTests(PublishTestCase):
    def test_first_publish_floor_refuses_nine_without_touching_output(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            items = [
                candidate(
                    f"core-{index}",
                    asia=True,
                    index=index,
                    within=14,
                    first=7,
                    second=7,
                )
                for index in range(9)
            ]
            manifest, fragments = self.write_bundle(root, items)
            output = root / "output"

            with self.assertRaisesRegex(RuntimeError, "at least 10"):
                publish_gmgn(self.args(manifest, fragments, output))

            self.assertFalse(output.exists())

    def test_later_publish_uses_maximum_of_ten_and_forty_percent(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            previous_proxies = [
                proxy(f"previous-{index}", asia=True, index=1000 + index)
                for index in range(30)
            ]
            previous_path = root / "previous.yaml"
            previous_status_path = self.write_previous_profile(
                previous_path, previous_proxies
            )
            items = [
                candidate(
                    f"current-{index}",
                    asia=True,
                    index=index,
                    within=14,
                    first=7,
                    second=7,
                )
                for index in range(11)
            ]
            manifest, fragments = self.write_bundle(root, items)

            with self.assertRaisesRegex(RuntimeError, "at least 12"):
                publish_gmgn(
                    self.args(
                        manifest,
                        fragments,
                        root / "output",
                        previous_profile=str(previous_path),
                        previous_status=str(previous_status_path),
                    )
                )

    def test_successful_output_has_required_groups_and_no_gstatic_merge(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            items = [
                candidate(
                    f"core-{index}",
                    asia=True,
                    index=index,
                    within=14,
                    first=7,
                    second=7,
                )
                for index in range(8)
            ]
            items.extend(
                candidate(
                    f"strict-{index}",
                    asia=False,
                    index=100 + index,
                    within=16,
                    first=8,
                    second=8,
                )
                for index in range(2)
            )
            manifest, fragments = self.write_bundle(root, items)
            old_proxy = proxy("old-gstatic-only", asia=False, index=999)
            previous_path = root / "previous.yaml"
            previous_status_path = self.write_previous_profile(
                previous_path, [old_proxy]
            )
            output = root / "output"

            self.assertEqual(
                publish_gmgn(
                    self.args(
                        manifest,
                        fragments,
                        output,
                        previous_profile=str(previous_path),
                        previous_status=str(previous_status_path),
                    )
                ),
                0,
            )

            profile = yaml.safe_load((output / "clash.yaml").read_text(encoding="utf-8"))
            status = json.loads((output / "status.json").read_text(encoding="utf-8"))
            readme = (output / "README.md").read_text(encoding="utf-8")
            groups = {group["name"]: group for group in profile["proxy-groups"]}
            self.assertEqual(
                set(groups),
                {
                    GROUP_MANUAL,
                    GROUP_STABLE,
                    GROUP_ASIA_FLEXIBLE,
                    GROUP_OBSERVATION,
                    GROUP_AUTO,
                },
            )
            self.assertEqual(groups[GROUP_AUTO]["url"], "https://gmgn.ai/")
            self.assertEqual(groups[GROUP_AUTO]["interval"], 300)
            self.assertNotIn("timeout", groups[GROUP_AUTO])
            self.assertEqual(groups[GROUP_MANUAL]["proxies"][0], GROUP_STABLE)
            self.assertEqual(len(profile["proxies"]), 10)
            self.assertNotIn("old-gstatic-only", (output / "clash.yaml").read_text(encoding="utf-8"))
            self.assertEqual(status["published_count"], 10)
            self.assertEqual(status["desired_capacity"], 80)
            self.assertFalse(status["desired_capacity_reached"])
            self.assertEqual(status["max_nodes"], 150)
            self.assertIn("启发式", readme)
            self.assertNotIn("secret-", json.dumps(status, ensure_ascii=False))
            self.assertNotIn("secret-", readme)

    def test_previous_stable_asia_is_written_to_observation_group_once(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            retained = candidate(
                "retained", asia=True, index=1, within=12, first=6, second=6
            )
            other_items = [
                candidate(
                    f"core-{index}",
                    asia=True,
                    index=10 + index,
                    within=14,
                    first=7,
                    second=7,
                )
                for index in range(9)
            ]
            items = [retained, *other_items]
            manifest, fragments = self.write_bundle(root, items)
            previous_path = root / "previous.yaml"
            previous_status_path = self.write_previous_profile(
                previous_path,
                [retained["proxy"]],
                stable_names=[retained["source_name"]],
            )
            output = root / "output"

            publish_gmgn(
                self.args(
                    manifest,
                    fragments,
                    output,
                    previous_profile=str(previous_path),
                    previous_status=str(previous_status_path),
                )
            )

            profile = yaml.safe_load((output / "clash.yaml").read_text(encoding="utf-8"))
            groups = {group["name"]: group for group in profile["proxy-groups"]}
            self.assertIn(retained["source_name"], groups[GROUP_OBSERVATION]["proxies"])
            self.assertNotIn(retained["source_name"], groups[GROUP_ASIA_FLEXIBLE]["proxies"])

    def test_history_adapter_is_default_off_and_can_stage_without_changing_selector(self):
        self.assertIsNone(
            stage_history_adapter(
                enabled=False,
                previous_history_path="missing-history.json",
                staged_history_path="missing-output.json",
                manifest={},
                candidates=[],
                selection={},
                accepted_at="",
            )
        )
        with self.temporary_directory() as directory:
            root = Path(directory)
            settings = IdentitySettings(b"publisher-history-test", "test-key-v1", "identity-v1")
            previous_path = root / "previous-history.json"
            staged_path = root / "staged-history.json"
            write_history_atomic(
                previous_path,
                empty_history(
                    identity_key_version=settings.identity_key_version,
                    identity_epoch=settings.identity_epoch,
                    selection_policy_version="selection-adapter-test",
                ),
            )
            item = candidate(
                "adapter", asia=True, index=501, within=14, first=7, second=7
            )
            selection = select_candidates([item])
            source_sha = hashlib.sha256(b"adapter-source").hexdigest()
            public_id = public_candidate_id(
                item["proxy"],
                key=settings.key,
                identity_key_version=settings.identity_key_version,
                identity_epoch=settings.identity_epoch,
            )
            identity_map = {
                "kind": HISTORY_IDENTITY_MAP_KIND,
                "schema_version": HISTORY_IDENTITY_MAP_SCHEMA_VERSION,
                "identity_key_version": settings.identity_key_version,
                "identity_epoch": settings.identity_epoch,
                "candidates": {item["fingerprint"]: public_id},
            }
            staged = stage_history_adapter(
                enabled=True,
                previous_history_path=str(previous_path),
                staged_history_path=str(staged_path),
                manifest={"run_id": "adapter-run", "source_sha256": source_sha},
                candidates=[item],
                selection=selection,
                accepted_at="2026-08-11T00:00:00Z",
                identity_map=identity_map,
            )
            self.assertEqual(staged["nodes"][public_id]["current_state"], "asia_core")
            self.assertEqual(load_history(staged_path), staged)

            publisher_source = Path("scripts/cnb_gmgn_publish.py").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("GMGN_IDENTITY_HMAC_KEY", publisher_source)
            self.assertNotIn("IdentitySettings.from_environment", publisher_source)

            with self.assertRaisesRegex(RuntimeError, "precomputed identity map"):
                stage_history_adapter(
                    enabled=True,
                    previous_history_path=str(previous_path),
                    staged_history_path=str(root / "missing-map.json"),
                    manifest={"run_id": "adapter-run-2", "source_sha256": hashlib.sha256(b"adapter-source-2").hexdigest()},
                    candidates=[item],
                    selection=selection,
                    accepted_at="2026-08-11T06:00:00Z",
                )

            with self.assertRaisesRegex(RuntimeError, "must not overwrite"):
                stage_history_adapter(
                    enabled=True,
                    previous_history_path=str(previous_path),
                    staged_history_path=str(previous_path),
                    manifest={"run_id": "adapter-run-2", "source_sha256": hashlib.sha256(b"adapter-source-2").hexdigest()},
                    candidates=[item],
                    selection=selection,
                    accepted_at="2026-08-11T06:00:00Z",
                    identity_map=identity_map,
                )

            wrong_version = copy.deepcopy(identity_map)
            wrong_version["identity_epoch"] = "identity-v2"
            with self.assertRaisesRegex(RuntimeError, "version disagrees"):
                stage_history_adapter(
                    enabled=True,
                    previous_history_path=str(previous_path),
                    staged_history_path=str(root / "wrong-version.json"),
                    manifest={"run_id": "adapter-run-2", "source_sha256": hashlib.sha256(b"adapter-source-2").hexdigest()},
                    candidates=[item],
                    selection=selection,
                    accepted_at="2026-08-11T06:00:00Z",
                    identity_map=wrong_version,
                )


if __name__ == "__main__":
    unittest.main()
