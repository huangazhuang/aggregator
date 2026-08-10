import argparse
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
    candidate_sort_key,
    load_previous_profile,
    load_selection_candidates,
    proxy_fingerprint,
    publish_gmgn,
    select_candidates,
)


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
    ) -> None:
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
        path.write_text(
            yaml.safe_dump(profile, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )

    @staticmethod
    def args(
        manifest_path: Path,
        fragment_paths: list[Path],
        output_dir: Path,
        *,
        previous_profile: str = "",
    ) -> argparse.Namespace:
        return argparse.Namespace(
            manifest=str(manifest_path),
            fragments=[str(path) for path in fragment_paths],
            output_dir=str(output_dir),
            previous_profile=previous_profile,
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
    def test_http_404_means_no_first_profile(self):
        error = urllib.error.HTTPError(
            "https://example.invalid/clash.yaml",
            404,
            "Not Found",
            {},
            io.BytesIO(b""),
        )
        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen", side_effect=error
        ):
            previous = load_previous_profile("https://example.invalid/clash.yaml")

        self.assertFalse(previous["exists"])
        self.assertEqual(previous["published_count"], 0)

    def test_non_404_network_failure_is_fail_closed(self):
        error = urllib.error.HTTPError(
            "https://example.invalid/clash.yaml",
            500,
            "Server Error",
            {},
            io.BytesIO(b""),
        )
        with patch(
            "scripts.cnb_gmgn_publish.urllib.request.urlopen", side_effect=error
        ):
            with self.assertRaisesRegex(RuntimeError, "HTTP 500"):
                load_previous_profile("https://example.invalid/clash.yaml")

    def test_corrupt_previous_profile_is_rejected(self):
        with self.temporary_directory() as directory:
            path = Path(directory) / "broken.yaml"
            path.write_text("proxies: [", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "invalid YAML"):
                load_previous_profile(str(path))


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
            self.write_previous_profile(previous_path, previous_proxies)
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
            self.write_previous_profile(previous_path, [old_proxy])
            output = root / "output"

            self.assertEqual(
                publish_gmgn(
                    self.args(
                        manifest,
                        fragments,
                        output,
                        previous_profile=str(previous_path),
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
            self.write_previous_profile(
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
                )
            )

            profile = yaml.safe_load((output / "clash.yaml").read_text(encoding="utf-8"))
            groups = {group["name"]: group for group in profile["proxy-groups"]}
            self.assertIn(retained["source_name"], groups[GROUP_OBSERVATION]["proxies"])
            self.assertNotIn(retained["source_name"], groups[GROUP_ASIA_FLEXIBLE]["proxies"])


if __name__ == "__main__":
    unittest.main()
