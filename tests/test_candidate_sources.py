from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.candidate_sources import (
    SOURCE_ID_VERSION,
    SOURCE_POLICY_VERSION,
    load_provenance_staging,
    provenance_for_task,
    safe_source_descriptor,
    write_provenance_staging,
)
from subscribe import collect
from subscribe.collect import _airport_quota_targets, select_airport_domains_with_stats
from subscribe.workflow import TaskConfig, dedup_task


class AirportExplorationQuotaTests(unittest.TestCase):
    def test_192_quota_reserves_known_untried_and_due_retry(self) -> None:
        now = 1_000_000.0
        domains = {f"known-{index:03d}": {} for index in range(300)}
        domains.update({f"new-{index:03d}": {} for index in range(60)})
        domains.update({f"due-{index:03d}": {} for index in range(60)})
        known = {name for name in domains if name.startswith("known-")}
        health = {
            name: {"retry_after": now - 1, "last_checked": index}
            for index, name in enumerate(sorted(name for name in domains if name.startswith("due-")))
        }

        selected, stats = select_airport_domains_with_stats(domains, health, known, 192, now=now)

        self.assertEqual(_airport_quota_targets(192), {"known_good": 115, "untried": 38, "due_retry": 39})
        self.assertEqual(len(selected), 192)
        self.assertEqual(stats["selected"], {"known_good": 115, "untried": 38, "due_retry": 39})

    def test_unused_bucket_spills_deterministically(self) -> None:
        now = 1_000_000.0
        domains = {f"known-{index:02d}": {} for index in range(20)}
        domains.update({"new-a": {}, "due-a": {}})
        known = {name for name in domains if name.startswith("known-")}
        health = {"due-a": {"retry_after": now - 1, "last_checked": 1}}

        selected, stats = select_airport_domains_with_stats(domains, health, known, 10, now=now)

        self.assertEqual(len(selected), 10)
        self.assertIn("new-a", selected)
        self.assertIn("due-a", selected)
        self.assertEqual(stats["selected"], {"known_good": 8, "untried": 1, "due_retry": 1})
        self.assertEqual(stats["unused"], {"known_good": 0, "untried": 1, "due_retry": 1})

    def test_input_order_does_not_change_selection(self) -> None:
        domains = {f"new-{index:03d}": {} for index in range(30)}
        reversed_domains = dict(reversed(list(domains.items())))

        first, _ = select_airport_domains_with_stats(domains, {}, set(), 10, now=1.0)
        second, _ = select_airport_domains_with_stats(reversed_domains, {}, set(), 10, now=1.0)

        self.assertEqual(list(first), list(second))

    def test_uncapped_pool_reports_real_buckets_without_changing_legacy_selection(self) -> None:
        now = 1_000_000.0
        domains = {"known": {}, "new": {}, "due": {}, "cooling": {}}
        health = {
            "due": {"retry_after": now - 1, "last_checked": 1},
            "cooling": {"retry_after": now + 100, "last_checked": 2},
        }

        selected, stats = select_airport_domains_with_stats(
            domains,
            health,
            {"known"},
            0,
            now=now,
        )

        self.assertEqual(list(selected), ["known", "new", "due", "cooling"])
        self.assertEqual(stats["selected"], {"known_good": 1, "untried": 1, "due_retry": 1})
        self.assertEqual(stats["cooldown_selected"], 1)


class TaskDeduplicationTests(unittest.TestCase):
    def test_duplicate_after_first_item_is_not_executed_twice(self) -> None:
        tasks = [
            TaskConfig(name="first", bin_name="subconverter", sub="https://one.example/sub"),
            TaskConfig(
                name="second",
                bin_name="subconverter",
                sub="https://two.example/sub",
                liveness=True,
                publish_derivatives=False,
            ),
            TaskConfig(
                name="duplicate",
                bin_name="subconverter",
                sub="https://two.example/sub",
                liveness=False,
                publish_derivatives=True,
                candidate_source_role="fixed",
            ),
        ]

        deduplicated = dedup_task(tasks)

        self.assertEqual([task.name for task in deduplicated], ["first", "second"])
        self.assertFalse(deduplicated[1].liveness)
        self.assertTrue(deduplicated[1].publish_derivatives)
        self.assertEqual(deduplicated[1].candidate_source_role, "fixed")

    def test_invalid_source_role_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "fixed or dynamic"):
            TaskConfig(
                name="invalid",
                bin_name="subconverter",
                candidate_source_role="guessed",
            )


class ProvenanceSourceTests(unittest.TestCase):
    def test_source_id_namespace_is_stable_across_policy_upgrade(self) -> None:
        raw = "https://raw.githubusercontent.com/acme/source/main/sub.yaml"
        descriptor = safe_source_descriptor(
            raw,
            task_name="stable-source",
            publish_derivatives=True,
        )
        expected_digest = hashlib.sha256(
            f"{SOURCE_ID_VERSION}\0public\0{raw}".encode("utf-8")
        ).hexdigest()[:24]

        self.assertEqual(SOURCE_ID_VERSION, "candidate-source-v2")
        self.assertEqual(SOURCE_POLICY_VERSION, "candidate-source-v3")
        self.assertEqual(descriptor["source_id"], f"public_{expected_digest}")

    def test_proxy_embedded_subscription_does_not_replace_stable_task_source(self) -> None:
        source_task = SimpleNamespace(
            name="stable-source",
            sub="https://raw.githubusercontent.com/acme/source/main/sub.yaml",
            domain="",
            publish_derivatives=True,
            candidate_source_role="fixed",
        )
        first = {"name": "one", "type": "ss", "server": "one.example", "port": 443, "cipher": "aes-128-gcm", "password": "x", "sub": "https://private.example/a?token=first"}
        second = {**first, "sub": "https://private.example/a?token=rotated"}

        first_sources, first_records = provenance_for_task(source_task, [first], observed_at="2026-08-11T00:00:00Z")
        second_sources, second_records = provenance_for_task(source_task, [second], observed_at="2026-08-11T06:00:00Z")

        self.assertEqual(first_sources[0]["source_id"], second_sources[0]["source_id"])
        self.assertEqual(first_sources[0]["source_kind"], "fixed")
        self.assertTrue(first_sources[0]["configured_this_run"])
        serialized = repr((first_sources, first_records, second_sources, second_records))
        self.assertNotIn("private.example", serialized)
        self.assertNotIn("token=", serialized)

    def test_refresh_tasks_keep_public_derivative_permission(self) -> None:
        task_temp = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        with tempfile.TemporaryDirectory(dir=task_temp) as directory:
            Path(directory, "subscribes.txt").write_text("https://example.invalid/sub\n", encoding="utf-8")
            with (
                patch.object(collect, "DATA_BASE", directory),
                patch.object(collect.utils, "multi_thread_run", return_value=[(True, False)]),
                patch.object(collect.AirPort, "enable_special_protocols", return_value=False),
                patch.dict(os.environ, {"PUBLISH_COLLECTED_DERIVATIVES": "true"}),
            ):
                tasks = collect.assign(
                    "subconverter",
                    subscribes_file="subscribes.txt",
                    refresh=True,
                    display=False,
                )

        self.assertEqual(len(tasks), 1)
        self.assertTrue(tasks[0].publish_derivatives)

    def test_private_source_url_credentials_cannot_survive_as_proxy_aliases(self) -> None:
        source_task = SimpleNamespace(
            name="opaque-source",
            sub=(
                "https://source-user:SOURCEPASSWORDABC123@private.example/sub"
                "?token=SUBSCRIPTIONTOKENABC123&client=CLIENTSECRETABC123"
            ),
            domain="",
            publish_derivatives=True,
        )

        sources, records = provenance_for_task(
            source_task,
            [
                {
                    "name": "JP SUBSCRIPTIONTOKENABC123",
                    "type": "ss",
                    "server": "node.example",
                    "port": 443,
                    "cipher": "aes-128-gcm",
                    "password": "proxy-secret",
                },
                {
                    "name": "JP sourcepasswordabc123",
                    "type": "ss",
                    "server": "node-2.example",
                    "port": 443,
                    "cipher": "aes-128-gcm",
                    "password": "proxy-secret-2",
                },
                {
                    "name": "JP safe label",
                    "type": "ss",
                    "server": "node-3.example",
                    "port": 443,
                    "cipher": "aes-128-gcm",
                    "password": "proxy-secret-3",
                },
            ],
            observed_at="2026-08-12T00:00:00Z",
        )

        self.assertEqual([record["alias"] for record in records], ["", "", "JP safe label"])
        public_projection = repr(
            (
                sources,
                [
                    {
                        key: value
                        for key, value in record.items()
                        if key != "proxy"
                    }
                    for record in records
                ],
            )
        )
        for secret in (
            "SOURCEPASSWORDABC123",
            "SUBSCRIPTIONTOKENABC123",
            "CLIENTSECRETABC123",
        ):
            self.assertNotIn(secret, public_projection)

    def test_private_source_path_fragment_bare_query_and_plus_tokens_are_private(self) -> None:
        source_task = SimpleNamespace(
            name="opaque-source",
            sub=(
                "https://private.example/sub/PATHTOKENABC123"
                "?BARETOKENABC123&encoded=BASE64+TOKENABC123"
                "#FRAGMENTTOKENABC123"
            ),
            domain="",
            publish_derivatives=True,
        )
        tokens = (
            "PATHTOKENABC123",
            "BARETOKENABC123",
            "BASE64+TOKENABC123",
            "FRAGMENTTOKENABC123",
        )
        proxies = [
            {
                "name": f"JP {token}",
                "type": "ss",
                "server": f"node-{index}.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": f"proxy-secret-{index}",
            }
            for index, token in enumerate(tokens)
        ]

        _, records = provenance_for_task(
            source_task,
            proxies,
            observed_at="2026-08-12T00:00:00Z",
        )

        self.assertEqual([record["alias"] for record in records], ["", "", "", ""])

    def test_public_github_path_segments_do_not_suppress_normal_aliases(self) -> None:
        source_task = SimpleNamespace(
            name="community",
            sub="https://raw.githubusercontent.com/acme/community/main/sub.yaml",
            domain="",
            publish_derivatives=True,
        )
        node = {
            "name": "JP community main",
            "type": "ss",
            "server": "node.example",
            "port": 443,
            "cipher": "aes-128-gcm",
            "password": "proxy-secret",
        }

        _, records = provenance_for_task(
            source_task,
            [node],
            observed_at="2026-08-12T00:00:00Z",
        )

        self.assertEqual(records[0]["alias"], "JP community main")

    def test_public_github_url_userinfo_and_query_tokens_are_still_private(self) -> None:
        source_task = SimpleNamespace(
            name="community",
            sub=(
                "https://source-user:GITHUBPASSWORDABC123@raw.githubusercontent.com/"
                "acme/community/main/sub.yaml?token=GITHUBQUERYTOKENABC123"
            ),
            domain="",
            publish_derivatives=True,
        )
        tokens = ("GITHUBPASSWORDABC123", "GITHUBQUERYTOKENABC123")
        proxies = [
            {
                "name": f"JP {token}",
                "type": "ss",
                "server": f"node-{index}.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": f"proxy-secret-{index}",
            }
            for index, token in enumerate(tokens)
        ]

        _, records = provenance_for_task(
            source_task,
            proxies,
            observed_at="2026-08-12T00:00:00Z",
        )

        self.assertEqual([record["alias"] for record in records], ["", ""])

    def test_percent_encoded_and_double_encoded_url_tokens_are_private(self) -> None:
        source_task = SimpleNamespace(
            name="opaque-source",
            sub=(
                "https://ENCODEDUSERABC123:ENCODED%252FPASSWORDABC123@private.example/"
                "sub?token=ABC%252FDEF123456"
            ),
            domain="",
            publish_derivatives=True,
        )
        aliases = (
            "JP ENCODED%252FPASSWORDABC123",
            "JP ENCODED%2FPASSWORDABC123",
            "JP ABC%252FDEF123456",
            "JP ABC%2FDEF123456",
            "JP ABC/DEF123456",
        )
        proxies = [
            {
                "name": alias,
                "type": "ss",
                "server": f"node-{index}.example",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": f"proxy-secret-{index}",
            }
            for index, alias in enumerate(aliases)
        ]

        _, records = provenance_for_task(
            source_task,
            proxies,
            observed_at="2026-08-12T00:00:00Z",
        )

        self.assertEqual([record["alias"] for record in records], ["", "", "", "", ""])

    def test_anytls_tls_fingerprint_survives_private_staging_round_trip(self) -> None:
        source_task = SimpleNamespace(
            name="JP AnyTLS",
            sub="https://raw.githubusercontent.com/acme/asia/main/anytls.yaml",
            domain="",
            publish_derivatives=True,
        )
        candidate = {
            "name": "JP AnyTLS 01",
            "type": "anytls",
            "server": "anytls.example",
            "port": 443,
            "password": "anytls-secret",
            "fingerprint": "chrome",
        }
        sources, records = provenance_for_task(
            source_task,
            [candidate],
            observed_at="2026-08-12T00:00:00Z",
        )
        self.assertEqual(records[0]["proxy"]["fingerprint"], "chrome")

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            path = Path(directory, "provenance.json")
            write_provenance_staging(
                path,
                sources=sources,
                records=records,
                generated_at="2026-08-12T00:00:00Z",
            )
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            loaded = load_provenance_staging(path)

        self.assertEqual(loaded["records"][0]["proxy"]["fingerprint"], "chrome")


if __name__ == "__main__":
    unittest.main()
