from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import yaml

from scripts.candidate_sources import (
    EndpointResolutionInfrastructureError,
    provenance_for_task,
    write_provenance_staging,
)
from scripts.sanitize_candidate_endpoints import (
    CandidateEndpointSanitizationError,
    rebuild_candidate_profile,
    sanitize_candidate_profile,
    sanitize_candidate_profile_files,
)


def node(name: str, server: str, password: str, *, port: int = 443) -> dict:
    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": "aes-128-gcm",
        "password": password,
    }


def tuic_node(name: str, server: str, password: str, *, ip: str) -> dict:
    return {
        "name": name,
        "type": "tuic",
        "server": server,
        "port": 443,
        "uuid": "00000000-0000-4000-8000-000000000001",
        "password": password,
        "ip": ip,
    }


def provenance(nodes: list[dict]) -> dict:
    source = SimpleNamespace(
        name="community-source",
        sub="https://raw.githubusercontent.com/acme/community/main/clash.yaml",
        domain="",
        publish_derivatives=True,
    )
    sources, records = provenance_for_task(
        source,
        nodes,
        observed_at="2026-08-12T00:00:00Z",
    )
    return {"sources": sources, "records": records}


class CandidateEndpointSanitizerTests(unittest.TestCase):
    def test_rebuild_uses_provenance_when_subconverter_changed_connection_fields(self) -> None:
        observed = node("JP original", "8.8.8.8", "original-secret")
        observed["udp"] = True
        transformed = dict(observed)
        transformed.pop("udp")

        with self.assertRaisesRegex(
            CandidateEndpointSanitizationError,
            "not covered by collection provenance",
        ):
            sanitize_candidate_profile(
                {"proxies": [transformed]},
                provenance([observed]),
            )

        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            profile = root / "clash.yaml"
            provenance_file = root / "provenance.json"
            profile.write_text(
                yaml.safe_dump(
                    {"proxies": [transformed]},
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            value = provenance([observed])
            write_provenance_staging(
                provenance_file,
                sources=value["sources"],
                records=value["records"],
                generated_at="2026-08-12T00:00:00Z",
            )

            result = sanitize_candidate_profile_files(
                profile,
                [provenance_file],
                rebuild_from_provenance=True,
            )

            rebuilt = yaml.safe_load(profile.read_bytes())
            self.assertEqual(result.raw_count, 1)
            self.assertEqual(result.safe_count, 1)
            self.assertTrue(rebuilt["proxies"][0]["udp"])
            self.assertEqual(rebuilt["proxies"][0]["password"], "original-secret")
            self.assertIn("ASIA-KEEP JP", rebuilt["proxies"][0]["name"])

    def test_rebuild_deduplicates_exact_config_and_merges_asia_regions(self) -> None:
        first = node("JP shared", "8.8.8.8", "shared-secret")
        duplicate = node("KR shared", "8.8.8.8", "shared-secret")

        result = rebuild_candidate_profile(provenance([first, duplicate]))

        self.assertEqual(result.raw_count, 2)
        self.assertEqual(result.safe_count, 1)
        self.assertEqual(len(result.profile["proxies"]), 1)
        self.assertIn("ASIA-KEEP JP-KR", result.profile["proxies"][0]["name"])

    def test_rebuild_keeps_distinct_configs_that_share_one_endpoint(self) -> None:
        first = node("JP first", "8.8.8.8", "first-secret")
        second = node("KR second", "8.8.8.8", "second-secret")

        result = rebuild_candidate_profile(provenance([first, second]))

        self.assertEqual(result.safe_count, 2)
        self.assertEqual(
            {item["password"] for item in result.profile["proxies"]},
            {"first-secret", "second-secret"},
        )
        self.assertEqual(
            len({item["name"] for item in result.profile["proxies"]}),
            2,
        )

    def test_rebuild_keeps_anytls_variants_that_only_differ_by_tls_fingerprint(self) -> None:
        base = {
            "name": "JP AnyTLS Chrome",
            "type": "anytls",
            "server": "8.8.8.8",
            "port": 443,
            "password": "anytls-secret",
            "fingerprint": "chrome",
        }
        changed = {**base, "name": "KR AnyTLS Firefox", "fingerprint": "firefox"}

        result = rebuild_candidate_profile(provenance([base, changed]))
        serialized = yaml.safe_dump(result.profile, allow_unicode=True, sort_keys=False)
        reloaded = yaml.safe_load(serialized)

        self.assertEqual(result.safe_count, 2)
        self.assertEqual(
            {item["fingerprint"] for item in reloaded["proxies"]},
            {"chrome", "firefox"},
        )

    def test_rebuild_output_is_deterministic_when_record_order_changes(self) -> None:
        first = node("JP first", "8.8.8.8", "first-secret")
        second = node("KR second", "8.8.4.4", "second-secret")
        forward = provenance([first, second])
        reversed_records = {
            "sources": list(reversed(forward["sources"])),
            "records": list(reversed(forward["records"])),
        }

        self.assertEqual(
            rebuild_candidate_profile(forward).profile,
            rebuild_candidate_profile(reversed_records).profile,
        )

    def test_rebuild_rejects_unknown_metrics_instead_of_silently_dropping_them(self) -> None:
        first = node("JP duplicate", "8.8.8.8", "shared-secret")
        second = dict(first)
        first["metrics"] = {"collector_note": "private-first"}
        second["metrics"] = {"collector_note": "private-second"}
        forward = provenance([first, second])
        reverse = {
            "sources": list(reversed(forward["sources"])),
            "records": list(reversed(forward["records"])),
        }

        for value in (forward, reverse):
            with self.assertRaisesRegex(
                CandidateEndpointSanitizationError,
                "retained no safe proxies",
            ):
                rebuild_candidate_profile(value)

    def test_rebuild_rejects_dialer_proxy_instead_of_changing_its_semantics(self) -> None:
        direct = node("JP direct", "8.8.8.8", "direct-secret")
        chained = node("JP chained", "8.8.4.4", "chained-secret")
        chained["dialer-proxy"] = "JP direct"

        result = rebuild_candidate_profile(provenance([direct, chained]))

        self.assertEqual(result.safe_count, 1)
        self.assertEqual(result.invalid_count, 1)
        self.assertEqual(result.profile["proxies"][0]["password"], "direct-secret")

    def test_rebuild_rejects_malformed_provenance_record(self) -> None:
        candidate = node("JP malformed", "8.8.8.8", "safe-secret")
        value = provenance([candidate])
        value["records"][0]["unexpected"] = "field"

        with self.assertRaisesRegex(
            CandidateEndpointSanitizationError,
            "provenance record is malformed",
        ):
            rebuild_candidate_profile(value)

    def test_rebuild_fails_closed_when_every_proxy_has_private_fields(self) -> None:
        candidate = node("JP private", "8.8.8.8", "safe-secret")
        value = provenance([candidate])
        value["records"][0]["proxy"]["candidate_id"] = "attacker-controlled"

        with self.assertRaisesRegex(
            CandidateEndpointSanitizationError,
            "retained no safe proxies",
        ):
            rebuild_candidate_profile(value)

    def test_rebuild_fails_closed_when_no_public_endpoint_remains(self) -> None:
        candidate = node("JP private endpoint", "10.0.0.1", "safe-secret")

        with self.assertRaisesRegex(
            CandidateEndpointSanitizationError,
            "retained no safe proxies",
        ):
            rebuild_candidate_profile(provenance([candidate]))

    def test_rebuild_does_not_reuse_tuic_override_safety_for_same_server(self) -> None:
        public = tuic_node("JP public override", "8.8.8.8", "public-secret", ip="1.1.1.1")
        private = tuic_node("KR private override", "8.8.8.8", "private-secret", ip="127.0.0.1")

        result = rebuild_candidate_profile(provenance([public, private]))

        self.assertEqual(result.safe_count, 1)
        self.assertEqual(result.quarantined_count, 1)
        self.assertEqual(result.profile["proxies"][0]["ip"], "1.1.1.1")

    def test_sanitizer_does_not_reuse_tuic_override_safety_for_same_server(self) -> None:
        public = tuic_node("JP public override", "8.8.8.8", "public-secret", ip="1.1.1.1")
        private = tuic_node("KR private override", "8.8.8.8", "private-secret", ip="169.254.169.254")

        result = sanitize_candidate_profile(
            {"proxies": [public, private]},
            provenance([public, private]),
        )

        self.assertEqual(result.safe_count, 1)
        self.assertEqual(result.quarantined_count, 1)
        self.assertEqual(result.profile["proxies"][0]["ip"], "1.1.1.1")

    def test_rebuild_propagates_dns_infrastructure_failure(self) -> None:
        candidate = node("JP transient", "transient.example", "safe-secret")

        def resolver(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_AGAIN, "try again")

        with self.assertRaises(EndpointResolutionInfrastructureError):
            rebuild_candidate_profile(
                provenance([candidate]),
                resolver=resolver,
            )

    def test_quarantines_bad_dns_private_and_invalid_before_network_consumers(self) -> None:
        good = node("JP good", "good.example", "good-secret")
        missing = node("KR missing", "missing.example", "missing-secret")
        rebound = node("SG rebound", "rebound.example", "rebound-secret")
        invalid = node("TW invalid", "invalid.example", "invalid-secret", port=0)
        profile = {
            "proxies": [good, missing, rebound, invalid],
            "proxy-groups": [
                {
                    "name": "select",
                    "type": "select",
                    "proxies": [item["name"] for item in (good, missing, rebound, invalid)],
                }
            ],
        }

        def resolver(host: str, _port: int) -> list[str]:
            if host == "missing.example":
                raise socket.gaierror(socket.EAI_NONAME, "not found")
            if host == "rebound.example":
                return ["8.8.8.8", "169.254.169.254"]
            return ["8.8.8.8"]

        result = sanitize_candidate_profile(
            profile,
            provenance([good, missing, rebound, invalid]),
            resolver=resolver,
        )

        self.assertEqual(result.raw_count, 4)
        self.assertEqual(result.safe_count, 1)
        self.assertEqual(result.quarantined_count, 2)
        self.assertEqual(result.invalid_count, 1)
        self.assertEqual(
            [item["name"] for item in result.profile["proxies"]],
            ["JP good"],
        )
        self.assertEqual(result.profile["proxy-groups"][0]["proxies"], ["JP good"])

    def test_transient_dns_infrastructure_error_fails_the_whole_sanitization(self) -> None:
        candidate = node("JP transient", "transient.example", "transient-secret")

        def resolver(_host: str, _port: int) -> list[str]:
            raise socket.gaierror(socket.EAI_AGAIN, "try again")

        with self.assertRaises(EndpointResolutionInfrastructureError):
            sanitize_candidate_profile(
                {"proxies": [candidate]},
                provenance([candidate]),
                resolver=resolver,
            )

    def test_profile_without_collection_provenance_fails_closed(self) -> None:
        observed = node("JP observed", "observed.example", "observed-secret")
        injected = node("US injected", "injected.example", "injected-secret")
        with self.assertRaisesRegex(
            CandidateEndpointSanitizationError,
            "not covered by collection provenance",
        ):
            sanitize_candidate_profile(
                {"proxies": [observed, injected]},
                provenance([observed]),
                resolver=lambda _host, _port: ["8.8.8.8"],
            )

    def test_file_sanitizer_rewrites_atomically_in_the_task_temp(self) -> None:
        candidate = node("JP safe", "8.8.8.8", "safe-secret")
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            profile = root / "clash.yaml"
            provenance_file = root / "provenance.json"
            profile.write_text(
                yaml.safe_dump(
                    {"proxies": [candidate]},
                    allow_unicode=True,
                    sort_keys=False,
                ),
                encoding="utf-8",
            )
            value = provenance([candidate])
            write_provenance_staging(
                provenance_file,
                sources=value["sources"],
                records=value["records"],
                generated_at="2026-08-12T00:00:00Z",
            )

            result = sanitize_candidate_profile_files(
                profile,
                [provenance_file],
            )

            self.assertEqual(result.safe_count, 1)
            parsed = yaml.safe_load(profile.read_bytes())
            self.assertEqual(len(parsed["proxies"]), 1)
            self.assertFalse((root / ".clash.yaml.tmp").exists())


if __name__ == "__main__":
    unittest.main()
