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
