from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml

from scripts.candidate_snapshot import main as candidate_main
from scripts.candidate_sources import provenance_for_task, write_provenance_staging


class CandidatePipelineComponentTests(unittest.TestCase):
    def test_prepare_build_validate_round_trip_keeps_public_sidecars_redacted(self) -> None:
        task_temp = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        with tempfile.TemporaryDirectory(dir=task_temp) as directory:
            root = Path(directory)
            profile = root / "source.yaml"
            provenance = root / "provenance.json"
            identity_input = root / "identity-input.json"
            public = root / "public"
            node = {
                "name": "JP component",
                "type": "ss",
                "server": "8.8.8.8",
                "port": 443,
                "cipher": "aes-128-gcm",
                "password": "component-fake-secret",
            }
            profile.write_text(
                yaml.safe_dump({"proxies": [node]}, allow_unicode=True, sort_keys=False),
                encoding="utf-8",
            )
            source_task = SimpleNamespace(
                name="component-jp",
                sub="https://raw.githubusercontent.com/acme/component/main/jp.yaml",
                domain="",
                publish_derivatives=True,
            )
            sources, records = provenance_for_task(
                source_task,
                [node],
                observed_at="2026-08-11T00:00:00Z",
            )
            write_provenance_staging(
                provenance,
                sources=sources,
                records=records,
                generated_at="2026-08-11T00:00:00Z",
            )

            environment = {
                "GMGN_IDENTITY_HMAC_KEY": "component-identity-key",
                "GMGN_IDENTITY_KEY_VERSION": "component-key-v1",
                "GMGN_IDENTITY_EPOCH": "identity-v1",
            }
            with patch.dict(os.environ, environment):
                self.assertEqual(
                    candidate_main(
                        [
                            "prepare",
                            "--profile",
                            str(profile),
                            "--provenance",
                            str(provenance),
                            "--output",
                            str(identity_input),
                            "--run-at",
                            "2026-08-11T00:00:00Z",
                            "--mode",
                            "collect",
                            "--main-sha",
                            "a" * 40,
                            "--profile-url",
                            "https://example.invalid/clash.yaml",
                            "--candidate-metadata-url",
                            "https://example.invalid/candidate-metadata.json",
                            "--previous-state",
                            "confirmed_absent",
                        ]
                    ),
                    0,
                )
                self.assertEqual(
                    candidate_main(["build", "--input", str(identity_input), "--output-dir", str(public)]),
                    0,
                )
                self.assertEqual(
                    candidate_main(
                        [
                            "validate",
                            "--profile",
                            str(public / "clash.yaml"),
                            "--status",
                            str(public / "status.json"),
                            "--metadata",
                            str(public / "candidate-metadata.json"),
                        ]
                    ),
                    0,
                )

            status = json.loads((public / "status.json").read_text(encoding="utf-8"))
            metadata = json.loads((public / "candidate-metadata.json").read_text(encoding="utf-8"))
            yaml.safe_load((public / "clash.yaml").read_text(encoding="utf-8"))
            public_sidecars = json.dumps({"status": status, "metadata": metadata})
            self.assertNotIn("component-fake-secret", public_sidecars)
            self.assertNotIn("raw.githubusercontent.com", public_sidecars)
            self.assertTrue(status["publish_gate"]["passed"])


if __name__ == "__main__":
    unittest.main()
