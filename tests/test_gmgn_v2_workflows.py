from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


class GmgnV2WorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sync_text = (ROOT / ".github/workflows/sync-cnb.yml").read_text(
            encoding="utf-8"
        )
        cls.sync = yaml.safe_load(cls.sync_text)
        cls.tests_text = (ROOT / ".github/workflows/tests.yml").read_text(
            encoding="utf-8"
        )
        cls.tests = yaml.safe_load(cls.tests_text)
        cls.cnb = yaml.safe_load((ROOT / ".cnb.yml").read_text(encoding="utf-8"))
        cls.coordinator_text = (ROOT / "scripts/cnb_gmgn_v2.py").read_text(
            encoding="utf-8"
        )
        cls.processed_state_text = (
            ROOT / "scripts/gmgn_processed_state.py"
        ).read_text(encoding="utf-8")
        cls.setup_text = (ROOT / "CNB_SETUP.md").read_text(encoding="utf-8")

    def test_manual_v2_trigger_is_default_off_and_requires_full_source_sha(self) -> None:
        dispatch = self.sync[True]["workflow_dispatch"]["inputs"]
        self.assertFalse(dispatch["trigger_gmgn_v2_shadow"]["default"])
        self.assertEqual(dispatch["gmgn_v2_source_sha"]["default"], "")

        step = next(
            item
            for item in self.sync["jobs"]["sync"]["steps"]
            if item["name"] == "Trigger guarded CNB GMGN V2 shadow"
        )
        script = step["run"]
        self.assertIn("^[0-9a-f]{64}$", script)
        self.assertIn('v2_tag="cnb-gmgn-v2-${source_sha}"', script)
        self.assertIn("cnb-gmgn-v2-retry-${source_sha}-${retry_token}", script)
        self.assertIn('primary_tag="cnb-gmgn-v2-${source_sha}"', script)
        self.assertIn("requires an existing primary GMGN V2 trigger", script)
        self.assertIn("Unable to determine whether the GMGN V2 trigger already exists", script)
        self.assertNotIn("cut -c", script)

    def test_v2_trigger_uses_guarded_anchor_and_cas_processed_registry(self) -> None:
        pipeline = self.cnb["main"]["web_trigger_gmgn_v2_shadow"][0]
        self.assertEqual(self.cnb["cnb-gmgn-v2-*"]["tag_push"][0], pipeline)
        serialized = json.dumps(pipeline, ensure_ascii=False)
        self.assertIn("clash-cn-gmgn-v2-shadow", serialized)
        self.assertNotIn("clash-cn-output", serialized)
        self.assertNotIn("clash-cn-gmgn-output", serialized)
        self.assertIn("scripts.cnb_gmgn_v2 processed", serialized)
        self.assertIn("failed_infrastructure", serialized)
        self.assertIn("identity-config", serialized)
        self.assertIn("--force-with-lease", self.coordinator_text)
        self.assertIn("processed_ref", self.coordinator_text)
        self.assertIn("clash-cn-gmgn-v2-processed", self.processed_state_text)
        self.assertNotIn("--state accepted", serialized)

        identity_stage = next(
            stage
            for stage in pipeline["stages"]
            if stage["name"] == "Prepare the offline identity-bound V2 manifest"
        )
        identity_script = identity_stage["script"]
        self.assertIn("--network none", identity_script)
        self.assertIn("--preflight /work/input/preflight.json", identity_script)
        self.assertIn("--trigger /work/input/trigger.json", identity_script)
        self.assertIn(
            "docker cp .cnb-runtime/gmgn-v2/preflight.json", identity_script
        )
        self.assertIn(
            "docker cp .cnb-runtime/gmgn-v2/trigger.json", identity_script
        )
        self.assertNotIn("--attempt-id", identity_script)
        self.assertNotIn("--retry-of", identity_script)
        self.assertNotIn("--retry-token", identity_script)

        finalize_stage = next(
            stage
            for stage in pipeline["stages"]
            if stage["name"] == "Finalize and locally validate one immutable V2 bundle"
        )
        finalize_script = finalize_stage["script"]
        self.assertIn("scripts.validate_public_outputs run", finalize_script)
        self.assertIn(
            "--evidence-dir .cnb-runtime/gmgn-v2/local-validation",
            finalize_script,
        )
        self.assertIn("-u CNB_TOKEN", finalize_script)
        self.assertIn("-u GITHUB_TOKEN", finalize_script)
        self.assertIn("-u GIT_ASKPASS", finalize_script)
        self.assertNotIn("clash/clash-linux-amd -t", finalize_script)

        legacy_pipeline = self.cnb["main"]["web_trigger_gmgn_shadow"][0]
        legacy_build = next(
            stage
            for stage in legacy_pipeline["stages"]
            if stage["name"] == "Build the independent GMGN priority profile"
        )
        legacy_script = legacy_build["script"]
        self.assertIn("if ! env -i", legacy_script)
        self.assertIn("mihomo-check.log 2>&1", legacy_script)
        self.assertIn("ERROR: Mihomo rejected the GMGN profile.", legacy_script)

        publish_stage = next(
            stage
            for stage in pipeline["stages"]
            if stage["name"] == "Transactionally publish only the V2 shadow branch"
        )
        self.assertEqual(publish_stage["timeout"], "30m")

    def test_setup_requires_identical_github_and_cnb_identity_configuration(self) -> None:
        self.assertIn("GitHub Actions Secret `GMGN_IDENTITY_HMAC_KEY`", self.setup_text)
        self.assertIn("完全相同的 key 字节", self.setup_text)
        self.assertIn("`GMGN_IDENTITY_KEY_VERSION`、`GMGN_IDENTITY_EPOCH`", self.setup_text)
        self.assertIn("GitHub Secret 尚未配置", self.setup_text)
        self.assertIn("clash-cn-gmgn-v2-processed/<source_sha>", self.setup_text)

    def test_ci_builds_the_exact_v2_dockerfile_without_publish_permissions(self) -> None:
        self.assertEqual(self.tests["permissions"], {"contents": "read"})
        unit_serialized = json.dumps(self.tests["jobs"]["unit-tests"], ensure_ascii=False)
        self.assertIn("scripts.validate_public_outputs candidate --help", unit_serialized)
        job = self.tests["jobs"]["gmgn-v2-container"]
        serialized = json.dumps(job, ensure_ascii=False)
        self.assertIn(
            "docker build --file Dockerfile.gmgn-v2 --tag aggregator-gmgn-v2:test .",
            serialized,
        )
        self.assertIn("--network none", serialized)
        self.assertNotIn("GMGN_IDENTITY_HMAC_KEY", serialized)
        self.assertNotIn("CNB_TOKEN", serialized)


if __name__ == "__main__":
    unittest.main()
