from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
GMGN_SECRET_IMPORT_URL = (
    "https://cnb.cool/ASD12321_446/aggregator-gmgn-secrets/"
    "-/blob/main/secret.yml"
)
GMGN_SECRET_REPOSITORY = "ASD12321_446/aggregator-gmgn-secrets"
GMGN_IDENTITY_CONFIG_NAMES = {
    "GMGN_IDENTITY_HMAC_KEY",
    "GMGN_IDENTITY_KEY_VERSION",
    "GMGN_IDENTITY_EPOCH",
}


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
        cls.cnb_text = (ROOT / ".cnb.yml").read_text(encoding="utf-8")
        cls.cnb = yaml.safe_load(cls.cnb_text)
        cls.coordinator_text = (ROOT / "scripts/cnb_gmgn_v2.py").read_text(
            encoding="utf-8"
        )
        cls.processed_state_text = (
            ROOT / "scripts/gmgn_processed_state.py"
        ).read_text(encoding="utf-8")
        cls.setup_text = (ROOT / "CNB_SETUP.md").read_text(encoding="utf-8")
        cls.dockerfile_text = (ROOT / "Dockerfile.gmgn-v2").read_text(
            encoding="utf-8"
        )
        cls.dockerignore_text = (
            ROOT / "Dockerfile.gmgn-v2.dockerignore"
        ).read_text(encoding="utf-8")

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

    def test_only_offline_identity_jobs_import_the_secret_repository(self) -> None:
        v2_pipeline = self.cnb["main"]["web_trigger_gmgn_v2_shadow"][0]
        self.assertNotIn("imports", v2_pipeline)

        import_routes = []
        for scope, events in self.cnb.items():
            if not isinstance(events, dict):
                continue
            for event, pipelines in events.items():
                if not isinstance(pipelines, list):
                    continue
                for index, pipeline in enumerate(pipelines):
                    if not isinstance(pipeline, dict):
                        continue
                    self.assertNotIn("imports", pipeline)
                    for stage_index, stage in enumerate(pipeline.get("stages", [])):
                        if not isinstance(stage, dict) or "imports" not in stage:
                            continue
                        import_routes.append(
                            (scope, event, index, stage_index, stage["name"])
                        )
                        self.assertEqual(stage["imports"], [GMGN_SECRET_IMPORT_URL])
                        self.assertEqual(
                            stage["env"],
                            {
                                "CNB_TOKEN": "",
                                "GITHUB_TOKEN": "",
                                "GIT_ASKPASS": "",
                            },
                        )

        self.assertEqual(
            import_routes,
            [
                (
                    "main",
                    "web_trigger_gmgn_v2_shadow",
                    0,
                    2,
                    "Prepare the offline identity-bound V2 manifest",
                ),
                (
                    "main",
                    "web_trigger_gmgn_v2_shadow",
                    0,
                    4,
                    "Redact measurements and exit identity offline",
                ),
                (
                    "cnb-gmgn-v2-*",
                    "tag_push",
                    0,
                    2,
                    "Prepare the offline identity-bound V2 manifest",
                ),
                (
                    "cnb-gmgn-v2-*",
                    "tag_push",
                    0,
                    4,
                    "Redact measurements and exit identity offline",
                ),
            ],
        )

        self.assertEqual(self.cnb_text.count(GMGN_SECRET_IMPORT_URL), 2)
        self.assertEqual(self.cnb_text.count(GMGN_SECRET_REPOSITORY), 2)

    def test_cnb_workflow_contains_no_plaintext_identity_hmac_key(self) -> None:
        def assert_no_identity_mapping_key(value: object) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    self.assertNotIn(key, GMGN_IDENTITY_CONFIG_NAMES)
                    assert_no_identity_mapping_key(nested)
            elif isinstance(value, list):
                for nested in value:
                    assert_no_identity_mapping_key(nested)

        assert_no_identity_mapping_key(self.cnb)
        plaintext_assignment = re.compile(
            r"(?m)^\s*(?:export\s+)?[\"']?(?:"
            + "|".join(sorted(GMGN_IDENTITY_CONFIG_NAMES))
            + r")[\"']?\s*(?::|=)"
        )
        self.assertIsNone(plaintext_assignment.search(self.cnb_text))

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

    def test_v2_child_image_includes_only_the_required_subscribe_runtime(self) -> None:
        self.assertEqual(
            [
                line
                for line in self.dockerfile_text.splitlines()
                if line.startswith("COPY subscribe/")
            ],
            [
                "COPY subscribe/__init__.py /opt/aggregator/subscribe/__init__.py",
                "COPY subscribe/asia.py /opt/aggregator/subscribe/asia.py",
            ],
        )
        self.assertEqual(
            [
                line
                for line in self.dockerignore_text.splitlines()
                if line.startswith("!subscribe")
            ],
            ["!subscribe/", "!subscribe/__init__.py", "!subscribe/asia.py"],
        )


if __name__ == "__main__":
    unittest.main()
