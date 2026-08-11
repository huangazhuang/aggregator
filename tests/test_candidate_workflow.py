from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

import yaml


WORKFLOW = Path(".github/workflows/clash-verge-auto.yml")


class CandidateWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")
        cls.document = yaml.safe_load(cls.text)
        cls.jobs = cls.document["jobs"]

    def test_candidate_v2_switch_is_explicit_and_default_off(self) -> None:
        self.assertRegex(
            self.text,
            r"candidate_v2:[\s\S]*?default: \"false\"",
        )
        self.assertIn("ENABLE_GITHUB_CANDIDATE_V2 || 'false'", self.text)

    def test_collection_identity_and_publish_permissions_are_isolated(self) -> None:
        self.assertEqual(set(self.jobs), {"collect", "candidate_identity", "publish"})
        self.assertEqual(self.document["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["collect"]["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["candidate_identity"]["permissions"], {"contents": "read"})
        self.assertEqual(self.jobs["publish"]["permissions"], {"contents": "write"})

        collect = json.dumps(self.jobs["collect"], ensure_ascii=False)
        identity = json.dumps(self.jobs["candidate_identity"], ensure_ascii=False)
        publish = json.dumps(self.jobs["publish"], ensure_ascii=False)
        self.assertNotIn("GMGN_IDENTITY_HMAC_KEY", collect)
        self.assertIn("GMGN_IDENTITY_HMAC_KEY", identity)
        self.assertNotIn("GMGN_IDENTITY_HMAC_KEY", publish)
        self.assertNotIn("subscribe/process.py", identity)
        self.assertNotIn("mihomo", identity.lower())
        self.assertNotIn("GH_TOKEN", identity)
        self.assertNotIn("PROBE_TOKEN", identity)
        self.assertNotIn("PROBE_TOKEN", publish)

    def test_v2_stage_does_not_trigger_cnb_or_write_other_output_branches(self) -> None:
        lowered = self.text.lower()
        self.assertNotIn("cnb-gmgn-source", lowered)
        self.assertNotIn("clash-cn-output", lowered)
        self.assertNotIn("clash-cn-gmgn-output", lowered)
        self.assertNotIn("clash-cn-gmgn-v2-shadow", lowered)
        self.assertIn("OUTPUT_BRANCH: clash-verge-output", self.text)

    def test_existing_concurrency_and_candidate_artifacts_are_preserved(self) -> None:
        self.assertEqual(
            self.document["concurrency"],
            {"group": "clash-verge-auto", "cancel-in-progress": True},
        )
        self.assertIn("candidate-metadata.json", self.text)
        self.assertIn("candidate-identity-input", self.text)
        self.assertIn("candidate-public-staging", self.text)

    def test_all_jobs_are_pinned_to_the_triggering_main_sha(self) -> None:
        for job_name in ("collect", "candidate_identity", "publish"):
            checkout = next(
                step
                for step in self.jobs[job_name]["steps"]
                if step.get("uses") == "actions/checkout@v5"
            )
            self.assertEqual(checkout["with"]["ref"], "${{ github.sha }}")

    def test_disabling_v2_restores_v1_without_a_stale_metadata_sidecar(self) -> None:
        publish_job = self.jobs["publish"]
        select_step = next(
            step
            for step in publish_job["steps"]
            if step.get("name") == "Select validated public staging"
        )
        self.assertIn("candidate_v2", select_step["if"])
        self.assertIn(
            "cp candidate-public/candidate-metadata.json public/candidate-metadata.json",
            select_step["run"],
        )

        publish_step = next(
            step
            for step in publish_job["steps"]
            if step.get("name") == "Build and stage profile commit"
        )
        self.assertIn('git switch --orphan "${OUTPUT_BRANCH}"', publish_step["run"])
        self.assertNotIn("previous-candidate-metadata", publish_step["run"])
        self.assertIn("needs.candidate_identity.result == 'success'", publish_job["if"])

    def test_candidate_v2_uses_staging_remote_smoke_lease_and_rollback(self) -> None:
        self.assertEqual(
            self.document["env"]["CANDIDATE_STAGING_BRANCH"],
            "clash-verge-output-staging",
        )
        self.assertGreaterEqual(self.jobs["publish"]["timeout-minutes"], 35)
        steps = {step.get("name"): step for step in self.jobs["publish"]["steps"]}
        build = steps["Build and stage profile commit"]["run"]
        self.assertIn('staging_ref="refs/heads/${CANDIDATE_STAGING_BRANCH}"', build)
        self.assertIn('--force-with-lease="${staging_ref}:${staging_tip}"', build)
        self.assertIn('if [ "${ENABLE_CANDIDATE_V2}" = "true" ]', build)

        staging = steps["Smoke exact candidate staging commit"]["run"]
        self.assertIn("scripts.validate_public_outputs candidate", staging)
        self.assertIn('--expected-revision "${revision}"', staging)
        self.assertIn("--scope staging", staging)

        promote = steps["Lease-promote and smoke candidate output branch"]["run"]
        self.assertIn('--force-with-lease="${output_ref}:${previous_tip}"', promote)
        self.assertIn('--expected-revision "${OUTPUT_BRANCH}"', promote)
        self.assertIn("--scope current", promote)
        self.assertIn("rollback_candidate_output()", promote)
        self.assertIn('--force-with-lease="${output_ref}:${candidate_commit}"', promote)
        self.assertIn('origin "${previous_tip}:${output_ref}"', promote)
        self.assertIn(
            'actual_output="$(git ls-remote --heads origin "${output_ref}")"',
            promote,
        )
        self.assertIn("actual_lookup_rc=$?", promote)
        self.assertRegex(
            promote,
            re.compile(
                r'if \[ "\$\{actual_lookup_rc\}" -ne 0 \]; then[\s\S]*?'
                r"rollback_candidate_output 1",
            ),
        )
        self.assertRegex(
            promote,
            re.compile(
                r'if \[ "\$\{actual_tip\}" != "\$\{candidate_commit\}" \]; then'
                r"[\s\S]*?rollback_candidate_output 1",
            ),
        )
        self.assertIn("rollback_push_rc=$?", promote)
        self.assertIn(
            'restored_output="$(git ls-remote --heads origin "${output_ref}")"',
            promote,
        )
        self.assertIn('if [ "${restored_tip}" != "${previous_tip}" ]; then', promote)
        self.assertIn('rollback_candidate_output "${smoke_rc}"', promote)
        self.assertIn('exit "${failure_rc}"', promote)
        self.assertNotIn("git push --force origin", promote)


if __name__ == "__main__":
    unittest.main()
