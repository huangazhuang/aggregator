from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts import build_manual_config


WORKFLOW = Path(".github/workflows/clash-verge-auto.yml")
HANDOFF_SECRET = "CANDIDATE_HANDOFF_AES_KEY"


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

    def test_manual_subscription_mode_is_rejected_before_private_remote_fetch_in_v2(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "ENABLE_CANDIDATE_V2": "true",
                    "CLASH_SUBSCRIPTIONS_SECRET": "",
                    "CLASH_SUBSCRIPTION_URL_SECRET": "https://private.invalid/list?token=secret",
                },
                clear=False,
            ),
            patch.object(build_manual_config.urllib.request, "urlopen") as urlopen,
            self.assertRaisesRegex(
                build_manual_config.ManualCandidateV2Error,
                "does not support manual subscription mode",
            ),
        ):
            build_manual_config.main()

        urlopen.assert_not_called()

    def test_manual_subscription_mode_remains_available_when_v2_is_disabled(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            with (
                patch.dict(
                    os.environ,
                    {
                        "ENABLE_CANDIDATE_V2": "false",
                        "CLASH_SUBSCRIPTIONS_SECRET": "https://manual.invalid/sub?token=secret",
                        "CLASH_SUBSCRIPTION_URL_SECRET": "",
                    },
                    clear=False,
                ),
                patch(
                    "scripts.build_manual_config.Path",
                    side_effect=lambda value: root / value,
                ),
            ):
                self.assertEqual(build_manual_config.main(), 0)

            config = json.loads(
                (root / "subscribe/config/clash-verge.generated.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                config["domains"][0]["sub"],
                ["https://manual.invalid/sub?token=secret"],
            )

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
        self.assertIn(HANDOFF_SECRET, collect)
        self.assertIn(HANDOFF_SECRET, identity)
        self.assertNotIn(HANDOFF_SECRET, publish)
        self.assertEqual(
            self.text.count("secrets.CANDIDATE_HANDOFF_AES_KEY"),
            2,
        )
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

    def test_publication_runs_queue_without_weakening_cas(self) -> None:
        self.assertEqual(
            self.document["concurrency"],
            {"group": "clash-verge-auto", "cancel-in-progress": False},
        )
        publish_steps = {
            step.get("name"): step for step in self.jobs["publish"]["steps"]
        }
        build = publish_steps["Build and stage profile commit"]["run"]
        promote = publish_steps[
            "Lease-promote and smoke candidate output branch"
        ]["run"]
        self.assertIn('--force-with-lease="${output_ref}:${previous_tip}"', build)
        self.assertIn('--force-with-lease="${output_ref}:${previous_tip}"', promote)
        self.assertIn(
            '--force-with-lease="${output_ref}:${candidate_commit}"', promote
        )
        self.assertIn("candidate-metadata.json", self.text)
        self.assertIn("candidate-identity-input", self.text)
        self.assertIn("candidate-public-staging", self.text)

    def test_private_identity_handoff_artifact_contains_only_authenticated_ciphertext(self) -> None:
        collect_steps = self.jobs["collect"]["steps"]
        identity_steps = self.jobs["candidate_identity"]["steps"]
        upload = next(
            step
            for step in collect_steps
            if step.get("name") == "Upload candidate identity handoff"
        )
        encrypt = next(
            step
            for step in collect_steps
            if step.get("name") == "Encrypt candidate V2 identity handoff"
        )
        download = next(
            step
            for step in identity_steps
            if step.get("name") == "Download encrypted identity handoff"
        )
        decrypt = next(
            step
            for step in identity_steps
            if step.get("name")
            == "Decrypt and authenticate candidate V2 identity handoff"
        )

        self.assertEqual(upload["if"], "env.ENABLE_CANDIDATE_V2 == 'true'")
        self.assertEqual(upload["with"]["path"], "candidate-handoff/identity-input.enc")
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertIs(upload["with"]["overwrite"], True)
        self.assertEqual(download["with"]["path"], "candidate-handoff")
        self.assertIn(
            "python -m scripts.candidate_handoff encrypt",
            encrypt["run"],
        )
        self.assertIn(
            "--input candidate-private/identity-input.json",
            encrypt["run"],
        )
        self.assertIn(
            "--output candidate-handoff/identity-input.enc",
            encrypt["run"],
        )
        self.assertIn(
            "python -m scripts.candidate_handoff decrypt",
            decrypt["run"],
        )
        self.assertIn(
            "--input candidate-handoff/identity-input.enc",
            decrypt["run"],
        )
        self.assertIn(
            "--output candidate-private/identity-input.json",
            decrypt["run"],
        )
        for step in (encrypt, decrypt):
            self.assertEqual(
                step["env"][HANDOFF_SECRET],
                "${{ secrets.CANDIDATE_HANDOFF_AES_KEY }}",
            )
            self.assertIn('--repository "${GITHUB_REPOSITORY}"', step["run"])
            self.assertIn('--run-id "${GITHUB_RUN_ID}"', step["run"])
            self.assertIn('--trigger-sha "${GITHUB_SHA}"', step["run"])
            self.assertNotIn("GITHUB_RUN_ATTEMPT", step["run"])

        upload_paths = [
            str(step.get("with", {}).get("path", ""))
            for job in self.jobs.values()
            for step in job.get("steps", [])
            if step.get("uses") == "actions/upload-artifact@v4"
        ]
        self.assertNotIn("candidate-private/identity-input.json", upload_paths)
        self.assertFalse(
            any("candidate-private" in path for path in upload_paths),
            upload_paths,
        )

    def test_handoff_secret_is_not_required_when_candidate_v2_is_disabled(self) -> None:
        collect_steps = {
            step.get("name"): step for step in self.jobs["collect"]["steps"]
        }
        encrypt = collect_steps["Encrypt candidate V2 identity handoff"]
        self.assertEqual(encrypt["if"], "env.ENABLE_CANDIDATE_V2 == 'true'")
        self.assertIn(
            "candidate_v2 || vars.ENABLE_GITHUB_CANDIDATE_V2 || 'false'",
            self.jobs["candidate_identity"]["if"],
        )

        publish = json.dumps(self.jobs["publish"], ensure_ascii=False)
        self.assertNotIn(HANDOFF_SECRET, publish)

    def test_setup_documents_the_dedicated_non_hmac_handoff_key(self) -> None:
        documentation = (
            Path("CLASH_VERGE_AUTO.md").read_text(encoding="utf-8")
            + Path("CNB_SETUP.md").read_text(encoding="utf-8")
        )
        self.assertIn(HANDOFF_SECRET, documentation)
        self.assertIn("32 字节", documentation)
        self.assertIn("Base64", documentation)
        self.assertIn("AES-256-GCM", documentation)
        self.assertIn("不得复用", documentation)
        self.assertIn("Candidate V2 关闭时", documentation)

    def test_previous_output_is_classified_as_absent_v2_or_explicit_legacy(self) -> None:
        collect_steps = {
            step.get("name"): step for step in self.jobs["collect"]["steps"]
        }
        restore = collect_steps["Restore previous data"]
        script = restore["run"]

        self.assertEqual(restore["shell"], "bash")
        self.assertEqual(restore["id"], "previous")
        self.assertEqual(
            self.jobs["collect"]["outputs"]["observed_output_tip"],
            "${{ steps.previous.outputs.observed_output_tip }}",
        )
        self.assertIn("set -euo pipefail", script)
        self.assertIn(
            'previous_ref="$(git ls-remote --heads origin "refs/heads/${OUTPUT_BRANCH}")"',
            script,
        )
        self.assertIn('if [ "${lookup_rc}" -ne 0 ]; then', script)
        self.assertIn('if [ "${previous_ref_count}" -gt 1 ]; then', script)
        self.assertIn('previous_tip="$(printf \'%s\\n\' "${previous_ref}" | awk \'NF {print $1}\')"', script)
        self.assertIn(
            'echo "observed_output_tip=${previous_tip}" >> "${GITHUB_OUTPUT}"',
            script,
        )
        self.assertRegex(
            script,
            re.compile(
                r'if \[ -z "\$\{previous_tip\}" \]; then\s+'
                r'echo "confirmed_absent" > data/previous-ref-state\.txt\s+'
                r'else',
            ),
        )
        self.assertIn(
            'restore_required_previous_blob "${PROFILE_FILE}" "data/previous-${PROFILE_FILE}"',
            script,
        )
        self.assertIn(
            'restore_required_previous_blob "status.json" data/previous-status.json',
            script,
        )
        metadata_branch = script[script.index('metadata_entry='):]
        legacy_marker = metadata_branch.index(
            'echo "legacy_v1" > data/previous-ref-state.txt'
        )
        metadata_cardinality = metadata_branch.index(
            'if [ "$(printf \'%s\\n\' "${metadata_entry}" | sed \'/^$/d\' | wc -l)" -ne 1 ]; then'
        )
        metadata_restore = metadata_branch.index(
            "restore_required_previous_blob candidate-metadata.json data/previous-candidate-metadata.json"
        )
        present_marker = metadata_branch.index(
            'echo "present" > data/previous-ref-state.txt'
        )
        self.assertLess(legacy_marker, metadata_cardinality)
        self.assertLess(metadata_cardinality, metadata_restore)
        self.assertLess(metadata_restore, present_marker)

        # A present ref without metadata is never relabelled as a first publish.
        self.assertNotIn('echo "confirmed_absent"', metadata_branch)

    def test_previous_required_files_are_restored_from_the_observed_tip_fail_closed(self) -> None:
        restore = next(
            step
            for step in self.jobs["collect"]["steps"]
            if step.get("name") == "Restore previous data"
        )["run"]

        self.assertIn(
            'fetched_tip="$(git rev-parse "refs/remotes/origin/${OUTPUT_BRANCH}")"',
            restore,
        )
        self.assertIn('if [ "${fetched_tip}" != "${previous_tip}" ]; then', restore)
        self.assertIn('entry="$(git ls-tree "${previous_tip}" -- "${name}")"', restore)
        self.assertIn('if [ -z "${entry}" ]; then', restore)
        self.assertIn('if [ "$(git cat-file -t "${previous_tip}:${name}")" != "blob" ]; then', restore)
        self.assertIn('if ! git show "${previous_tip}:${name}" > "${destination}"; then', restore)
        self.assertNotIn(
            'git show "origin/${OUTPUT_BRANCH}:${name}" > "data/previous-',
            restore,
        )

    def test_candidate_prepare_routes_legacy_without_forging_v2_metadata(self) -> None:
        prepare = next(
            step
            for step in self.jobs["collect"]["steps"]
            if step.get("name") == "Prepare candidate V2 identity handoff"
        )["run"]

        self.assertIn('case "${previous_state}" in', prepare)
        present = re.search(
            r'present\)\s+(?P<body>[\s\S]*?)\s+;;',
            prepare,
        )
        legacy = re.search(
            r'legacy_v1\)\s+(?P<body>[\s\S]*?)\s+;;',
            prepare,
        )
        absent = re.search(
            r'confirmed_absent\)\s+(?P<body>[\s\S]*?)\s+;;',
            prepare,
        )
        self.assertIsNotNone(present)
        self.assertIsNotNone(legacy)
        self.assertIsNotNone(absent)
        self.assertIn("--previous-profile", present.group("body"))
        self.assertIn("--previous-status", present.group("body"))
        self.assertIn("--previous-metadata", present.group("body"))
        self.assertIn("--previous-profile", legacy.group("body"))
        self.assertIn("--previous-status", legacy.group("body"))
        self.assertNotIn("--previous-metadata", legacy.group("body"))
        self.assertNotIn("--previous-profile", absent.group("body"))
        self.assertNotIn("--previous-status", absent.group("body"))
        self.assertNotIn("--previous-metadata", absent.group("body"))
        self.assertIn('python -m scripts.candidate_snapshot prepare "${args[@]}"', prepare)

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

    def test_publish_uses_the_collect_observed_tip_and_rejects_stale_work(self) -> None:
        publish_job = self.jobs["publish"]
        build_step = next(
            step
            for step in publish_job["steps"]
            if step.get("name") == "Build and stage profile commit"
        )
        build = build_step["run"]

        self.assertEqual(
            build_step["env"]["OBSERVED_OUTPUT_TIP"],
            "${{ needs.collect.outputs.observed_output_tip }}",
        )
        self.assertIn('previous_tip="${OBSERVED_OUTPUT_TIP}"', build)
        self.assertIn(
            "grep -Eq '^[0-9a-f]{40}$'",
            build,
        )
        self.assertIn(
            'current_output="$(git ls-remote --heads origin "${output_ref}")"',
            build,
        )
        self.assertIn("current_lookup_rc=$?", build)
        self.assertIn('if [ "${current_lookup_rc}" -ne 0 ]; then', build)
        self.assertIn(
            'current_tip="$(printf \'%s\\n\' "${current_output}" | awk \'NF {print $1}\')"',
            build,
        )
        self.assertRegex(
            build,
            re.compile(
                r'if \[ "\$\{current_tip\}" != "\$\{previous_tip\}" \]; then\s+'
                r'echo "Output branch changed after collection; refusing to publish stale data\." >&2\s+'
                r'exit 1',
            ),
        )

        # A second lookup may verify the handoff, but it must never replace the
        # collect-time observed tip as the lease or rollback baseline.
        self.assertNotIn(
            'previous_tip="$(printf \'%s\\n\' "${current_output}"',
            build,
        )
        self.assertIn(
            '--force-with-lease="${output_ref}:${previous_tip}"',
            build,
        )
        self.assertNotIn('git push --force origin "${candidate_commit}:${output_ref}"', build)

    def test_candidate_v2_collection_and_crawler_fail_closed_while_v1_keeps_fallbacks(self) -> None:
        steps = {
            step.get("name"): step for step in self.jobs["collect"]["steps"]
        }
        collected = steps["Generate Clash profile from collected sources"]["run"]
        crawler = steps["Generate Clash profile from crawlers"]["run"]

        self.assertRegex(
            collected,
            re.compile(
                r'if \[ "\$\{ENABLE_CANDIDATE_V2\}" = "true" \] && '
                r'\[ "\$\{status\}" -ne 0 \]; then[\s\S]*?exit "\$\{status\}"'
            ),
        )
        self.assertRegex(
            collected,
            re.compile(
                r'if \[ "\$\{ENABLE_CANDIDATE_V2\}" = "true" \] && '
                r'\{ \[ "\$\{status\}" -ne 0 \] \|\| '
                r'\[ ! -s "data/\$\{PROFILE_FILE\}" \]; \}; then[\s\S]*?exit 1'
            ),
        )
        self.assertIn(
            "Airport collection did not produce live nodes; continuing with crawler mode.",
            collected,
        )
        self.assertIn("trying a no-alive-check rebuild", collected)

        self.assertRegex(
            crawler,
            re.compile(
                r'if \[ "\$\{ENABLE_CANDIDATE_V2\}" = "true" \] && '
                r'\[ "\$\{status\}" -ne 0 \]; then[\s\S]*?exit "\$\{status\}"'
            ),
        )
        self.assertRegex(
            crawler,
            re.compile(
                r'if \[ "\$\{ENABLE_CANDIDATE_V2\}" = "true" \] && '
                r'\[ ! -s "data/crawler-clash\.yaml" \]; then[\s\S]*?exit 1'
            ),
        )
        self.assertIn(
            "Crawler generation failed; keeping airport collection output.", crawler
        )
        self.assertIn(
            "Crawler generation produced no Clash profile; keeping airport collection output.",
            crawler,
        )

    def test_candidate_v2_sanitizes_endpoints_before_fc_and_mihomo(self) -> None:
        steps = self.jobs["collect"]["steps"]
        names = [step.get("name") for step in steps]
        collected = next(
            step for step in steps if step.get("name") == "Generate Clash profile from collected sources"
        )["run"]
        crawler = next(
            step for step in steps if step.get("name") == "Generate Clash profile from crawlers"
        )["run"]
        sanitizer = next(
            step
            for step in steps
            if step.get("name")
            == "Sanitize Candidate V2 endpoints before any proxy network access"
        )

        self.assertIn(
            'if [ "${ENABLE_CANDIDATE_V2}" = "true" ]; then\n  base_args+=(--skip)',
            collected,
        )
        self.assertIn(
            'if [ "${ENABLE_CANDIDATE_V2}" = "true" ]; then\n  export SKIP_ALIVE_CHECK="true"',
            crawler,
        )
        self.assertEqual(sanitizer["if"], "env.ENABLE_CANDIDATE_V2 == 'true'")
        self.assertIn(
            "python -m scripts.sanitize_candidate_endpoints",
            sanitizer["run"],
        )
        self.assertIn("--rebuild-from-provenance", sanitizer["run"])
        self.assertIn(
            "--safety-evidence data/candidate-endpoint-safety-evidence.json",
            sanitizer["run"],
        )
        self.assertIn(
            'cp "data/${PROFILE_FILE}" data/candidate-sanitized-clash.yaml',
            sanitizer["run"],
        )
        prepare = next(
            step
            for step in steps
            if step.get("name") == "Prepare candidate V2 identity handoff"
        )["run"]
        self.assertIn(
            "--endpoint-safety-evidence data/candidate-endpoint-safety-evidence.json",
            prepare,
        )
        self.assertIn(
            "--sanitized-profile data/candidate-sanitized-clash.yaml",
            prepare,
        )
        self.assertEqual(self.text.count("--rebuild-from-provenance"), 1)
        self.assertLess(
            names.index("Sanitize Candidate V2 endpoints before any proxy network access"),
            names.index("Drop GFW-blocked entries via configured China-side probe"),
        )
        self.assertLess(
            names.index("Sanitize Candidate V2 endpoints before any proxy network access"),
            names.index("Filter proxies by required site reachability"),
        )

    def test_candidate_v2_rebuild_is_gated_without_changing_the_v1_network_path(self) -> None:
        steps = self.jobs["collect"]["steps"]
        sanitizer = next(
            step
            for step in steps
            if step.get("name")
            == "Sanitize Candidate V2 endpoints before any proxy network access"
        )
        fc_probe = next(
            step
            for step in steps
            if step.get("name") == "Drop GFW-blocked entries via configured China-side probe"
        )
        reachability = next(
            step
            for step in steps
            if step.get("name") == "Filter proxies by required site reachability"
        )

        self.assertEqual(sanitizer["if"], "env.ENABLE_CANDIDATE_V2 == 'true'")
        self.assertEqual(fc_probe["if"], "env.PROBE_URL != ''")
        self.assertNotIn("if", reachability)


if __name__ == "__main__":
    unittest.main()
