from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROCESS = ROOT / "subscribe" / "process.py"


def run_guard(groups: object, *, candidate_v2: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment["ENABLE_CANDIDATE_V2"] = candidate_v2
    code = (
        "import json,sys; "
        f"sys.path.insert(0, {str(PROCESS.parent)!r}); "
        "import process; "
        "process.enforce_candidate_v2_pre_network_config(json.loads(sys.argv[1]))"
    )
    return subprocess.run(
        [sys.executable, "-c", code, json.dumps(groups)],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


class CandidateProcessSafetyTests(unittest.TestCase):
    def test_candidate_v2_rejects_regularize_before_any_task_execution(self) -> None:
        result = run_guard(
            {
                "crawler": {
                    "regularize": {"enable": True, "locate": True},
                }
            },
            candidate_v2="true",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "forbids group regularize before endpoint sanitization",
            result.stderr,
        )

        source = PROCESS.read_text(encoding="utf-8")
        guard = source.index(
            "enforce_candidate_v2_pre_network_config(process_config.groups)"
        )
        task_execution = source.index(
            "pushtool = push.get_instance",
            guard,
        )
        self.assertLess(guard, task_execution)

    def test_v1_keeps_existing_regularize_configuration(self) -> None:
        groups = {"crawler": {"regularize": {"enable": True}}}

        for value in ("", "false"):
            with self.subTest(value=value):
                result = run_guard(groups, candidate_v2=value)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_v2_accepts_configs_without_enabled_regularize(self) -> None:
        result = run_guard(
            {
                "missing": {},
                "disabled": {"regularize": {"enable": False}},
            },
            candidate_v2="true",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_candidate_v2_rejects_a_malformed_group_contract(self) -> None:
        result = run_guard([], candidate_v2="true")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Candidate V2 group configuration is invalid", result.stderr)


if __name__ == "__main__":
    unittest.main()
