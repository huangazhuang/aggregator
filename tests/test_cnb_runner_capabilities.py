from __future__ import annotations

import unittest

from scripts.cnb_runner_capabilities import DIAGNOSTIC_CASES, parse_proc_status


class CnbRunnerCapabilityDiagnosticTests(unittest.TestCase):
    def test_proc_status_parser_keeps_only_sandbox_fields(self) -> None:
        parsed = parse_proc_status(
            "Name:\tpython\n"
            "CapEff:\t0000000000001000\n"
            "NoNewPrivs:\t1\n"
            "Seccomp:\t2\n"
            "VmRSS:\t123 kB\n"
        )
        self.assertEqual(
            parsed,
            {
                "CapEff": "0000000000001000",
                "NoNewPrivs": "1",
                "Seccomp": "2",
            },
        )

    def test_cases_request_only_the_exact_guard_capabilities(self) -> None:
        serialized = " ".join(
            option for _label, options in DIAGNOSTIC_CASES for option in options
        )
        self.assertNotIn("--privileged", serialized)
        self.assertNotIn("seccomp", serialized)
        self.assertNotIn("ALL", serialized)
        self.assertIn("NET_ADMIN", serialized)
        self.assertIn("SYS_ADMIN", serialized)


if __name__ == "__main__":
    unittest.main()
