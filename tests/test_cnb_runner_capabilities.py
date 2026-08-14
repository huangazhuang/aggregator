from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import unittest
from unittest.mock import patch

from scripts import cnb_runner_capabilities
from scripts.cnb_runner_capabilities import DIAGNOSTIC_CASES, parse_proc_status
from scripts.probe_network_guard_linux import LinuxGuardError


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

    def test_inside_diagnostic_calls_the_linux_backend_entrypoint(self) -> None:
        output = StringIO()
        with (
            patch(
                "scripts.probe_network_guard_linux.preflight_linux_backend",
                side_effect=LinuxGuardError("CAP_NET_ADMIN is required"),
            ) as preflight,
            patch.object(
                cnb_runner_capabilities,
                "_unprivileged_userns_probe",
                return_value={"available": True, "ok": False},
            ),
            redirect_stdout(output),
        ):
            returncode = cnb_runner_capabilities.main(
                ["inside", "--token", "0123456789ab"]
            )

        self.assertEqual(returncode, 0)
        preflight.assert_called_once_with()
        report = json.loads(output.getvalue())
        self.assertEqual(
            report["preflight"],
            {"ok": False, "error": "CAP_NET_ADMIN is required"},
        )


if __name__ == "__main__":
    unittest.main()
