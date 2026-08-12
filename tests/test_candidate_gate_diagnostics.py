from __future__ import annotations

import json
import unittest

from scripts.candidate_gate_diagnostics import (
    CandidateGateDiagnosticError,
    build_candidate_gate_diagnostic,
    format_candidate_gate_rejection,
)


class CandidateGateDiagnosticTests(unittest.TestCase):
    def test_rejection_contains_only_fixed_codes_and_integer_aggregates(self) -> None:
        diagnostic = build_candidate_gate_diagnostic(
            candidate_count=59,
            protected_asia_count=6,
            region_counts={"HK": 0, "JP": 2, "KR": 3, "SG": 4, "TW": 5},
            previous={
                "candidate_count": 100,
                "protected_asia_count": 10,
                "region_hint_counts": {"HK": 2, "JP": 3, "KR": 4, "SG": 5, "TW": 6},
            },
            source_quorum={"eligible": 25, "healthy_or_last_good": 19},
            reasons=[
                "candidate_retention_below_60",
                "region_HK_retention_below_50",
                "region_HK_dropped_to_zero",
                "source_quorum_below_80",
            ],
        )

        self.assertEqual(diagnostic["candidate"], {"current": 59, "minimum": 60})
        self.assertEqual(diagnostic["protected_asia"], {"current": 6, "minimum": 7})
        self.assertEqual(diagnostic["regions"]["JP"], {"current": 2, "minimum": 2})
        self.assertEqual(diagnostic["regions"]["SG"], {"current": 4, "minimum": 3})
        self.assertEqual(
            diagnostic["source_quorum"],
            {"acceptable": 19, "eligible": 25, "minimum": 20},
        )
        encoded = format_candidate_gate_rejection(diagnostic)
        payload = json.loads(encoded.removeprefix("candidate publish gate rejected: "))
        self.assertEqual(payload, diagnostic)
        self.assertTrue(
            all(type(value) is int for value in self._leaf_values(payload) if not isinstance(value, str))
        )

    def test_sensitive_input_cannot_enter_reason_codes_or_output(self) -> None:
        sentinel = "https://private.invalid/sub?token=credential-sentinel"
        with self.assertRaises(CandidateGateDiagnosticError) as raised:
            build_candidate_gate_diagnostic(
                candidate_count=1,
                protected_asia_count=1,
                region_counts={region: 0 for region in ("HK", "JP", "KR", "SG", "TW")},
                previous={
                    "candidate_count": 2,
                    "protected_asia_count": 2,
                    "region_hint_counts": {
                        region: 0 for region in ("HK", "JP", "KR", "SG", "TW")
                    },
                },
                source_quorum={"eligible": 1, "healthy_or_last_good": 0},
                reasons=[sentinel],
            )

        message = str(raised.exception)
        self.assertNotIn("private.invalid", message)
        self.assertNotIn("credential-sentinel", message)

    def test_invalid_counts_are_rejected_without_stringifying_values(self) -> None:
        sentinel = "credential-sentinel"
        with self.assertRaises(CandidateGateDiagnosticError) as raised:
            build_candidate_gate_diagnostic(
                candidate_count=sentinel,  # type: ignore[arg-type]
                protected_asia_count=0,
                region_counts={region: 0 for region in ("HK", "JP", "KR", "SG", "TW")},
                previous={
                    "candidate_count": 0,
                    "protected_asia_count": 0,
                    "region_hint_counts": {
                        region: 0 for region in ("HK", "JP", "KR", "SG", "TW")
                    },
                },
                source_quorum={"eligible": 0, "healthy_or_last_good": 0},
                reasons=["source_quorum_below_80"],
            )
        self.assertNotIn(sentinel, str(raised.exception))

    @staticmethod
    def _leaf_values(value: object) -> list[object]:
        if isinstance(value, dict):
            result: list[object] = []
            for nested in value.values():
                result.extend(CandidateGateDiagnosticTests._leaf_values(nested))
            return result
        if isinstance(value, list):
            result = []
            for nested in value:
                result.extend(CandidateGateDiagnosticTests._leaf_values(nested))
            return result
        return [value]


if __name__ == "__main__":
    unittest.main()
