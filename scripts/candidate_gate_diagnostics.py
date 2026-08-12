#!/usr/bin/env python3
"""Build deterministic, aggregate-only Candidate publish-gate diagnostics."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any


REGION_ORDER = ("HK", "JP", "KR", "SG", "TW")
KNOWN_REASON_CODES = frozenset(
    {
        "candidate_retention_below_60",
        "asia_retention_below_70",
        "source_quorum_below_80",
        *{
            f"region_{region}_{suffix}"
            for region in REGION_ORDER
            for suffix in ("retention_below_50", "dropped_to_zero")
        },
    }
)


class CandidateGateDiagnosticError(ValueError):
    """Raised when gate data cannot be represented by the safe contract."""


def _integer(value: Any, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise CandidateGateDiagnosticError(f"candidate gate {label} is invalid")
    return value


def _region_counts(value: Mapping[str, Any], *, label: str) -> dict[str, int]:
    return {
        region: _integer(value.get(region), label=f"{label} region count")
        for region in REGION_ORDER
    }


def build_candidate_gate_diagnostic(
    *,
    candidate_count: int,
    protected_asia_count: int,
    region_counts: Mapping[str, Any],
    previous: Mapping[str, Any],
    source_quorum: Mapping[str, Any],
    reasons: Sequence[str],
) -> dict[str, Any]:
    """Return reason codes plus integer current/minimum aggregates only."""

    current_total = _integer(candidate_count, label="candidate count")
    current_asia = _integer(protected_asia_count, label="Asia count")
    current_regions = _region_counts(region_counts, label="current")
    previous_total = _integer(previous.get("candidate_count"), label="previous candidate count")
    previous_asia = _integer(
        previous.get("protected_asia_count"),
        label="previous Asia count",
    )
    previous_regions_value = previous.get("region_hint_counts")
    if not isinstance(previous_regions_value, Mapping):
        raise CandidateGateDiagnosticError("candidate gate previous regions are invalid")
    previous_regions = _region_counts(previous_regions_value, label="previous")
    eligible = _integer(source_quorum.get("eligible"), label="eligible source count")
    acceptable = _integer(
        source_quorum.get("healthy_or_last_good"),
        label="acceptable source count",
    )
    if acceptable > eligible:
        raise CandidateGateDiagnosticError("candidate gate source counts are inconsistent")

    normalized_reasons: list[str] = []
    for reason in reasons:
        if not isinstance(reason, str) or reason not in KNOWN_REASON_CODES:
            raise CandidateGateDiagnosticError("candidate gate reason code is unsupported")
        if reason not in normalized_reasons:
            normalized_reasons.append(reason)
    if not normalized_reasons:
        raise CandidateGateDiagnosticError("candidate gate rejection has no reason codes")

    return {
        "reason_codes": normalized_reasons,
        "candidate": {
            "current": current_total,
            "minimum": (previous_total * 60 + 99) // 100,
        },
        "protected_asia": {
            "current": current_asia,
            "minimum": (previous_asia * 70 + 99) // 100,
        },
        "regions": {
            region: {
                "current": current_regions[region],
                "minimum": (previous_regions[region] * 50 + 99) // 100,
            }
            for region in REGION_ORDER
        },
        "source_quorum": {
            "acceptable": acceptable,
            "eligible": eligible,
            "minimum": (eligible * 80 + 99) // 100,
        },
    }


def format_candidate_gate_rejection(diagnostic: Mapping[str, Any]) -> str:
    """Serialize the fixed diagnostic without exposing arbitrary objects."""

    return "candidate publish gate rejected: " + json.dumps(
        diagnostic,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


__all__ = [
    "CandidateGateDiagnosticError",
    "KNOWN_REASON_CODES",
    "build_candidate_gate_diagnostic",
    "format_candidate_gate_rejection",
]
