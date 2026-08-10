#!/usr/bin/env python3
"""Replay the CNB tiered selector from secret-free aggregate probe metrics.

Primary input is ``redacted-probe-results.json`` produced by
``scripts.cnb_diagnostics``. A colocated ``failure.json`` is also accepted;
its safe basename reference is resolved relative to that file.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any, Iterable

from scripts.cnb_diagnostics import (
    POLICY_NODE_ID_KEY,
    SELECTION_SCHEMA_VERSION,
    replay_policy_snapshot,
)
from scripts.cnb_mihomo_filter import select_stable_results


TIER_NAMES = (
    "asia-strict",
    "asia-fallback",
    "asia-emergency",
    "non-asia-strict",
)


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read replay JSON {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("replay JSON must be an object")
    return payload


def _validate_replay_bundle(payload: dict[str, Any]) -> None:
    if payload.get("schema_version") != 1:
        raise ValueError("unsupported replay schema_version")
    if payload.get("kind") != "cnb-redacted-probe-results":
        raise ValueError("JSON is not a CNB redacted replay bundle")
    if not re.fullmatch(r"r1_[0-9a-f]{32}", str(payload.get("run_id") or "")):
        raise ValueError("replay bundle has an invalid run_id")
    results = payload.get("results")
    if not isinstance(results, list):
        raise ValueError("replay bundle has no results list")
    try:
        result_count = int(payload.get("result_count"))
    except (TypeError, ValueError) as exc:
        raise ValueError("replay bundle has an invalid result_count") from exc
    if result_count != len(results):
        raise ValueError("replay bundle result_count does not match its results list")
    if not isinstance(payload.get("policy"), dict):
        raise ValueError("replay bundle has no policy object")
    _validate_stored_policy(payload["policy"])


def _validate_stored_policy(stored: dict[str, Any]) -> None:
    """Reject mixed, partial, or unsupported production-policy snapshots."""

    expected_fields = set(replay_policy_snapshot())
    stored_fields = set(stored)
    missing = sorted(expected_fields - stored_fields)
    if missing:
        raise ValueError(
            "replay policy is missing required field(s): " + ", ".join(missing)
        )
    unexpected = sorted(stored_fields - expected_fields)
    if unexpected:
        raise ValueError(
            "replay policy has unsupported field(s): " + ", ".join(unexpected)
        )
    if stored.get("selection_schema_version") != SELECTION_SCHEMA_VERSION:
        raise ValueError(
            "unsupported selection_schema_version; expected "
            f"{SELECTION_SCHEMA_VERSION}"
        )
    if stored.get("asia_tiering") is not True:
        raise ValueError("production replay requires asia_tiering=true")


def load_replay_input(path: str | Path) -> dict[str, Any]:
    """Load a standalone replay bundle or follow a failure.json sibling reference."""

    source = Path(path)
    payload = _read_json(source)
    if isinstance(payload.get("results"), list):
        _validate_replay_bundle(payload)
        return payload

    replay = payload.get("replay")
    if not isinstance(replay, dict):
        raise ValueError("JSON has neither a results list nor a replay reference")
    filename = str(replay.get("results_file") or "")
    if not filename or Path(filename).name != filename:
        raise ValueError("failure.json replay reference must be a safe sibling basename")
    result_payload = _read_json(source.parent / filename)
    _validate_replay_bundle(result_payload)
    if replay.get("schema_version") != 1:
        raise ValueError("failure.json has an unsupported replay reference schema")
    if payload.get("main_sha") != result_payload.get("main_sha"):
        raise ValueError("failure.json and replay data have different main_sha values")
    if payload.get("source_sha256") != result_payload.get("source_sha256"):
        raise ValueError("failure.json and replay data have different source_sha256 values")
    if replay.get("run_id") != result_payload.get("run_id"):
        raise ValueError("failure.json and replay data have different run_id values")
    if replay.get("result_count") != result_payload.get("result_count"):
        raise ValueError("failure.json and replay data have different result counts")
    if not isinstance(replay.get("policy"), dict):
        raise ValueError("failure.json replay reference has no policy object")
    if replay["policy"] != result_payload.get("policy"):
        raise ValueError("failure.json and replay data have different policies")
    return result_payload


def _integer(policy: dict[str, Any], key: str) -> int:
    try:
        return int(policy[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"policy field {key!r} must be an integer") from exc


def _positive_float(policy: dict[str, Any], key: str) -> float:
    try:
        value = float(policy[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"policy field {key!r} must be numeric") from exc
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"policy field {key!r} must be greater than zero")
    return value


def _normalise_policy(
    payload: dict[str, Any], overrides: dict[str, Any] | None
) -> dict[str, Any]:
    defaults = replay_policy_snapshot()
    stored = payload.get("policy")
    if not isinstance(stored, dict):
        raise ValueError("replay bundle has no policy object")
    _validate_stored_policy(stored)
    defaults.update(stored)
    if overrides:
        explicit = {key: value for key, value in overrides.items() if value is not None}
        # Production currently uses the same strict quality line for Asia and
        # non-Asia. Keep the paired fields synchronized when the public CLI
        # overrides the shared strict thresholds.
        if "strict_min_success" in explicit:
            explicit.setdefault("non_asia_min_success", explicit["strict_min_success"])
        if "qualified_p90_ms" in explicit:
            explicit.setdefault("non_asia_p90_ms", explicit["qualified_p90_ms"])
        defaults.update(explicit)

    integer_fields = (
        "total_rounds",
        "strict_min_success",
        "fallback_min_success",
        "emergency_min_success",
        "non_asia_min_success",
        "elite_min_success",
        "base_target",
        "max_nodes",
        "non_asia_min",
        "non_asia_max",
        "emergency_max_count",
        "required_count",
    )
    policy = {**defaults, **{key: _integer(defaults, key) for key in integer_fields}}
    for key in (
        "qualified_p90_ms",
        "non_asia_p90_ms",
        "emergency_p90_ms",
        "elite_p90_ms",
    ):
        policy[key] = _positive_float(defaults, key)

    rounds = policy["total_rounds"]
    if not (
        0
        < policy["emergency_min_success"]
        < policy["fallback_min_success"]
        < policy["strict_min_success"]
        <= policy["elite_min_success"]
        <= rounds
    ):
        raise ValueError(
            "success thresholds must satisfy "
            "0 < emergency < fallback < strict <= elite <= total_rounds"
        )
    if policy["non_asia_min_success"] != policy["strict_min_success"]:
        raise ValueError("production replay requires equal strict Asia/non-Asia success lines")
    if policy["non_asia_p90_ms"] != policy["qualified_p90_ms"]:
        raise ValueError("production replay requires equal strict Asia/non-Asia P90 lines")
    if policy["elite_p90_ms"] > policy["qualified_p90_ms"]:
        raise ValueError("elite P90 cannot exceed the qualified P90")
    if not 0 < policy["base_target"] <= policy["max_nodes"]:
        raise ValueError("base_target must satisfy 0 < base_target <= max_nodes")
    if not (
        0
        <= policy["non_asia_min"]
        <= policy["non_asia_max"]
        <= policy["max_nodes"]
    ):
        raise ValueError("non-Asia limits must satisfy 0 <= min <= max <= max_nodes")
    if policy["non_asia_min"] > policy["base_target"]:
        raise ValueError("non_asia_min cannot exceed base_target")
    if policy["emergency_max_count"] < 0:
        raise ValueError("emergency_max_count cannot be negative")
    if not 0 < policy["required_count"] <= policy["max_nodes"]:
        raise ValueError("required_count must satisfy 0 < required_count <= max_nodes")
    return policy


def _metric(result: dict[str, Any], key: str) -> float | None:
    value = result.get(key)
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"result field {key!r} must be numeric or null") from exc
    if not math.isfinite(numeric) or numeric < 0:
        raise ValueError(f"result field {key!r} must be finite and non-negative")
    return numeric


def _normalise_results(payload: dict[str, Any]) -> list[dict[str, Any]]:
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        raise ValueError("replay JSON must contain a results list")

    summaries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_results):
        if not isinstance(raw, dict):
            raise ValueError(f"results[{index}] must be an object")
        node_id = str(raw.get("node_id") or "")
        if not re.fullmatch(r"n1_[0-9a-f]{24}", node_id):
            raise ValueError(f"results[{index}] has an invalid opaque node_id")
        if node_id in seen:
            raise ValueError(f"results[{index}] has a missing or duplicate node_id")
        seen.add(node_id)
        try:
            attempts = max(int(raw.get("attempts", 0)), 0)
            successes = max(int(raw.get("success_count", 0)), 0)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"results[{index}] has invalid attempt counts") from exc
        if successes > attempts:
            raise ValueError(f"results[{index}] has more successes than attempts")
        summaries.append(
            {
                # The production selector only needs a unique stable name. The
                # opaque node ID preserves that property without restoring the
                # original node name.
                "name": node_id,
                POLICY_NODE_ID_KEY: node_id,
                "preferred_asia": bool(raw.get("preferred_asia")),
                "attempts": attempts,
                "success_count": successes,
                "success_rate": round(successes / attempts, 4) if attempts else 0.0,
                "min_delay_ms": _metric(raw, "min_delay_ms"),
                "median_delay_ms": _metric(raw, "median_delay_ms"),
                "p90_delay_ms": _metric(raw, "p90_delay_ms"),
                "jitter_ms": _metric(raw, "jitter_ms"),
            }
        )
    return summaries


def _region_counts(items: Iterable[dict[str, Any]]) -> dict[str, int]:
    materialised = list(items)
    asia = sum(bool(item.get("preferred_asia")) for item in materialised)
    return {"asia": asia, "non_asia": len(materialised) - asia}


def _tier_counts(items: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {tier: 0 for tier in TIER_NAMES}
    for item in items:
        tier = str(item.get("qualification_tier") or item.get("selection_tier") or "")
        if tier in counts:
            counts[tier] += 1
    return counts


def replay_policy(
    payload: dict[str, Any], overrides: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Run the production tiered selector and return an audit-friendly summary."""

    policy = _normalise_policy(payload, overrides)
    summaries = _normalise_results(payload)
    incomplete_count = sum(
        int(item.get("attempts", 0)) != policy["total_rounds"] for item in summaries
    )

    selected: list[dict[str, Any]] = []
    qualified: list[dict[str, Any]] = []
    if not incomplete_count:
        rounds = policy["total_rounds"]
        selected, qualified = select_stable_results(
            summaries,
            policy["strict_min_success"] / rounds,
            policy["strict_min_success"] / rounds,
            policy["qualified_p90_ms"],
            policy["base_target"],
            policy["max_nodes"],
            policy["non_asia_min"],
            policy["non_asia_max"],
            policy["elite_min_success"] / rounds,
            policy["elite_p90_ms"],
            asia_tiering=True,
            total_rounds=rounds,
            asia_fallback_min_success=policy["fallback_min_success"],
            asia_emergency_min_success=policy["emergency_min_success"],
            asia_emergency_max_p90_ms=policy["emergency_p90_ms"],
            asia_emergency_max_count=policy["emergency_max_count"],
        )

    required = policy["required_count"]
    reasons: list[dict[str, str]] = []
    if incomplete_count:
        reasons.append(
            {
                "code": "incomplete_probe_rounds",
                "message": (
                    f"{incomplete_count} result(s) do not contain exactly "
                    f"{policy['total_rounds']} attempts"
                ),
            }
        )
    else:
        if len(selected) < required:
            reasons.append(
                {
                    "code": "selectable_count_below_publish_floor",
                    "message": (
                        f"only {len(selected)} result(s) are selectable after tier and "
                        f"non-Asia cap rules; {required} are required"
                    ),
                }
            )
        if len(qualified) < required:
            reasons.append(
                {
                    "code": "qualified_count_below_publish_floor",
                    "message": f"only {len(qualified)} result(s) qualify; {required} are required",
                }
            )

    selected_regions = _region_counts(selected)
    qualified_regions = _region_counts(qualified)
    return {
        "passed": not reasons,
        "failure_reason_code": reasons[0]["code"] if reasons else "",
        "failure_reason": reasons[0]["message"] if reasons else "",
        "failure_reasons": reasons,
        "policy": policy,
        "input_count": len(summaries),
        "complete_count": len(summaries) - incomplete_count,
        "incomplete_count": incomplete_count,
        "qualified_count": len(qualified),
        "qualified_asia_count": qualified_regions["asia"],
        "qualified_non_asia_count": qualified_regions["non_asia"],
        "selected_count": len(selected),
        "selected_asia_count": selected_regions["asia"],
        "selected_non_asia_count": selected_regions["non_asia"],
        "qualification_tier_counts": _tier_counts(qualified),
        "selected_tier_counts": _tier_counts(selected),
        "selected_node_ids": [str(item["name"]) for item in selected],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Replay CNB selection from redacted-probe-results.json (or a colocated "
            "failure.json that references it)."
        )
    )
    parser.add_argument("input", help="Path to redacted-probe-results.json or failure.json")
    parser.add_argument("--total-rounds", type=int)
    parser.add_argument("--strict-min-success", type=int)
    parser.add_argument("--fallback-min-success", type=int)
    parser.add_argument("--emergency-min-success", type=int)
    parser.add_argument("--qualified-p90-ms", type=float)
    parser.add_argument("--emergency-p90-ms", type=float)
    parser.add_argument("--elite-min-success", type=int)
    parser.add_argument("--elite-p90-ms", type=float)
    parser.add_argument("--base-target", type=int)
    parser.add_argument("--max-nodes", type=int)
    parser.add_argument("--non-asia-min", type=int)
    parser.add_argument("--non-asia-max", type=int)
    parser.add_argument("--emergency-max-count", type=int)
    parser.add_argument("--required-count", type=int)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    overrides = {
        key: getattr(args, key)
        for key in (
            "total_rounds",
            "strict_min_success",
            "fallback_min_success",
            "emergency_min_success",
            "qualified_p90_ms",
            "emergency_p90_ms",
            "elite_min_success",
            "elite_p90_ms",
            "base_target",
            "max_nodes",
            "non_asia_min",
            "non_asia_max",
            "emergency_max_count",
            "required_count",
        )
    }
    try:
        report = replay_policy(load_replay_input(args.input), overrides)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    print(
        f"Input {report['input_count']}; complete {report['complete_count']}; "
        f"qualified {report['qualified_count']} "
        f"(Asia {report['qualified_asia_count']}, non-Asia {report['qualified_non_asia_count']})."
    )
    print(
        f"Selected {report['selected_count']} "
        f"(Asia {report['selected_asia_count']}, non-Asia {report['selected_non_asia_count']})."
    )
    print(
        "Selected tiers: "
        + ", ".join(
            f"{tier}={count}" for tier, count in report["selected_tier_counts"].items()
        )
    )
    if report["passed"]:
        print("Result: PASS; the configured publish floor is reachable.")
    else:
        print(
            f"Result: FAIL [{report['failure_reason_code']}]: "
            f"{report['failure_reason']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
