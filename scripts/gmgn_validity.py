#!/usr/bin/env python3
"""Pure GMGN V2 valid-run gate.

The validator consumes only redacted shard evidence.  It never reads proxy
credentials, raw runner IPs, or HMAC keys, and it never writes accepted input
unless every system-accident gate passes.
"""

from __future__ import annotations

import copy
import ipaddress
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any

from scripts.gmgn_measurement import (
    ERROR_CATEGORIES,
    MANIFEST_SCHEMA_VERSION,
    MINIMUM_OBSERVATION_WINDOW_SECONDS,
    REDACTED_FRAGMENT_KIND,
    REDACTED_FRAGMENT_SCHEMA_VERSION,
    SHARD_COUNT,
    TOTAL_ROUNDS,
    VALIDITY_POLICY_VERSION,
    VALIDITY_RESULT_KIND,
    VALIDITY_RESULT_SCHEMA_VERSION,
    MeasurementError,
    candidate_ids_sha256,
    canonical_json_sha256,
    validate_manifest_v3,
)
from scripts.proxy_identity import validate_public_id


IPV4_TEXT_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")


def contains_ip_literal(value: str) -> bool:
    for match in IPV4_TEXT_RE.findall(value):
        try:
            ipaddress.ip_address(match)
            return True
        except ValueError:
            pass
    for token in re.findall(r"[0-9A-Fa-f:]{2,}", value):
        if ":" not in token:
            continue
        try:
            ipaddress.ip_address(token.strip("[]"))
            return True
        except ValueError:
            pass
    return False


REDACTED_FRAGMENT_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "manifest_sha256",
        "run_id",
        "source_sha256",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "candidate_metadata_schema_version",
        "candidate_metadata_count",
        "identity_key_version",
        "identity_epoch",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "minimum_observation_window_seconds",
        "shard_count",
        "workers_per_shard",
        "stagger_seconds",
        "validity_policy_version",
        "scheduler_policy_version",
        "canary_policy_version",
        "canary_set_sha256",
        "python_version",
        "pyyaml_version",
        "mihomo_version",
        "mihomo_sha256",
        "resolver_policy_version",
        "network_guard_policy_version",
        "shard_index",
        "candidate_count",
        "candidate_ids_sha256",
        "results",
        "round_trends",
        "controller",
        "control",
        "canaries",
        "egress",
    }
)

CONTROLLER_FIELDS = frozenset(
    {"healthy_check_count", "unhealthy_count", "version", "mihomo_sha256"}
)
REDACTED_RESULT_FIELDS = frozenset(
    {
        "candidate_id",
        "attempt_count",
        "response_count",
        "within_1000_count",
        "slow_response_count",
        "no_result_count",
        "min_delay_ms",
        "median_delay_ms",
        "p90_delay_ms",
        "max_delay_ms",
        "jitter_ms",
        "first_half_within_1000_count",
        "second_half_within_1000_count",
        "five_round_within_1000_counts",
        "observation_span_seconds",
        "error_counts",
    }
)
ROUND_TREND_FIELDS = frozenset(
    {
        "round",
        "attempt_count",
        "within_1000_count",
        "slow_response_count",
        "no_result_count",
        "error_counts",
    }
)
CONTROL_FIELDS = frozenset(
    {"attempt_count", "success_count", "failure_count", "max_consecutive_failures", "median_delay_ms"}
)
CANARY_FIELDS = frozenset({"canary_id", *CONTROL_FIELDS})
EGRESS_FIELDS = frozenset({"before", "after"})
EGRESS_POINT_FIELDS = frozenset({"country", "region", "org", "exit_id"})

VALIDITY_REASONS = frozenset(
    {
        "manifest_invalid",
        "fragment_contract_mismatch",
        "shard_incomplete",
        "candidate_coverage_mismatch",
        "candidate_rounds_incomplete",
        "observation_window_short",
        "controller_unhealthy",
        "runtime_mismatch",
        "egress_not_cn",
        "egress_changed",
        "egress_region_mismatch",
        "control_below_threshold",
        "control_consecutive_failures",
        "canary_below_threshold",
        "canary_success_skew",
        "canary_latency_skew",
        "target_status_global_incident",
        "target_status_round_incident",
        "shard_system_error_skew",
    }
)


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise MeasurementError(f"{label} must be a non-negative integer")
    return value


def _finite_or_none(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise MeasurementError(f"{label} must be finite or null")
    return float(value)


def _validate_control_summary(value: Mapping[str, Any], label: str) -> None:
    expected_fields = CANARY_FIELDS if label == "canary" else CONTROL_FIELDS
    if not isinstance(value, Mapping) or frozenset(value) != expected_fields:
        raise MeasurementError(f"{label} evidence is invalid")
    attempts = _non_negative_int(value["attempt_count"], f"{label} attempts")
    success = _non_negative_int(value["success_count"], f"{label} successes")
    failure = _non_negative_int(value["failure_count"], f"{label} failures")
    consecutive = _non_negative_int(
        value["max_consecutive_failures"], f"{label} consecutive failures"
    )
    median = _finite_or_none(value["median_delay_ms"], f"{label} median")
    if attempts != TOTAL_ROUNDS or success + failure != attempts or consecutive > failure:
        raise MeasurementError(f"{label} accounting mismatch")
    if (success == 0) != (median is None):
        raise MeasurementError(f"{label} median accounting mismatch")
    if median is not None and median <= 0:
        raise MeasurementError(f"{label} median accounting mismatch")


def validate_redacted_fragment(
    manifest: Mapping[str, Any], fragment: Mapping[str, Any]
) -> dict[str, Any]:
    normalized_manifest = validate_manifest_v3(manifest)
    if not isinstance(fragment, Mapping) or frozenset(fragment) != REDACTED_FRAGMENT_FIELDS:
        raise MeasurementError("redacted fragment fields are incomplete or unexpected")
    value = dict(fragment)
    if value["kind"] != REDACTED_FRAGMENT_KIND or value["schema_version"] != REDACTED_FRAGMENT_SCHEMA_VERSION:
        raise MeasurementError("unsupported redacted fragment")
    if value["manifest_sha256"] != canonical_json_sha256(normalized_manifest):
        raise MeasurementError("fragment manifest hash mismatch")
    shared = (
        "run_id",
        "source_sha256",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "candidate_metadata_schema_version",
        "candidate_metadata_count",
        "identity_key_version",
        "identity_epoch",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "minimum_observation_window_seconds",
        "shard_count",
        "workers_per_shard",
        "validity_policy_version",
        "scheduler_policy_version",
        "canary_policy_version",
        "canary_set_sha256",
        "python_version",
        "pyyaml_version",
        "mihomo_version",
        "mihomo_sha256",
        "resolver_policy_version",
        "network_guard_policy_version",
    )
    for field in shared:
        if value[field] != normalized_manifest[field]:
            raise MeasurementError(f"fragment {field} mismatch")
    index = _non_negative_int(value["shard_index"], "shard_index")
    if index >= SHARD_COUNT:
        raise MeasurementError("fragment shard_index is invalid")
    expected_shard = normalized_manifest["shards"][index]
    if value["stagger_seconds"] != expected_shard["stagger_seconds"]:
        raise MeasurementError("fragment shard stagger mismatch")
    count = _non_negative_int(value["candidate_count"], "candidate_count")
    if count != expected_shard["candidate_count"] or value["candidate_ids_sha256"] != expected_shard["candidate_ids_sha256"]:
        raise MeasurementError("fragment shard candidate contract mismatch")
    results = value["results"]
    if not isinstance(results, list) or len(results) != count:
        raise MeasurementError("fragment result count mismatch")
    ids: list[str] = []
    result_totals = {
        "within": 0,
        "slow": 0,
        "no_result": 0,
        "first_half": 0,
        "second_half": 0,
        "blocks": [0, 0, 0, 0],
        "errors": {category: 0 for category in ERROR_CATEGORIES},
    }
    for result in results:
        if not isinstance(result, Mapping) or frozenset(result) != REDACTED_RESULT_FIELDS:
            raise MeasurementError("fragment result fields are incomplete or unexpected")
        candidate_id = validate_public_id(result.get("candidate_id"), "candidate")
        ids.append(candidate_id)
        attempts = _non_negative_int(result.get("attempt_count"), "attempt_count")
        response = _non_negative_int(result.get("response_count"), "response_count")
        within = _non_negative_int(result.get("within_1000_count"), "within_1000_count")
        slow = _non_negative_int(result.get("slow_response_count"), "slow_response_count")
        no_result = _non_negative_int(result.get("no_result_count"), "no_result_count")
        if attempts != TOTAL_ROUNDS or response + no_result != attempts or within + slow != response:
            raise MeasurementError("fragment result accounting mismatch")
        blocks = result.get("five_round_within_1000_counts")
        if not isinstance(blocks, list) or len(blocks) != 4:
            raise MeasurementError("fragment result five-round accounting mismatch")
        normalized_blocks = [_non_negative_int(item, "five-round count") for item in blocks]
        if any(item > 5 for item in normalized_blocks) or sum(normalized_blocks) != within:
            raise MeasurementError("fragment result five-round accounting mismatch")
        first_half = _non_negative_int(
            result.get("first_half_within_1000_count"), "first half"
        )
        second_half = _non_negative_int(
            result.get("second_half_within_1000_count"), "second half"
        )
        if first_half > 10 or second_half > 10 or first_half + second_half != within:
            raise MeasurementError("fragment result half accounting mismatch")
        span = _finite_or_none(result.get("observation_span_seconds"), "observation span")
        if span is None or span < 0:
            raise MeasurementError("fragment result observation span is invalid")
        errors = result.get("error_counts")
        if not isinstance(errors, Mapping) or set(errors) != set(ERROR_CATEGORIES):
            raise MeasurementError("fragment result error categories mismatch")
        if sum(_non_negative_int(errors[name], name) for name in ERROR_CATEGORIES) != no_result:
            raise MeasurementError("fragment result error accounting mismatch")
        latency_fields = {
            name: _finite_or_none(result.get(name), name)
            for name in (
                "min_delay_ms",
                "median_delay_ms",
                "p90_delay_ms",
                "max_delay_ms",
                "jitter_ms",
            )
        }
        if response == 0:
            if any(metric is not None for metric in latency_fields.values()):
                raise MeasurementError("fragment result latency accounting mismatch")
        else:
            if any(metric is None for metric in latency_fields.values()):
                raise MeasurementError("fragment result latency accounting mismatch")
            minimum = float(latency_fields["min_delay_ms"])
            median = float(latency_fields["median_delay_ms"])
            p90 = float(latency_fields["p90_delay_ms"])
            maximum = float(latency_fields["max_delay_ms"])
            jitter = float(latency_fields["jitter_ms"])
            if minimum <= 0 or not minimum <= median <= p90 <= maximum or jitter < 0:
                raise MeasurementError("fragment result latency accounting mismatch")
        result_totals["within"] += within
        result_totals["slow"] += slow
        result_totals["no_result"] += no_result
        result_totals["first_half"] += first_half
        result_totals["second_half"] += second_half
        for block_index, block_count in enumerate(normalized_blocks):
            result_totals["blocks"][block_index] += block_count
        for name in ERROR_CATEGORIES:
            result_totals["errors"][name] += int(errors[name])
    if len(ids) != len(set(ids)) or candidate_ids_sha256(sorted(ids)) != value["candidate_ids_sha256"]:
        raise MeasurementError("fragment candidate IDs mismatch")
    trends = value["round_trends"]
    if not isinstance(trends, list) or len(trends) != TOTAL_ROUNDS:
        raise MeasurementError("fragment round trends are incomplete")
    trend_totals = {
        "within": 0,
        "slow": 0,
        "no_result": 0,
        "first_half": 0,
        "second_half": 0,
        "blocks": [0, 0, 0, 0],
        "errors": {category: 0 for category in ERROR_CATEGORIES},
    }
    for round_number, trend in enumerate(trends, start=1):
        if not isinstance(trend, Mapping) or frozenset(trend) != ROUND_TREND_FIELDS or int(trend.get("round", 0)) != round_number:
            raise MeasurementError("fragment round trend order is invalid")
        attempts = _non_negative_int(trend.get("attempt_count"), "round attempts")
        within = _non_negative_int(trend.get("within_1000_count"), "round within")
        slow = _non_negative_int(trend.get("slow_response_count"), "round slow")
        no_result = _non_negative_int(trend.get("no_result_count"), "round no-result")
        errors = trend.get("error_counts")
        if attempts != count or within + slow + no_result != attempts:
            raise MeasurementError("fragment round accounting mismatch")
        if not isinstance(errors, Mapping) or set(errors) != set(ERROR_CATEGORIES) or sum(_non_negative_int(errors[name], name) for name in ERROR_CATEGORIES) != no_result:
            raise MeasurementError("fragment round error accounting mismatch")
        trend_totals["within"] += within
        trend_totals["slow"] += slow
        trend_totals["no_result"] += no_result
        half_key = "first_half" if round_number <= 10 else "second_half"
        trend_totals[half_key] += within
        trend_totals["blocks"][(round_number - 1) // 5] += within
        for name in ERROR_CATEGORIES:
            trend_totals["errors"][name] += int(errors[name])
    if trend_totals != result_totals:
        raise MeasurementError("fragment results and round trends do not conserve totals")
    controller = value["controller"]
    if not isinstance(controller, Mapping) or frozenset(controller) != CONTROLLER_FIELDS:
        raise MeasurementError("fragment controller evidence is invalid")
    if controller["mihomo_sha256"] != normalized_manifest["mihomo_sha256"]:
        raise MeasurementError("fragment controller runtime mismatch")
    healthy_checks = _non_negative_int(
        controller["healthy_check_count"], "healthy_check_count"
    )
    unhealthy = _non_negative_int(controller["unhealthy_count"], "unhealthy_count")
    if (
        healthy_checks != TOTAL_ROUNDS * 2
        or unhealthy > healthy_checks
        or controller["version"] != normalized_manifest["mihomo_version"]
    ):
        raise MeasurementError("fragment controller evidence is incomplete or inconsistent")
    control = value["control"]
    _validate_control_summary(control, "control")
    canaries = value["canaries"]
    if not isinstance(canaries, list) or not canaries:
        raise MeasurementError("fragment canary evidence is missing")
    canary_ids: list[str] = []
    for canary in canaries:
        _validate_control_summary(canary, "canary")
        canary_id = str(canary["canary_id"]).strip()
        if not canary_id:
            raise MeasurementError("fragment canary ID is missing")
        canary_ids.append(canary_id)
    if len(canary_ids) != len(set(canary_ids)):
        raise MeasurementError("fragment canary IDs are duplicated")
    if canonical_json_sha256(sorted(canary_ids)) != normalized_manifest["canary_set_sha256"]:
        raise MeasurementError("fragment canary set hash mismatch")
    egress = value["egress"]
    if not isinstance(egress, Mapping) or frozenset(egress) != EGRESS_FIELDS:
        raise MeasurementError("fragment egress evidence is invalid")
    for point in (egress["before"], egress["after"]):
        if not isinstance(point, Mapping) or frozenset(point) != EGRESS_POINT_FIELDS:
            raise MeasurementError("fragment egress point is invalid")
        validate_public_id(point["exit_id"], "exit")
        for field in ("country", "region", "org"):
            if not isinstance(point[field], str) or not point[field].strip():
                raise MeasurementError("fragment egress metadata is incomplete")
        if contains_ip_literal(point["region"]):
            raise MeasurementError("fragment egress region contains an IP address")
    return value


def _invalid(run_id: str, reasons: set[str], metrics: dict[str, Any]) -> dict[str, Any]:
    unknown = reasons - VALIDITY_REASONS
    if unknown:
        raise MeasurementError("validator produced an unknown reason")
    return {
        "kind": VALIDITY_RESULT_KIND,
        "schema_version": VALIDITY_RESULT_SCHEMA_VERSION,
        "run_id": run_id,
        "valid_run": not reasons,
        "reasons": sorted(reasons),
        "metrics": metrics,
    }


def validate_run(
    manifest: Mapping[str, Any], fragments: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    reasons: set[str] = set()
    metrics: dict[str, Any] = {}
    try:
        normalized_manifest = validate_manifest_v3(manifest)
    except Exception:
        return _invalid(str(manifest.get("run_id", "")) if isinstance(manifest, Mapping) else "", {"manifest_invalid"}, metrics)
    run_id = str(normalized_manifest["run_id"])
    if len(fragments) != SHARD_COUNT:
        reasons.add("shard_incomplete")
    normalized: list[dict[str, Any]] = []
    for fragment in fragments:
        try:
            normalized.append(validate_redacted_fragment(normalized_manifest, fragment))
        except Exception:
            reasons.add("fragment_contract_mismatch")
    indices = [int(item["shard_index"]) for item in normalized]
    if len(indices) != SHARD_COUNT or sorted(indices) != list(range(SHARD_COUNT)):
        reasons.add("shard_incomplete")
    if reasons & {"fragment_contract_mismatch", "shard_incomplete"}:
        return _invalid(run_id, reasons, metrics)

    all_results = [result for fragment in normalized for result in fragment["results"]]
    ids = [str(result["candidate_id"]) for result in all_results]
    if len(ids) != normalized_manifest["candidate_count"] or len(ids) != len(set(ids)):
        reasons.add("candidate_coverage_mismatch")
    short_spans = sum(float(result["observation_span_seconds"]) + 1e-6 < MINIMUM_OBSERVATION_WINDOW_SECONDS for result in all_results)
    if short_spans:
        reasons.add("observation_window_short")
    if any(int(fragment["controller"]["unhealthy_count"]) for fragment in normalized):
        reasons.add("controller_unhealthy")
    versions = {str(fragment["controller"]["version"]) for fragment in normalized}
    if len(versions) != 1:
        reasons.add("runtime_mismatch")

    regions: set[str] = set()
    for fragment in normalized:
        before = fragment["egress"]["before"]
        after = fragment["egress"]["after"]
        if str(before["country"]).upper() != "CN" or str(after["country"]).upper() != "CN":
            reasons.add("egress_not_cn")
        if before["exit_id"] != after["exit_id"]:
            reasons.add("egress_changed")
        regions.add(str(before["region"]).strip().casefold())
        regions.add(str(after["region"]).strip().casefold())
    if "" in regions or len(regions) != 1:
        reasons.add("egress_region_mismatch")

    canary_by_id: dict[str, list[Mapping[str, Any]]] = {}
    for fragment in normalized:
        control = fragment["control"]
        if int(control["attempt_count"]) != TOTAL_ROUNDS or int(control["success_count"]) < 18:
            reasons.add("control_below_threshold")
        if int(control["max_consecutive_failures"]) >= 3:
            reasons.add("control_consecutive_failures")
        for canary in fragment["canaries"]:
            canary_by_id.setdefault(str(canary["canary_id"]), []).append(canary)
            if int(canary["attempt_count"]) != TOTAL_ROUNDS or int(canary["success_count"]) < 16:
                reasons.add("canary_below_threshold")
    for values in canary_by_id.values():
        if len(values) != SHARD_COUNT:
            reasons.add("fragment_contract_mismatch")
            continue
        successes = [int(value["success_count"]) for value in values]
        if max(successes) - min(successes) > 4:
            reasons.add("canary_success_skew")
        medians = [float(value["median_delay_ms"]) for value in values if value["median_delay_ms"] is not None]
        if len(medians) != SHARD_COUNT:
            reasons.add("canary_latency_skew")
        else:
            fastest = min(medians)
            if max(medians) - fastest > max(300.0, fastest * 0.5):
                reasons.add("canary_latency_skew")

    total_attempts = len(all_results) * TOTAL_ROUNDS
    global_target_errors = 0
    per_round_target_errors = [0] * TOTAL_ROUNDS
    per_round_attempts = [0] * TOTAL_ROUNDS
    shard_system_rates: list[float] = []
    for fragment in normalized:
        shard_errors = 0
        shard_attempts = int(fragment["candidate_count"]) * TOTAL_ROUNDS
        for index, trend in enumerate(fragment["round_trends"]):
            errors = trend["error_counts"]
            count = int(errors["target_403"]) + int(errors["target_429"])
            global_target_errors += count
            shard_errors += count + int(errors["controller_request"]) + int(errors["controller_unhealthy"])
            per_round_target_errors[index] += count
            per_round_attempts[index] += int(trend["attempt_count"])
        shard_system_rates.append(shard_errors / shard_attempts if shard_attempts else 0.0)
    global_rate = global_target_errors / total_attempts if total_attempts else 1.0
    if global_rate > 0.02 + 1e-12:
        reasons.add("target_status_global_incident")
    if any(errors / attempts >= 0.10 - 1e-12 for errors, attempts in zip(per_round_target_errors, per_round_attempts) if attempts):
        reasons.add("target_status_round_incident")
    if max(shard_system_rates, default=0.0) - min(shard_system_rates, default=0.0) > 0.05:
        reasons.add("shard_system_error_skew")
    metrics.update(
        {
            "candidate_count": len(all_results),
            "short_observation_count": short_spans,
            "target_403_429_rate": round(global_rate, 6),
            "runner_region": next(iter(regions)) if len(regions) == 1 else "",
        }
    )
    return _invalid(run_id, reasons, metrics)


def accepted_measurement(
    manifest: Mapping[str, Any], fragments: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    result = validate_run(manifest, fragments)
    if not result["valid_run"]:
        raise MeasurementError("invalid GMGN run cannot produce accepted measurement input")
    return {
        "kind": "cnb-gmgn-accepted-measurement",
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "source_sha256": manifest["source_sha256"],
        "main_sha": manifest["main_sha"],
        "profile_sha256": manifest["profile_sha256"],
        "candidate_metadata_sha256": manifest["candidate_metadata_sha256"],
        "candidate_metadata_schema_version": manifest[
            "candidate_metadata_schema_version"
        ],
        "candidate_metadata_count": manifest["candidate_metadata_count"],
        "identity_key_version": manifest["identity_key_version"],
        "identity_epoch": manifest["identity_epoch"],
        "validity_policy_version": VALIDITY_POLICY_VERSION,
        "manifest_sha256": canonical_json_sha256(dict(manifest)),
        "fragment_sha256": [canonical_json_sha256(dict(item)) for item in sorted(fragments, key=lambda item: int(item["shard_index"]))],
        "results": [
            copy.deepcopy(result)
            for fragment in sorted(fragments, key=lambda item: int(item["shard_index"]))
            for result in fragment["results"]
        ],
    }


__all__ = [
    "CANARY_FIELDS",
    "CONTROL_FIELDS",
    "EGRESS_POINT_FIELDS",
    "REDACTED_FRAGMENT_FIELDS",
    "REDACTED_RESULT_FIELDS",
    "ROUND_TREND_FIELDS",
    "VALIDITY_REASONS",
    "accepted_measurement",
    "canonical_json_sha256",
    "contains_ip_literal",
    "validate_redacted_fragment",
    "validate_run",
]
