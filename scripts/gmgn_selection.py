#!/usr/bin/env python3
"""GMGN V2 pure selection, diversity, grouping, and redacted diagnostics."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

import yaml

from scripts.candidate_contract import CANDIDATE_METADATA_SCHEMA_VERSION
from scripts.candidate_snapshot import CANDIDATE_FIELDS as C1_CANDIDATE_METADATA_FIELDS
from scripts.candidate_sources import ENDPOINT_SAFETY_POLICY_VERSION, SOURCE_ID_RE, utc_timestamp
from scripts.gmgn_history import (
    allocate_stable_output_names,
    validate_history,
)
from scripts.gmgn_region import (
    REGION_POLICY_VERSION,
    TARGET_ASIA_REGIONS,
    validate_region_decision,
)
from scripts.gmgn_measurement import ERROR_CATEGORIES, VALIDITY_POLICY_VERSION
from scripts.gmgn_validity import REDACTED_RESULT_FIELDS
from scripts.pipeline_utils import BUILTIN_PROXY_NAMES, dump_clash_yaml
from scripts.proxy_identity import validate_identity_version, validate_public_id


SELECTION_POLICY_VERSION = "gmgn-selection-v3"
SELECTION_INPUT_KIND = "cnb-gmgn-selection-input"
SELECTION_INPUT_SCHEMA_VERSION = 1
SELECTION_RESULT_KIND = "cnb-gmgn-selection-result"
SELECTION_RESULT_SCHEMA_VERSION = 1
NODE_STATUS_KIND = "cnb-gmgn-node-status"
NODE_STATUS_SCHEMA_VERSION = 2
DESIRED_CAPACITY = 80
MAX_NODES = 150
NON_ASIA_BASE_LIMIT = 10
NON_ASIA_MAX = 20

GROUP_MANUAL_PRIORITY = "👆手动优先测速"
GROUP_HK = "🇭🇰香港"
GROUP_JP = "🇯🇵日本"
GROUP_KR = "🇰🇷韩国"
GROUP_SG = "🇸🇬新加坡"
GROUP_TW = "🇹🇼台湾"
GROUP_ASIA_BACKUP = "🌏亚洲候补"
GROUP_NON_ASIA = "🌍非亚洲稳定"
GROUP_ALL = "📦全部入选"
GROUP_AUTO = "GMGN自动"
V2_GROUP_NAMES = (
    GROUP_MANUAL_PRIORITY,
    GROUP_HK,
    GROUP_JP,
    GROUP_KR,
    GROUP_SG,
    GROUP_TW,
    GROUP_ASIA_BACKUP,
    GROUP_NON_ASIA,
    GROUP_ALL,
    GROUP_AUTO,
)
REGION_GROUPS = {
    "HK": GROUP_HK,
    "JP": GROUP_JP,
    "KR": GROUP_KR,
    "SG": GROUP_SG,
    "TW": GROUP_TW,
}

_SELECTION_INPUT_FIELDS = frozenset(
    {"kind", "schema_version", "snapshot", "accepted_measurement", "history", "region_decisions"}
)
_SNAPSHOT_FIELDS = frozenset(
    {
        "snapshot_id",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "candidate_metadata_schema_version",
        "identity_key_version",
        "identity_epoch",
        "candidates",
    }
)
_SNAPSHOT_CANDIDATE_FIELDS = frozenset({"candidate_id", "proxy", "metadata"})
_ACCEPTED_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "source_sha256",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "candidate_metadata_schema_version",
        "candidate_metadata_count",
        "identity_key_version",
        "identity_epoch",
        "validity_policy_version",
        "manifest_sha256",
        "fragment_sha256",
        "results",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAIN_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
_SNAPSHOT_ID_RE = re.compile(r"^candidate_[0-9a-f]{24}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REGION_EVIDENCE_RE = re.compile(
    r"(?:name_hint|source_hint):(HK|JP|KR|SG|TW)|explicit:asia_keep"
)
_TIERS = frozenset(
    {"asia_core", "asia_flexible", "asia_manual_candidate", "history_protected", "non_asia_stable"}
)


class SelectionError(ValueError):
    """The V2 selection input or result violates the frozen contract."""


def _strict_mapping(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != fields:
        raise SelectionError(f"{label} fields are incomplete or unexpected")
    return dict(value)


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SelectionError(f"{label} must be a non-negative integer")
    return value


def _finite_optional(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        raise SelectionError(f"{label} must be finite or null")
    return float(value)


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise SelectionError(f"{label} is malformed")
    return value


def _normalize_measurement(raw: Any) -> dict[str, Any]:
    value = _strict_mapping(raw, REDACTED_RESULT_FIELDS, "accepted node measurement")
    candidate_id = validate_public_id(value["candidate_id"], "candidate")
    attempt_count = _non_negative_int(value["attempt_count"], "attempt_count")
    response_count = _non_negative_int(value["response_count"], "response_count")
    within = _non_negative_int(value["within_1000_count"], "within_1000_count")
    slow = _non_negative_int(value["slow_response_count"], "slow_response_count")
    no_result = _non_negative_int(value["no_result_count"], "no_result_count")
    first = _non_negative_int(
        value["first_half_within_1000_count"], "first_half_within_1000_count"
    )
    second = _non_negative_int(
        value["second_half_within_1000_count"], "second_half_within_1000_count"
    )
    blocks = value["five_round_within_1000_counts"]
    if (
        attempt_count != 20
        or response_count + no_result != 20
        or within + slow != response_count
        or first + second != within
        or first > 10
        or second > 10
        or not isinstance(blocks, list)
        or len(blocks) != 4
        or any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 5 for item in blocks)
        or sum(blocks) != within
        or sum(blocks[:2]) != first
        or sum(blocks[2:]) != second
    ):
        raise SelectionError("accepted node measurement counts are inconsistent")
    metrics = {
        name: _finite_optional(value[name], name)
        for name in ("min_delay_ms", "median_delay_ms", "p90_delay_ms", "max_delay_ms", "jitter_ms")
    }
    if response_count == 0 and any(item is not None for item in metrics.values()):
        raise SelectionError("zero-response measurement contains delay metrics")
    if response_count > 0 and any(item is None for item in metrics.values()):
        raise SelectionError("responsive measurement is missing delay metrics")
    if response_count > 0 and not (
        0 < metrics["min_delay_ms"] <= metrics["median_delay_ms"] <= metrics["p90_delay_ms"] <= metrics["max_delay_ms"]
        and metrics["jitter_ms"] >= 0
    ):
        raise SelectionError("accepted node delay metrics are inconsistent")
    error_counts = value["error_counts"]
    if not isinstance(error_counts, Mapping) or set(error_counts) != set(ERROR_CATEGORIES):
        raise SelectionError("accepted node error categories are inconsistent")
    normalized_errors = {
        name: _non_negative_int(error_counts[name], f"error_counts.{name}")
        for name in ERROR_CATEGORIES
    }
    if sum(normalized_errors.values()) != no_result:
        raise SelectionError("accepted node error counts do not match no-result attempts")
    span = _finite_optional(value["observation_span_seconds"], "observation_span_seconds")
    if span is None or span < 900:
        raise SelectionError("accepted node observation window is too short")
    return {
        **copy.deepcopy(value),
        "candidate_id": candidate_id,
        "attempt_count": attempt_count,
        "response_count": response_count,
        "within_1000_count": within,
        "slow_response_count": slow,
        "no_result_count": no_result,
        "first_half_within_1000_count": first,
        "second_half_within_1000_count": second,
        "five_round_within_1000_counts": list(blocks),
        "error_counts": normalized_errors,
        **metrics,
        "observation_span_seconds": span,
    }


def _candidate_alias(metadata: Mapping[str, Any], proxy: Mapping[str, Any]) -> str:
    aliases = metadata.get("aliases")
    if isinstance(aliases, list):
        for alias in aliases:
            if isinstance(alias, str) and alias.strip():
                return alias
    return str(proxy.get("name") or "Node")


def snapshot_from_candidate_snapshot(snapshot: Any) -> dict[str, Any]:
    """Project a validated C1 CandidateSnapshot into the private C4 handoff."""

    required = (
        "snapshot_id",
        "main_sha",
        "profile_sha256",
        "metadata_sha256",
        "identity_key_version",
        "identity_epoch",
        "ordered_candidates",
        "metadata",
    )
    if any(not hasattr(snapshot, field) for field in required):
        raise SelectionError("validated CandidateSnapshot object is required")
    records: list[dict[str, Any]] = []
    for entry in snapshot.ordered_candidates:
        records.append(
            {
                "candidate_id": entry.candidate_id,
                "proxy": copy.deepcopy(entry.proxy),
                "metadata": copy.deepcopy(entry.metadata),
            }
        )
    return {
        "snapshot_id": snapshot.snapshot_id,
        "main_sha": snapshot.main_sha,
        "profile_sha256": snapshot.profile_sha256,
        "candidate_metadata_sha256": snapshot.metadata_sha256,
        "candidate_metadata_schema_version": snapshot.metadata["schema_version"],
        "identity_key_version": snapshot.identity_key_version,
        "identity_epoch": snapshot.identity_epoch,
        "candidates": records,
    }


def build_selection_input(
    snapshot: Any,
    accepted_measurement: Mapping[str, Any],
    history: Mapping[str, Any],
    region_decisions: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    value = {
        "kind": SELECTION_INPUT_KIND,
        "schema_version": SELECTION_INPUT_SCHEMA_VERSION,
        "snapshot": snapshot_from_candidate_snapshot(snapshot),
        "accepted_measurement": copy.deepcopy(dict(accepted_measurement)),
        "history": copy.deepcopy(dict(history)),
        "region_decisions": copy.deepcopy(dict(region_decisions)),
    }
    return validate_selection_input(value)


def validate_selection_input(raw: Any) -> dict[str, Any]:
    value = _strict_mapping(raw, _SELECTION_INPUT_FIELDS, "selection input")
    if value["kind"] != SELECTION_INPUT_KIND or value["schema_version"] != SELECTION_INPUT_SCHEMA_VERSION:
        raise SelectionError("selection input kind or schema is unsupported")
    snapshot = _strict_mapping(value["snapshot"], _SNAPSHOT_FIELDS, "selection snapshot")
    if not _SNAPSHOT_ID_RE.fullmatch(str(snapshot["snapshot_id"])):
        raise SelectionError("selection snapshot ID is malformed")
    if not _MAIN_SHA_RE.fullmatch(str(snapshot["main_sha"])):
        raise SelectionError("selection snapshot main SHA is malformed")
    for field in ("profile_sha256", "candidate_metadata_sha256"):
        snapshot[field] = _sha256(snapshot[field], field)
    metadata_schema = _non_negative_int(
        snapshot["candidate_metadata_schema_version"], "candidate metadata schema"
    )
    if metadata_schema != CANDIDATE_METADATA_SCHEMA_VERSION:
        raise SelectionError("candidate metadata schema is unsupported")
    key_version = validate_identity_version(snapshot["identity_key_version"], "identity_key_version")
    epoch = validate_identity_version(snapshot["identity_epoch"], "identity_epoch")
    raw_candidates = snapshot["candidates"]
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise SelectionError("selection snapshot contains no candidates")
    candidates: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    proxy_names: set[str] = set()
    for raw_candidate in raw_candidates:
        record = _strict_mapping(raw_candidate, _SNAPSHOT_CANDIDATE_FIELDS, "selection candidate")
        candidate_id = validate_public_id(record["candidate_id"], "candidate")
        if candidate_id in candidate_ids:
            raise SelectionError("selection snapshot contains duplicate candidate IDs")
        if not isinstance(record["proxy"], Mapping) or not isinstance(record["metadata"], Mapping):
            raise SelectionError("selection candidate proxy/metadata is malformed")
        proxy = copy.deepcopy(dict(record["proxy"]))
        for field in ("name", "type", "server", "port"):
            if field not in proxy or not str(proxy[field]).strip():
                raise SelectionError("selection candidate proxy is incomplete")
        name = str(proxy["name"])
        if name in proxy_names:
            raise SelectionError("selection snapshot contains duplicate proxy names")
        proxy_names.add(name)
        metadata = _strict_mapping(
            record["metadata"], frozenset(C1_CANDIDATE_METADATA_FIELDS), "selection candidate metadata"
        )
        validate_public_id(metadata["server_id"], "server")
        validate_public_id(metadata["endpoint_id"], "endpoint")
        source_ids = metadata["source_ids"]
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or source_ids != sorted(set(source_ids))
            or any(not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id) for source_id in source_ids)
        ):
            raise SelectionError("selection candidate source IDs are malformed")
        aliases = metadata["aliases"]
        if (
            not isinstance(aliases, list)
            or aliases != sorted(set(aliases))
            or any(not isinstance(alias, str) for alias in aliases)
        ):
            raise SelectionError("selection candidate aliases are malformed")
        for field in ("first_seen_at", "last_seen_at", "source_last_success_at", "endpoint_checked_at"):
            try:
                normalized_timestamp = utc_timestamp(metadata[field])
            except Exception as exc:
                raise SelectionError(f"selection candidate {field} is malformed") from exc
            if normalized_timestamp != metadata[field]:
                raise SelectionError(f"selection candidate {field} must be canonical UTC")
        if metadata["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION:
            raise SelectionError("selection candidate endpoint policy is unsupported")
        if metadata["protocol"] != str(proxy["type"]).lower():
            raise SelectionError("selection candidate protocol disagrees with its proxy")
        hints = metadata["region_hints"]
        if (
            not isinstance(hints, list)
            or any(item not in TARGET_ASIA_REGIONS for item in hints)
            or hints != sorted(set(hints), key=TARGET_ASIA_REGIONS.index)
        ):
            raise SelectionError("selection candidate region hints are malformed")
        evidence = metadata["region_evidence"]
        if (
            not isinstance(evidence, list)
            or evidence != sorted(set(evidence))
            or any(not isinstance(item, str) or not _REGION_EVIDENCE_RE.fullmatch(item) for item in evidence)
        ):
            raise SelectionError("selection candidate region evidence is malformed")
        if not isinstance(metadata["protected_asia"], bool):
            raise SelectionError("selection candidate Asia protection flag is malformed")
        if metadata["github_check_state"] not in {"passed", "bypassed_asia"}:
            raise SelectionError("selection candidate GitHub state is unsupported")
        if (metadata["github_check_state"] == "bypassed_asia") != metadata["protected_asia"]:
            raise SelectionError("selection candidate GitHub state contradicts Asia protection")
        candidate_ids.add(candidate_id)
        candidates.append({"candidate_id": candidate_id, "proxy": proxy, "metadata": metadata})

    accepted = _strict_mapping(value["accepted_measurement"], _ACCEPTED_FIELDS, "accepted measurement")
    if accepted["kind"] != "cnb-gmgn-accepted-measurement" or accepted["schema_version"] != 1:
        raise SelectionError("accepted measurement kind or schema is unsupported")
    if accepted["validity_policy_version"] != VALIDITY_POLICY_VERSION:
        raise SelectionError("accepted measurement validity policy is unsupported")
    run_id = accepted["run_id"]
    if not isinstance(run_id, str) or not _RUN_ID_RE.fullmatch(run_id):
        raise SelectionError("accepted measurement run_id is malformed")
    if accepted["main_sha"] != snapshot["main_sha"]:
        raise SelectionError("accepted measurement main SHA mismatch")
    for field in ("profile_sha256", "candidate_metadata_sha256"):
        if _sha256(accepted[field], field) != snapshot[field]:
            raise SelectionError(f"accepted measurement {field} mismatch")
    if accepted["candidate_metadata_schema_version"] != metadata_schema:
        raise SelectionError("accepted measurement metadata schema mismatch")
    if _non_negative_int(accepted["candidate_metadata_count"], "candidate metadata count") != len(candidates):
        raise SelectionError("accepted measurement candidate count mismatch")
    if accepted["identity_key_version"] != key_version or accepted["identity_epoch"] != epoch:
        raise SelectionError("accepted measurement identity version mismatch")
    for field in ("source_sha256", "manifest_sha256"):
        accepted[field] = _sha256(accepted[field], field)
    fragment_hashes = accepted["fragment_sha256"]
    if not isinstance(fragment_hashes, list) or len(fragment_hashes) != 4:
        raise SelectionError("accepted measurement must bind four fragments")
    accepted["fragment_sha256"] = [_sha256(item, "fragment_sha256") for item in fragment_hashes]
    raw_results = accepted["results"]
    if not isinstance(raw_results, list) or len(raw_results) != len(candidates):
        raise SelectionError("accepted measurement result count mismatch")
    measurements: dict[str, dict[str, Any]] = {}
    for raw_result in raw_results:
        result = _normalize_measurement(raw_result)
        candidate_id = result["candidate_id"]
        if candidate_id in measurements:
            raise SelectionError("accepted measurement contains duplicate candidate IDs")
        measurements[candidate_id] = result
    if set(measurements) != candidate_ids:
        raise SelectionError("accepted measurement does not exactly cover the snapshot")

    history = validate_history(value["history"], reserved_names=V2_GROUP_NAMES)
    if history["identity_key_version"] != key_version or history["identity_epoch"] != epoch:
        raise SelectionError("history identity version mismatch")
    if history["selection_policy_version"] != SELECTION_POLICY_VERSION:
        raise SelectionError("history selection policy version is unsupported")
    raw_regions = value["region_decisions"]
    if not isinstance(raw_regions, Mapping):
        raise SelectionError("region decisions must be an object")
    regions: dict[str, dict[str, Any]] = {}
    for raw_candidate, raw_region in raw_regions.items():
        candidate_id = validate_public_id(raw_candidate, "candidate")
        region = validate_region_decision(raw_region)
        if region["candidate_id"] != candidate_id:
            raise SelectionError("region decision key and candidate_id disagree")
        if (
            region["identity_key_version"] != key_version
            or region["identity_epoch"] != epoch
        ):
            raise SelectionError("region decision identity version mismatch")
        regions[candidate_id] = region
    if set(regions) != candidate_ids:
        raise SelectionError("region decisions do not exactly cover the snapshot")
    return {
        "kind": SELECTION_INPUT_KIND,
        "schema_version": SELECTION_INPUT_SCHEMA_VERSION,
        "snapshot": {
            **snapshot,
            "identity_key_version": key_version,
            "identity_epoch": epoch,
            "candidates": candidates,
        },
        "accepted_measurement": {**accepted, "results": list(measurements.values())},
        "history": history,
        "region_decisions": regions,
    }


def candidate_quality_key(candidate: Mapping[str, Any]) -> tuple[Any, ...]:
    measurement = candidate["measurement"]

    def metric(name: str) -> float:
        value = measurement.get(name)
        return float("inf") if value is None else float(value)

    return (
        -int(measurement["within_1000_count"]),
        -int(measurement["response_count"]),
        metric("p90_delay_ms"),
        metric("median_delay_ms"),
        metric("jitter_ms"),
        str(candidate["candidate_id"]),
    )


def _quality_without_identity(candidate: Mapping[str, Any]) -> tuple[Any, ...]:
    return candidate_quality_key(candidate)[:-1]


def _classify(candidate: Mapping[str, Any]) -> tuple[str | None, str, bool]:
    measurement = candidate["measurement"]
    region = candidate["region"]
    history_node = candidate.get("history_node")
    within = int(measurement["within_1000_count"])
    response = int(measurement["response_count"])
    first = int(measurement["first_half_within_1000_count"])
    second = int(measurement["second_half_within_1000_count"])
    if history_node:
        state = history_node["current_state"]
        source_state = history_node["source_state"]
        if state == "removed_source_missing" or source_state == "confirmed_missing":
            return None, "source_confirmed_missing", state != "non_asia_stable"
        if state == "removed_invalid_config" or source_state == "invalid_config":
            return None, "invalid_config", state != "non_asia_stable"
        if state == "removed_bad_streak" and response == 0:
            return None, "bad_streak_limit", True
    protected = bool(
        history_node
        and not history_node["removed"]
        and history_node["current_state"] == "history_protected"
        and history_node["bad_run_streak"] in {1, 2}
        and history_node["source_state"] not in {"confirmed_missing", "invalid_config"}
    )
    if protected and response == 0:
        return "history_protected", f"history_bad_{history_node['bad_run_streak']}", True
    if region["verified_target_asia"]:
        if within >= 14 and first >= 5 and second >= 5:
            return "asia_core", "asia_core", True
        if 10 <= within <= 13:
            return "asia_flexible", "asia_flexible", True
        if response >= 1:
            reason = "asia_manual_unbalanced" if within >= 14 else "asia_manual_below_flexible"
            return "asia_manual_candidate", reason, True
        return None, "new_asia_zero_response", True
    if region["temporary_target_asia"]:
        if response >= 1:
            return "asia_manual_candidate", "asia_manual_source_specific", True
        return None, "new_asia_zero_response", True
    if protected:
        return "history_protected", "history_region_unavailable", True
    if region["confidence"] == "unknown":
        return None, "region_unknown_unverified", False
    if within >= 16:
        return "non_asia_stable", "non_asia_eligible", False
    return None, "non_asia_below_threshold", False


def _diversity_reason(
    candidate: Mapping[str, Any],
    counts: Mapping[str, Counter[str]],
    *,
    asn_limit: int,
    source_limit: int,
) -> str | None:
    region = candidate["region"]
    metadata = candidate["metadata"]
    exit_value = region["exit_id"]
    if exit_value is not None and counts["exit"][exit_value] >= 3:
        return "diversity_exit_cap"
    server = str(metadata["server_id"])
    if counts["server"][server] >= 3:
        return "diversity_server_cap"
    asn = region["asn_id"]
    if asn is not None and counts["asn"][asn] >= asn_limit:
        return "diversity_asn_cap"
    if any(counts["source"][str(source)] >= source_limit for source in metadata["source_ids"]):
        return "diversity_source_cap"
    return None


def _record_diversity(candidate: Mapping[str, Any], counts: Mapping[str, Counter[str]]) -> None:
    region = candidate["region"]
    metadata = candidate["metadata"]
    if region["exit_id"] is not None:
        counts["exit"][str(region["exit_id"])] += 1
    counts["server"][str(metadata["server_id"])] += 1
    if region["asn_id"] is not None:
        counts["asn"][str(region["asn_id"])] += 1
    for source in metadata["source_ids"]:
        counts["source"][str(source)] += 1
    counts["protocol"][str(metadata.get("protocol") or "unknown")] += 1


def _greedy_diverse(
    candidates: Sequence[dict[str, Any]],
    *,
    limit: int,
    counts: Mapping[str, Counter[str]],
    covered_regions: set[str],
    asn_limit: int,
    source_limit: int,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    remaining = [copy.deepcopy(item) for item in candidates]
    selected: list[dict[str, Any]] = []
    rejected: dict[str, str] = {}
    while remaining and len(selected) < limit:
        remaining.sort(
            key=lambda item: (
                _quality_without_identity(item),
                0
                if item["region"]["country_code"] in TARGET_ASIA_REGIONS
                and item["region"]["country_code"] not in covered_regions
                else 1,
                counts["protocol"][str(item["metadata"].get("protocol") or "unknown")],
                str(item["candidate_id"]),
            )
        )
        candidate = remaining.pop(0)
        reason = _diversity_reason(
            candidate, counts, asn_limit=asn_limit, source_limit=source_limit
        )
        if reason is not None:
            rejected[str(candidate["candidate_id"])] = reason
            continue
        selected.append(candidate)
        _record_diversity(candidate, counts)
        country = str(candidate["region"]["country_code"])
        if country in TARGET_ASIA_REGIONS:
            covered_regions.add(country)
    return selected, rejected


def _concentration_flags(
    candidate: Mapping[str, Any],
    counts: Mapping[str, Counter[str]],
    *,
    asn_limit: int,
    source_limit: int,
) -> list[str]:
    flags: list[str] = []
    region = candidate["region"]
    metadata = candidate["metadata"]
    if region["exit_id"] is not None and counts["exit"][str(region["exit_id"])] > 3:
        flags.append("exit_concentrated")
    if counts["server"][str(metadata["server_id"])] > 3:
        flags.append("server_concentrated")
    if region["asn_id"] is not None and counts["asn"][str(region["asn_id"])] > asn_limit:
        flags.append("asn_concentrated")
    if any(counts["source"][str(source)] > source_limit for source in metadata["source_ids"]):
        flags.append("source_concentrated")
    return flags


def _capacity_order(
    candidates: Sequence[dict[str, Any]],
    *,
    limit: int,
    counts: Mapping[str, Counter[str]],
    covered_regions: set[str],
) -> list[dict[str, Any]]:
    """Keep backup quality primary, then prefer missing and less concentrated domains."""

    remaining = list(candidates)
    selected: list[dict[str, Any]] = []
    while remaining and len(selected) < limit:
        def concentration_key(item: Mapping[str, Any]) -> tuple[int, ...]:
            region = item["region"]
            metadata = item["metadata"]
            source_load = max(
                (counts["source"][str(source)] for source in metadata["source_ids"]),
                default=0,
            )
            return (
                counts["exit"][str(region["exit_id"])] if region["exit_id"] is not None else 0,
                counts["server"][str(metadata["server_id"])],
                counts["asn"][str(region["asn_id"])] if region["asn_id"] is not None else 0,
                source_load,
                counts["protocol"][str(metadata.get("protocol") or "unknown")],
            )

        remaining.sort(
            key=lambda item: (
                _quality_without_identity(item),
                0
                if item["region"]["verified_target_asia"]
                and item["region"]["country_code"] not in covered_regions
                else 1,
                concentration_key(item),
                str(item["candidate_id"]),
            )
        )
        candidate = remaining.pop(0)
        selected.append(candidate)
        _record_diversity(candidate, counts)
        country = str(candidate["region"]["country_code"])
        if country in TARGET_ASIA_REGIONS:
            covered_regions.add(country)
    return selected


def _empty_group(names: Iterable[str]) -> list[str]:
    values = list(dict.fromkeys(str(name) for name in names))
    return values or ["DIRECT"]


def _build_profile(
    selected: Sequence[Mapping[str, Any]],
    tier_ids: Mapping[str, list[str]],
    priority_ids: list[str],
    auto_ids: list[str],
) -> dict[str, Any]:
    by_id = {str(item["candidate_id"]): item for item in selected}
    if len(by_id) != len(selected):
        raise SelectionError("selected candidates contain duplicate identities")

    def names(candidate_ids: Iterable[str]) -> list[str]:
        return [str(by_id[candidate_id]["output_name"]) for candidate_id in candidate_ids if candidate_id in by_id]

    region_ids = {
        region: [
            str(item["candidate_id"])
            for item in selected
            if item["region"]["verified_target_asia"]
            and item["region"]["country_code"] == region
        ]
        for region in TARGET_ASIA_REGIONS
    }
    backup_ids = tier_ids["history_protected"] + tier_ids["asia_manual_candidate"]
    all_ids = [str(item["candidate_id"]) for item in selected]
    profile = {
        "mode": "rule",
        "log-level": "warning",
        "proxies": [],
        "proxy-groups": [
            {"name": GROUP_MANUAL_PRIORITY, "type": "select", "proxies": _empty_group(names(priority_ids))},
            {"name": GROUP_HK, "type": "select", "proxies": _empty_group(names(region_ids["HK"]))},
            {"name": GROUP_JP, "type": "select", "proxies": _empty_group(names(region_ids["JP"]))},
            {"name": GROUP_KR, "type": "select", "proxies": _empty_group(names(region_ids["KR"]))},
            {"name": GROUP_SG, "type": "select", "proxies": _empty_group(names(region_ids["SG"]))},
            {"name": GROUP_TW, "type": "select", "proxies": _empty_group(names(region_ids["TW"]))},
            {"name": GROUP_ASIA_BACKUP, "type": "select", "proxies": _empty_group(names(backup_ids))},
            {"name": GROUP_NON_ASIA, "type": "select", "proxies": _empty_group(names(tier_ids["non_asia_stable"]))},
            {"name": GROUP_ALL, "type": "select", "proxies": _empty_group(names(all_ids))},
            {
                "name": GROUP_AUTO,
                "type": "url-test",
                "proxies": _empty_group(names(auto_ids)),
                "url": "https://gmgn.ai/",
                "interval": 300,
                "tolerance": 50,
                "lazy": True,
            },
        ],
        "rules": [f"MATCH,{GROUP_MANUAL_PRIORITY}"],
    }
    used_names: set[str] = set(V2_GROUP_NAMES) | set(BUILTIN_PROXY_NAMES)
    for item in selected:
        proxy = copy.deepcopy(dict(item["proxy"]))
        output_name = str(item["output_name"])
        if output_name in used_names:
            raise SelectionError("stable output name collides with another proxy or group")
        used_names.add(output_name)
        proxy["name"] = output_name
        profile["proxies"].append(proxy)
    rendered, rejected = dump_clash_yaml(profile)
    if rejected:
        raise SelectionError("selected profile contains invalid REALITY short IDs")
    loaded = yaml.safe_load(rendered)
    if not isinstance(loaded, Mapping):
        raise SelectionError("selected profile failed YAML round-trip")
    published_names = {str(proxy["name"]) for proxy in profile["proxies"]}
    group_names = set(V2_GROUP_NAMES)
    allowed = published_names | group_names | BUILTIN_PROXY_NAMES
    for group in profile["proxy-groups"]:
        if any(str(reference) not in allowed for reference in group["proxies"]):
            raise SelectionError("selected profile contains a dangling group reference")
    return profile


def select_candidates_v2(raw_input: Mapping[str, Any], *, max_nodes: int = MAX_NODES) -> dict[str, Any]:
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or not 1 <= max_nodes <= MAX_NODES:
        raise SelectionError("max_nodes must be between 1 and 150")
    value = validate_selection_input(raw_input)
    snapshot = value["snapshot"]
    accepted = value["accepted_measurement"]
    history = value["history"]
    regions = value["region_decisions"]
    measurements = {item["candidate_id"]: item for item in accepted["results"]}
    aliases = {
        item["candidate_id"]: _candidate_alias(item["metadata"], item["proxy"])
        for item in snapshot["candidates"]
    }
    output_names = allocate_stable_output_names(
        history["nodes"], aliases, reserved_names=V2_GROUP_NAMES
    )
    candidates: list[dict[str, Any]] = []
    for record in snapshot["candidates"]:
        candidate_id = record["candidate_id"]
        candidate = {
            **copy.deepcopy(record),
            "measurement": copy.deepcopy(measurements[candidate_id]),
            "region": copy.deepcopy(regions[candidate_id]),
            "history_node": copy.deepcopy(history["nodes"].get(candidate_id)),
            "output_name": output_names[candidate_id],
        }
        tier, reason, is_asia = _classify(candidate)
        candidate["eligible_tier"] = tier
        candidate["classification_reason"] = reason
        candidate["is_asia"] = is_asia
        candidates.append(candidate)

    core = sorted((item for item in candidates if item["eligible_tier"] == "asia_core"), key=candidate_quality_key)
    flexible = sorted((item for item in candidates if item["eligible_tier"] == "asia_flexible"), key=candidate_quality_key)
    manual = sorted((item for item in candidates if item["eligible_tier"] == "asia_manual_candidate"), key=candidate_quality_key)
    protected = sorted((item for item in candidates if item["eligible_tier"] == "history_protected"), key=candidate_quality_key)
    non_asia = sorted((item for item in candidates if item["eligible_tier"] == "non_asia_stable"), key=candidate_quality_key)

    eligible_strict_count = len(core) + len(flexible) + min(len(non_asia), NON_ASIA_MAX)
    strict_target = max(1, min(DESIRED_CAPACITY, eligible_strict_count))
    asn_limit = max(3, math.ceil(strict_target * 0.30))
    source_limit = max(2, math.ceil(strict_target * 0.25))
    counts: dict[str, Counter[str]] = {
        name: Counter() for name in ("exit", "server", "asn", "source", "protocol")
    }
    covered_regions: set[str] = set()
    diversity_rejected: dict[str, str] = {}
    selected_core, rejected = _greedy_diverse(
        core,
        limit=len(core),
        counts=counts,
        covered_regions=covered_regions,
        asn_limit=asn_limit,
        source_limit=source_limit,
    )
    diversity_rejected.update(rejected)
    selected_flexible, rejected = _greedy_diverse(
        flexible,
        limit=len(flexible),
        counts=counts,
        covered_regions=covered_regions,
        asn_limit=asn_limit,
        source_limit=source_limit,
    )
    diversity_rejected.update(rejected)
    selected_non_base, rejected = _greedy_diverse(
        non_asia,
        limit=NON_ASIA_BASE_LIMIT,
        counts=counts,
        covered_regions=covered_regions,
        asn_limit=asn_limit,
        source_limit=source_limit,
    )
    diversity_rejected.update(rejected)
    base_ids = {item["candidate_id"] for item in selected_non_base}
    extension_pool = [
        item
        for item in non_asia
        if item["candidate_id"] not in base_ids
        and item["candidate_id"] not in diversity_rejected
        and int(item["measurement"]["within_1000_count"]) >= 18
    ]
    selected_non_extra, rejected = _greedy_diverse(
        extension_pool,
        limit=NON_ASIA_MAX - len(selected_non_base),
        counts=counts,
        covered_regions=covered_regions,
        asn_limit=asn_limit,
        source_limit=source_limit,
    )
    diversity_rejected.update(rejected)
    selected_non_asia = selected_non_base + selected_non_extra

    strict_tiers: list[tuple[str, list[dict[str, Any]]]] = [
        ("asia_core", selected_core),
        ("asia_flexible", selected_flexible),
        ("non_asia_stable", selected_non_asia),
    ]
    final: list[dict[str, Any]] = []
    tier_ids: dict[str, list[str]] = {tier: [] for tier in _TIERS}
    capacity_trimmed: set[str] = set()
    for tier, items in strict_tiers:
        for item in items:
            candidate_id = str(item["candidate_id"])
            if len(final) >= max_nodes:
                capacity_trimmed.add(candidate_id)
                continue
            item["tier"] = tier
            final.append(item)
            tier_ids[tier].append(candidate_id)
    for tier, items in (
        ("history_protected", protected),
        ("asia_manual_candidate", manual),
    ):
        remaining_slots = max_nodes - len(final)
        chosen = _capacity_order(
            items,
            limit=max(remaining_slots, 0),
            counts=counts,
            covered_regions=covered_regions,
        )
        chosen_ids = {str(item["candidate_id"]) for item in chosen}
        capacity_trimmed.update(
            str(item["candidate_id"])
            for item in items
            if str(item["candidate_id"]) not in chosen_ids
        )
        for item in chosen:
            item["tier"] = tier
            final.append(item)
            tier_ids[tier].append(str(item["candidate_id"]))
    final_ids = {str(item["candidate_id"]) for item in final}
    priority_ids = tier_ids["asia_core"] + tier_ids["asia_flexible"] + tier_ids["non_asia_stable"]
    auto_ids = tier_ids["asia_core"] + tier_ids["non_asia_stable"]

    all_counts: dict[str, Counter[str]] = {
        name: Counter() for name in ("exit", "server", "asn", "source", "protocol")
    }
    for item in final:
        _record_diversity(item, all_counts)
    concentration = {
        str(item["candidate_id"]): _concentration_flags(
            item, all_counts, asn_limit=asn_limit, source_limit=source_limit
        )
        for item in final
    }

    node_status: list[dict[str, Any]] = []
    history_decisions: dict[str, dict[str, Any]] = {}
    by_id = {str(item["candidate_id"]): item for item in candidates}
    for candidate_id in sorted(by_id):
        item = by_id[candidate_id]
        eligible_tier = item["eligible_tier"]
        if candidate_id in diversity_rejected:
            reason = diversity_rejected[candidate_id]
        elif candidate_id in capacity_trimmed:
            reason = "capacity_cap"
        else:
            reason = item["classification_reason"]
        selected = candidate_id in final_ids
        node = item["history_node"]
        measurement = item["measurement"]
        flags = concentration.get(candidate_id, [])
        node_status.append(
            {
                "candidate_id": candidate_id,
                "output_name": item["output_name"],
                "tier": eligible_tier if selected else "not_selected",
                "eligible_tier": eligible_tier,
                "reason": reason,
                "selected": selected,
                "priority_selected": candidate_id in priority_ids,
                "auto_selected": candidate_id in auto_ids,
                "country_code": item["region"]["country_code"],
                "region_confidence": item["region"]["confidence"],
                "region_stale": item["region"]["stale"],
                "within_1000_count": measurement["within_1000_count"],
                "under_1000_count": measurement["within_1000_count"],
                "response_count": measurement["response_count"],
                "slow_response_count": measurement["slow_response_count"],
                "over_1000_count": measurement["slow_response_count"],
                "no_result_count": measurement["no_result_count"],
                "timeout_count": measurement["error_counts"]["client_timeout"],
                "error_counts": copy.deepcopy(measurement["error_counts"]),
                "first_half_within_1000_count": measurement[
                    "first_half_within_1000_count"
                ],
                "second_half_within_1000_count": measurement[
                    "second_half_within_1000_count"
                ],
                "median_delay_ms": measurement["median_delay_ms"],
                "p90_delay_ms": measurement["p90_delay_ms"],
                "jitter_ms": measurement["jitter_ms"],
                "history_transition": node["transition_reason"] if node else "new_candidate",
                "concentration_flags": flags,
            }
        )
        proposed_state = eligible_tier or "unknown_region"
        if proposed_state == "history_protected":
            proposed_state = "asia_manual_candidate"
        history_decisions[candidate_id] = {
            "is_asia": bool(item["is_asia"]),
            "proposed_state": proposed_state,
            "source_alias": _candidate_alias(item["metadata"], item["proxy"]),
            "selected": selected,
            "region_cache": copy.deepcopy(item["region"]["cache"]),
        }

    profile = _build_profile(final, tier_ids, priority_ids, auto_ids)
    region_counts = {
        region: sum(
            1
            for item in final
            if item["region"]["verified_target_asia"]
            and item["region"]["country_code"] == region
        )
        for region in TARGET_ASIA_REGIONS
    }
    stable_capacity = (
        len(tier_ids["asia_core"])
        + len(tier_ids["asia_flexible"])
        + len(tier_ids["non_asia_stable"])
    )
    summary = {
        "source_candidate_count": len(candidates),
        "published_count": len(final),
        "stable_capacity_count": stable_capacity,
        "desired_capacity": DESIRED_CAPACITY,
        "desired_capacity_reached": stable_capacity >= DESIRED_CAPACITY,
        "max_nodes": max_nodes,
        "asia_core_count": len(tier_ids["asia_core"]),
        "asia_flexible_count": len(tier_ids["asia_flexible"]),
        "asia_manual_candidate_count": len(tier_ids["asia_manual_candidate"]),
        "history_protected_count": len(tier_ids["history_protected"]),
        "non_asia_stable_count": len(tier_ids["non_asia_stable"]),
        "unknown_region_count": sum(item["region"]["confidence"] == "unknown" for item in candidates),
        "region_counts": region_counts,
        "capacity_trimmed_count": len(capacity_trimmed),
        "diversity_trimmed_count": len(diversity_rejected),
        "diversity_limits": {
            "exit_id_cap": 3,
            "server_id_cap": 3,
            "asn_id_cap": asn_limit,
            "source_id_cap": source_limit,
        },
    }
    node_status_document = {
        "kind": NODE_STATUS_KIND,
        "schema_version": NODE_STATUS_SCHEMA_VERSION,
        "run_id": accepted["run_id"],
        "source_sha256": accepted["source_sha256"],
        "main_sha": accepted["main_sha"],
        "profile_sha256": accepted["profile_sha256"],
        "candidate_metadata_sha256": accepted["candidate_metadata_sha256"],
        "identity_key_version": snapshot["identity_key_version"],
        "identity_epoch": snapshot["identity_epoch"],
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": REGION_POLICY_VERSION,
        "summary": summary,
        "nodes": node_status,
    }
    return {
        "kind": SELECTION_RESULT_KIND,
        "schema_version": SELECTION_RESULT_SCHEMA_VERSION,
        "run_id": accepted["run_id"],
        "source_sha256": accepted["source_sha256"],
        "main_sha": accepted["main_sha"],
        "profile_sha256": accepted["profile_sha256"],
        "candidate_metadata_sha256": accepted["candidate_metadata_sha256"],
        "identity_key_version": snapshot["identity_key_version"],
        "identity_epoch": snapshot["identity_epoch"],
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": REGION_POLICY_VERSION,
        "selected": final,
        "tier_ids": tier_ids,
        "priority_ids": priority_ids,
        "auto_ids": auto_ids,
        "profile": profile,
        "summary": summary,
        "node_status": node_status_document,
        "history_decisions": history_decisions,
    }


def render_selection_profile(result: Mapping[str, Any]) -> str:
    if result.get("kind") != SELECTION_RESULT_KIND or result.get("schema_version") != SELECTION_RESULT_SCHEMA_VERSION:
        raise SelectionError("selection result kind or schema is unsupported")
    rendered, rejected = dump_clash_yaml(dict(result["profile"]))
    if rejected:
        raise SelectionError("selection profile rejected REALITY proxies")
    return rendered


def public_selection_status(result: Mapping[str, Any]) -> dict[str, Any]:
    rendered = render_selection_profile(result).encode("utf-8")
    return {
        "kind": "cnb-gmgn-selection-status",
        "schema_version": 1,
        "run_id": result["run_id"],
        "source_sha256": result["source_sha256"],
        "main_sha": result["main_sha"],
        "source_profile_sha256": result["profile_sha256"],
        "candidate_metadata_sha256": result["candidate_metadata_sha256"],
        "output_profile_sha256": hashlib.sha256(rendered).hexdigest(),
        "identity_key_version": result["identity_key_version"],
        "identity_epoch": result["identity_epoch"],
        "selection_policy_version": result["selection_policy_version"],
        "region_policy_version": result["region_policy_version"],
        **copy.deepcopy(dict(result["summary"])),
    }


def selection_input_json_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = validate_selection_input(value)
    return (json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


__all__ = [
    "DESIRED_CAPACITY",
    "GROUP_ALL",
    "GROUP_ASIA_BACKUP",
    "GROUP_AUTO",
    "GROUP_HK",
    "GROUP_JP",
    "GROUP_KR",
    "GROUP_MANUAL_PRIORITY",
    "GROUP_NON_ASIA",
    "GROUP_SG",
    "GROUP_TW",
    "MAX_NODES",
    "NODE_STATUS_KIND",
    "NON_ASIA_MAX",
    "SELECTION_INPUT_KIND",
    "SELECTION_INPUT_SCHEMA_VERSION",
    "SELECTION_POLICY_VERSION",
    "SelectionError",
    "V2_GROUP_NAMES",
    "build_selection_input",
    "candidate_quality_key",
    "public_selection_status",
    "render_selection_profile",
    "select_candidates_v2",
    "selection_input_json_bytes",
    "snapshot_from_candidate_snapshot",
    "validate_selection_input",
]
