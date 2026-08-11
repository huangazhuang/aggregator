#!/usr/bin/env python3
"""Durable public GMGN identity history and stable output-name ownership.

The reducer in this module is intentionally pure: it validates and copies the
previous public history, applies one already accepted/valid run, and returns a
staged next value.  It performs no DNS, HTTP, Mihomo, or remote publication I/O.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from scripts.pipeline_utils import BUILTIN_PROXY_NAMES
from scripts.proxy_identity import (
    IdentitySettings,
    assert_unique_public_id_bindings,
    candidate_id,
    canonical_port,
    canonical_proxy_fingerprint,
    exit_id,
    validate_public_id,
)


HISTORY_KIND = "cnb-gmgn-history"
HISTORY_SCHEMA_VERSION = 1
HISTORY_POLICY_VERSION = "history-v1"
BAD_RUN_SPACING_SECONDS = 21_600
RECENT_OBSERVATION_LIMIT = 5
TOMBSTONE_RETENTION_DAYS = 90
OUTPUT_NAME_MAX_LENGTH = 80

STATES = frozenset(
    {
        "asia_core",
        "asia_flexible",
        "asia_manual_candidate",
        "history_protected",
        "non_asia_stable",
        "unknown_region",
        "removed_bad_streak",
        "removed_source_missing",
        "removed_invalid_config",
    }
)
ASIA_STATES = frozenset(
    {
        "asia_core",
        "asia_flexible",
        "asia_manual_candidate",
        "history_protected",
        "removed_bad_streak",
    }
)
PUBLISHABLE_STATES = frozenset(
    {
        "asia_core",
        "asia_flexible",
        "asia_manual_candidate",
        "history_protected",
        "non_asia_stable",
    }
)
REMOVED_STATES = frozenset(
    {
        "removed_bad_streak",
        "removed_source_missing",
        "removed_invalid_config",
    }
)
SOURCE_STATES = frozenset(
    {"present", "temporary_failure", "last_good", "confirmed_missing", "invalid_config"}
)
TRANSITION_REASONS = frozenset(
    {
        "first_responsive_observation",
        "responsive_observation",
        "selected_quality",
        "selection_changed",
        "zero_response_not_counted",
        "zero_response_bad_run",
        "bad_streak_limit",
        "recovered_response",
        "recovered_quality",
        "source_confirmed_missing",
        "invalid_config",
        "temporary_source_failure",
        "bootstrap_legacy_profile",
        "identity_migrated",
        "legacy_identity_reappeared",
    }
)

TOP_LEVEL_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "identity_key_version",
        "identity_epoch",
        "history_policy_version",
        "selection_policy_version",
        "last_accepted_run_id",
        "last_accepted_source_sha256",
        "last_accepted_at",
        "recent_accepted_runs",
        "nodes",
    }
)
RUN_FIELDS = frozenset({"run_id", "source_sha256", "accepted_at"})
MEASUREMENT_FIELDS = frozenset(
    {
        "total_rounds",
        "response_count",
        "within_limit_count",
        "slow_response_count",
        "no_result_count",
        "median_delay_ms",
        "p90_delay_ms",
        "jitter_ms",
    }
)
OBSERVATION_FIELDS = frozenset(
    {
        "run_id",
        "source_sha256",
        "accepted_at",
        "measurement_available",
        *MEASUREMENT_FIELDS,
        "counted_bad",
        "state",
        "reason",
        "source_state",
    }
)
TRANSITION_FIELDS = frozenset(
    {"from_state", "to_state", "reason", "run_id", "source_sha256", "at"}
)
REGION_CACHE_FIELDS = frozenset(
    {
        "country_code",
        "region_code",
        "exit_id",
        "asn_id",
        "queried_at",
        "expires_at",
        "stale",
        "policy_version",
    }
)
NODE_FIELDS = frozenset(
    {
        "candidate_id",
        "identity_key_version",
        "identity_epoch",
        "legacy_identity",
        "tombstone_expires_at",
        "output_name",
        "current_state",
        "previous_state",
        "transition_reason",
        "last_transition",
        "bad_run_streak",
        "last_counted_bad_source_sha256",
        "last_counted_bad_at",
        "recent_observations",
        "first_seen_at",
        "last_seen_at",
        "last_selected_at",
        "source_state",
        "last_measurement",
        "region_cache",
        "removed",
        "removed_at",
        "removed_reason",
    }
)

VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ASN_ID_RE = re.compile(r"^asn1_[0-9a-f]{24}$")
RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
REGION_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
URL_RE = re.compile(r"(?:https?://\S+|\bwww\.\S+)", re.IGNORECASE)
FINGERPRINT_TEXT_RE = re.compile(r"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])", re.IGNORECASE)
IPV4_TEXT_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
DYNAMIC_SUFFIX_RE = re.compile(
    r"(?:\s*[-|·/]\s*)?(?:\d+(?:\.\d+)?\s*ms|timeout|"
    r"\d+(?:\.\d+)?\s*%|rank\s*#?\d+)\s*$",
    re.IGNORECASE,
)


class HistoryError(ValueError):
    """Base failure for strict history validation and reduction."""


class HistoryValidationError(HistoryError):
    """The public history document violates schema v1."""


class HistoryMigrationError(HistoryError):
    """An identity/bootstrap/GC migration cannot be completed safely."""


def _exact_fields(value: Any, expected: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != expected:
        raise HistoryValidationError(f"{label} fields are incomplete or unexpected")
    return value


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise HistoryValidationError(f"{label} must be a version token")
    token = value
    if not VERSION_RE.fullmatch(token):
        raise HistoryValidationError(f"{label} must be a version token")
    return token


def _run_id(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise HistoryValidationError("run_id is malformed")
    token = value
    if not RUN_ID_RE.fullmatch(token):
        raise HistoryValidationError("run_id is malformed")
    return token


def _sha256(value: Any, label: str = "source_sha256") -> str:
    if not isinstance(value, str):
        raise HistoryValidationError(f"{label} must be lowercase SHA-256")
    token = value
    if not SHA256_RE.fullmatch(token):
        raise HistoryValidationError(f"{label} must be lowercase SHA-256")
    return token


def _timestamp(value: Any, label: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str) or not RFC3339_UTC_RE.fullmatch(value):
        raise HistoryValidationError(f"{label} must be an RFC3339 UTC timestamp")
    token = value
    try:
        parsed = datetime.fromisoformat(token[:-1] + "+00:00")
    except ValueError as exc:
        raise HistoryValidationError(f"{label} must be an RFC3339 UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise HistoryValidationError(f"{label} must be UTC")
    return token


def _datetime(value: str, label: str) -> datetime:
    _timestamp(value, label)
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _non_negative_int(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise HistoryValidationError(f"{label} must be a non-negative integer")
    return value


def _finite_optional(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float):
        raise HistoryValidationError(f"{label} must be finite or null")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise HistoryValidationError(f"{label} must be finite and non-negative")
    return number


def _contains_ip(value: str) -> bool:
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


def _validate_output_name(value: Any, reserved_names: Iterable[str] = ()) -> str:
    name = str(value or "")
    reserved = set(BUILTIN_PROXY_NAMES) | {str(item) for item in reserved_names}
    if not name or len(name) > OUTPUT_NAME_MAX_LENGTH:
        raise HistoryValidationError("output_name is empty or too long")
    if name != name.strip() or CONTROL_RE.search(name):
        raise HistoryValidationError("output_name contains unsafe whitespace or controls")
    if name in reserved:
        raise HistoryValidationError("output_name conflicts with a reserved Clash target")
    if URL_RE.search(name) or FINGERPRINT_TEXT_RE.search(name) or _contains_ip(name):
        raise HistoryValidationError("output_name contains private connection material")
    return name


def sanitize_output_alias(value: Any) -> str:
    """Return a safe, stable base name without dynamic measurement suffixes."""

    alias = CONTROL_RE.sub(" ", str(value or ""))
    alias = URL_RE.sub(" ", alias)
    alias = FINGERPRINT_TEXT_RE.sub(" ", alias)
    alias = IPV4_TEXT_RE.sub(" ", alias)
    alias = " ".join(alias.split()).strip(" -|·/[]()")
    previous = None
    while alias and alias != previous:
        previous = alias
        alias = DYNAMIC_SUFFIX_RE.sub("", alias).strip(" -|·/")
    if _contains_ip(alias):
        return ""
    return alias[:OUTPUT_NAME_MAX_LENGTH].rstrip()


def _stable_conflict_name(base: str, candidate: str, used: set[str]) -> str:
    suffix = candidate[-6:]
    prefix_length = OUTPUT_NAME_MAX_LENGTH - len(suffix) - 3
    root = (base or "Node")[:prefix_length].rstrip() or "Node"
    proposed = f"{root} [{suffix}]"
    if proposed not in used:
        return proposed
    full_suffix = candidate
    prefix_length = OUTPUT_NAME_MAX_LENGTH - len(full_suffix) - 3
    root = (base or "Node")[: max(prefix_length, 1)].rstrip() or "N"
    proposed = f"{root} [{full_suffix}]"
    if proposed in used:
        raise HistoryValidationError("stable output-name collision detected")
    return proposed


def allocate_stable_output_names(
    previous_nodes: Mapping[str, Mapping[str, Any]],
    aliases: Mapping[str, Any],
    *,
    reserved_names: Iterable[str] = (),
) -> dict[str, str]:
    """Allocate deterministic names while preserving all prior/tombstone names."""

    reserved = set(BUILTIN_PROXY_NAMES) | {str(item) for item in reserved_names}
    used = set(reserved)
    result: dict[str, str] = {}
    for raw_candidate, node in previous_nodes.items():
        cid = validate_public_id(raw_candidate, "candidate")
        if not isinstance(node, Mapping) or node.get("candidate_id") != cid:
            raise HistoryValidationError("previous name mapping is malformed")
        name = _validate_output_name(node.get("output_name"), reserved)
        if name in used:
            raise HistoryValidationError("previous output names are not unique")
        used.add(name)
        result[cid] = name

    for raw_candidate in sorted(aliases):
        cid = validate_public_id(raw_candidate, "candidate")
        if cid in result:
            continue
        base = sanitize_output_alias(aliases[raw_candidate])
        if not base or base in reserved:
            name = _stable_conflict_name("Node", cid, used)
        elif base in used:
            name = _stable_conflict_name(base, cid, used)
        else:
            try:
                _validate_output_name(base, reserved)
                name = base
            except HistoryValidationError:
                name = _stable_conflict_name("Node", cid, used)
        _validate_output_name(name, reserved)
        used.add(name)
        result[cid] = name
    return result


def _normalize_measurement(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise HistoryValidationError("measurement must be an object")
    total = _non_negative_int(raw.get("total_rounds", raw.get("attempts")), "total_rounds")
    response = _non_negative_int(raw.get("response_count"), "response_count")
    within = _non_negative_int(raw.get("within_limit_count"), "within_limit_count")
    slow = _non_negative_int(raw.get("slow_response_count"), "slow_response_count")
    no_result = _non_negative_int(raw.get("no_result_count"), "no_result_count")
    if total != 20 or response + no_result != total or within + slow != response:
        raise HistoryValidationError("measurement counts are inconsistent")
    metrics = {
        "median_delay_ms": _finite_optional(raw.get("median_delay_ms"), "median_delay_ms"),
        "p90_delay_ms": _finite_optional(raw.get("p90_delay_ms"), "p90_delay_ms"),
        "jitter_ms": _finite_optional(raw.get("jitter_ms"), "jitter_ms"),
    }
    if response == 0 and any(value is not None for value in metrics.values()):
        raise HistoryValidationError("zero-response measurement contains delay metrics")
    if response > 0 and any(value is None for value in metrics.values()):
        raise HistoryValidationError("responsive measurement is missing delay metrics")
    return {
        "total_rounds": total,
        "response_count": response,
        "within_limit_count": within,
        "slow_response_count": slow,
        "no_result_count": no_result,
        **metrics,
    }


def _validate_measurement(raw: Any, label: str) -> dict[str, Any]:
    value = _exact_fields(raw, MEASUREMENT_FIELDS, label)
    return _normalize_measurement(value)


def _validate_region_cache(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    value = _exact_fields(raw, REGION_CACHE_FIELDS, "region_cache")
    if not isinstance(value["country_code"], str):
        raise HistoryValidationError("region_cache country_code is malformed")
    country = value["country_code"]
    if country and not re.fullmatch(r"[A-Z]{2}", country):
        raise HistoryValidationError("region_cache country_code is malformed")
    if not isinstance(value["region_code"], str):
        raise HistoryValidationError("region_cache region_code is malformed")
    region = value["region_code"]
    if region and (
        not REGION_CODE_RE.fullmatch(region)
        or URL_RE.search(region)
        or FINGERPRINT_TEXT_RE.search(region)
        or _contains_ip(region)
    ):
        raise HistoryValidationError("region_cache region_code is malformed")
    exit_value = value["exit_id"]
    if exit_value is not None:
        exit_value = validate_public_id(exit_value, "exit")
    asn = value["asn_id"]
    if asn is not None and (not isinstance(asn, str) or not ASN_ID_RE.fullmatch(asn)):
        raise HistoryValidationError("region_cache asn_id is malformed")
    queried = _timestamp(value["queried_at"], "region_cache.queried_at")
    expires = _timestamp(value["expires_at"], "region_cache.expires_at")
    if _datetime(expires, "region_cache.expires_at") <= _datetime(
        queried, "region_cache.queried_at"
    ):
        raise HistoryValidationError("region_cache expiry must follow query time")
    if not isinstance(value["stale"], bool):
        raise HistoryValidationError("region_cache stale must be boolean")
    return {
        "country_code": country,
        "region_code": region,
        "exit_id": exit_value,
        "asn_id": asn,
        "queried_at": queried,
        "expires_at": expires,
        "stale": value["stale"],
        "policy_version": _version(value["policy_version"], "region_cache.policy_version"),
    }


def _validate_transition(raw: Any) -> dict[str, Any]:
    value = _exact_fields(raw, TRANSITION_FIELDS, "last_transition")
    from_state = value["from_state"]
    if from_state is not None and from_state not in STATES:
        raise HistoryValidationError("last_transition from_state is invalid")
    if value["to_state"] not in STATES or value["reason"] not in TRANSITION_REASONS:
        raise HistoryValidationError("last_transition state or reason is invalid")
    return {
        "from_state": from_state,
        "to_state": value["to_state"],
        "reason": value["reason"],
        "run_id": _run_id(value["run_id"]),
        "source_sha256": _sha256(value["source_sha256"]),
        "at": _timestamp(value["at"], "last_transition.at"),
    }


def _validate_observation(raw: Any) -> dict[str, Any]:
    value = _exact_fields(raw, OBSERVATION_FIELDS, "observation")
    available = value["measurement_available"]
    if not isinstance(available, bool) or not isinstance(value["counted_bad"], bool):
        raise HistoryValidationError("observation booleans are malformed")
    if value["state"] not in STATES or value["reason"] not in TRANSITION_REASONS:
        raise HistoryValidationError("observation state or reason is invalid")
    if value["source_state"] not in SOURCE_STATES:
        raise HistoryValidationError("observation source_state is invalid")
    if available:
        measurement = _validate_measurement(
            {field: value[field] for field in MEASUREMENT_FIELDS}, "observation measurement"
        )
    else:
        if any(value[field] is not None for field in MEASUREMENT_FIELDS):
            raise HistoryValidationError("unavailable observation contains measurement values")
        measurement = {field: None for field in MEASUREMENT_FIELDS}
        if value["counted_bad"]:
            raise HistoryValidationError("unavailable observation cannot count bad")
    return {
        "run_id": _run_id(value["run_id"]),
        "source_sha256": _sha256(value["source_sha256"]),
        "accepted_at": _timestamp(value["accepted_at"], "observation.accepted_at"),
        "measurement_available": available,
        **measurement,
        "counted_bad": value["counted_bad"],
        "state": value["state"],
        "reason": value["reason"],
        "source_state": value["source_state"],
    }


def _validate_node(
    raw: Any,
    candidate_key: str,
    *,
    active_key_version: str,
    active_epoch: str,
    reserved_names: Iterable[str],
) -> dict[str, Any]:
    value = _exact_fields(raw, NODE_FIELDS, f"node {candidate_key}")
    cid = validate_public_id(candidate_key, "candidate")
    if value["candidate_id"] != cid:
        raise HistoryValidationError("history node key and candidate_id disagree")
    key_version = _version(value["identity_key_version"], "node.identity_key_version")
    epoch = _version(value["identity_epoch"], "node.identity_epoch")
    legacy = value["legacy_identity"]
    if not isinstance(legacy, bool):
        raise HistoryValidationError("legacy_identity must be boolean")
    if not legacy and (key_version != active_key_version or epoch != active_epoch):
        raise HistoryValidationError("active node identity version disagrees with history")
    state = value["current_state"]
    previous_state = value["previous_state"]
    if state not in STATES or (previous_state is not None and previous_state not in STATES):
        raise HistoryValidationError("history node state is invalid")
    if value["transition_reason"] not in TRANSITION_REASONS:
        raise HistoryValidationError("history node transition_reason is invalid")
    bad_streak = _non_negative_int(value["bad_run_streak"], "bad_run_streak")
    if bad_streak > 3 or (state == "removed_bad_streak" and bad_streak != 3):
        raise HistoryValidationError("bad_run_streak is inconsistent with node state")
    counted_sha = value["last_counted_bad_source_sha256"]
    counted_at = value["last_counted_bad_at"]
    if (counted_sha is None) != (counted_at is None):
        raise HistoryValidationError("last counted-bad fields must be paired")
    if counted_sha is not None:
        counted_sha = _sha256(counted_sha, "last_counted_bad_source_sha256")
        counted_at = _timestamp(counted_at, "last_counted_bad_at")
    observations_raw = value["recent_observations"]
    if (
        not isinstance(observations_raw, list)
        or not observations_raw
        or len(observations_raw) > RECENT_OBSERVATION_LIMIT
    ):
        raise HistoryValidationError("recent_observations is malformed")
    observations = [_validate_observation(item) for item in observations_raw]
    if observations != sorted(observations, key=lambda item: item["accepted_at"]):
        raise HistoryValidationError("recent_observations are not chronological")
    observation_runs: set[str] = set()
    observation_shas: set[str] = set()
    for observation in observations:
        if (
            observation["run_id"] in observation_runs
            or observation["source_sha256"] in observation_shas
        ):
            raise HistoryValidationError("recent_observations contain duplicates")
        observation_runs.add(observation["run_id"])
        observation_shas.add(observation["source_sha256"])
    removed = value["removed"]
    if not isinstance(removed, bool) or removed != (state in REMOVED_STATES):
        raise HistoryValidationError("removed flag disagrees with node state")
    removed_at = _timestamp(value["removed_at"], "removed_at", nullable=True)
    tombstone = _timestamp(
        value["tombstone_expires_at"], "tombstone_expires_at", nullable=True
    )
    removed_reason = value["removed_reason"]
    if removed:
        if removed_at is None or tombstone is None or removed_reason not in TRANSITION_REASONS:
            raise HistoryValidationError("removed node is missing tombstone fields")
        if _datetime(tombstone, "tombstone_expires_at") <= _datetime(
            removed_at, "removed_at"
        ):
            raise HistoryValidationError("tombstone expiry must follow removal")
    elif any(item is not None for item in (removed_at, tombstone, removed_reason)):
        raise HistoryValidationError("active node contains removed tombstone fields")
    if legacy and not removed:
        raise HistoryValidationError("only removed tombstones may keep legacy identity")
    measurement = value["last_measurement"]
    if measurement is not None:
        measurement = _validate_measurement(measurement, "last_measurement")
    transition = _validate_transition(value["last_transition"])
    first_seen_at = _timestamp(value["first_seen_at"], "first_seen_at")
    last_seen_at = _timestamp(value["last_seen_at"], "last_seen_at")
    last_selected_at = _timestamp(
        value["last_selected_at"], "last_selected_at", nullable=True
    )
    if _datetime(last_seen_at, "last_seen_at") < _datetime(
        first_seen_at, "first_seen_at"
    ):
        raise HistoryValidationError("last_seen_at precedes first_seen_at")
    if last_selected_at is not None and _datetime(
        last_selected_at, "last_selected_at"
    ) < _datetime(first_seen_at, "first_seen_at"):
        raise HistoryValidationError("last_selected_at precedes first_seen_at")
    if bad_streak and counted_sha is None:
        raise HistoryValidationError("bad_run_streak is missing counted-bad evidence")
    node = {
        "candidate_id": cid,
        "identity_key_version": key_version,
        "identity_epoch": epoch,
        "legacy_identity": legacy,
        "tombstone_expires_at": tombstone,
        "output_name": _validate_output_name(value["output_name"], reserved_names),
        "current_state": state,
        "previous_state": previous_state,
        "transition_reason": value["transition_reason"],
        "last_transition": transition,
        "bad_run_streak": bad_streak,
        "last_counted_bad_source_sha256": counted_sha,
        "last_counted_bad_at": counted_at,
        "recent_observations": observations,
        "first_seen_at": first_seen_at,
        "last_seen_at": last_seen_at,
        "last_selected_at": last_selected_at,
        "source_state": value["source_state"],
        "last_measurement": measurement,
        "region_cache": _validate_region_cache(value["region_cache"]),
        "removed": removed,
        "removed_at": removed_at,
        "removed_reason": removed_reason,
    }
    if node["source_state"] not in SOURCE_STATES:
        raise HistoryValidationError("source_state is invalid")
    if (
        node["last_transition"]["from_state"] != previous_state
        or node["last_transition"]["to_state"] != state
        or node["last_transition"]["reason"] != node["transition_reason"]
    ):
        raise HistoryValidationError("last_transition disagrees with node state")
    available_observations = [
        observation for observation in observations if observation["measurement_available"]
    ]
    expected_measurement = None
    if available_observations:
        expected_measurement = {
            field: available_observations[-1][field] for field in MEASUREMENT_FIELDS
        }
    if measurement != expected_measurement:
        raise HistoryValidationError("last_measurement disagrees with observations")
    return node


def validate_history(
    raw: Any,
    *,
    reserved_names: Iterable[str] = (),
) -> dict[str, Any]:
    """Strictly validate and return a detached public history v1 mapping."""

    value = _exact_fields(raw, TOP_LEVEL_FIELDS, "history")
    if value["kind"] != HISTORY_KIND or value["schema_version"] != HISTORY_SCHEMA_VERSION:
        raise HistoryValidationError("unsupported history kind or schema")
    key_version = _version(value["identity_key_version"], "identity_key_version")
    epoch = _version(value["identity_epoch"], "identity_epoch")
    if value["history_policy_version"] != HISTORY_POLICY_VERSION:
        raise HistoryValidationError("unsupported history policy version")
    selection_policy = _version(
        value["selection_policy_version"], "selection_policy_version"
    )
    last_run = value["last_accepted_run_id"]
    last_sha = value["last_accepted_source_sha256"]
    last_at = value["last_accepted_at"]
    if all(item is None for item in (last_run, last_sha, last_at)):
        normalized_last = (None, None, None)
    elif any(item is None for item in (last_run, last_sha, last_at)):
        raise HistoryValidationError("last accepted fields must be all null or all populated")
    else:
        normalized_last = (
            _run_id(last_run),
            _sha256(last_sha, "last_accepted_source_sha256"),
            _timestamp(last_at, "last_accepted_at"),
        )
    recent_raw = value["recent_accepted_runs"]
    if not isinstance(recent_raw, list):
        raise HistoryValidationError("recent_accepted_runs is malformed")
    recent: list[dict[str, Any]] = []
    seen_runs: set[str] = set()
    seen_shas: set[str] = set()
    for item in recent_raw:
        entry = _exact_fields(item, RUN_FIELDS, "recent accepted run")
        normalized = {
            "run_id": _run_id(entry["run_id"]),
            "source_sha256": _sha256(entry["source_sha256"]),
            "accepted_at": _timestamp(entry["accepted_at"], "accepted run time"),
        }
        if normalized["run_id"] in seen_runs or normalized["source_sha256"] in seen_shas:
            raise HistoryValidationError("recent accepted runs contain duplicates")
        seen_runs.add(normalized["run_id"])
        seen_shas.add(normalized["source_sha256"])
        recent.append(normalized)
    if recent != sorted(recent, key=lambda item: item["accepted_at"]):
        raise HistoryValidationError("recent accepted runs are not chronological")
    if normalized_last[0] is None and recent:
        raise HistoryValidationError("empty history cannot contain accepted runs")
    if normalized_last[0] is not None:
        if not recent or recent[-1] != {
            "run_id": normalized_last[0],
            "source_sha256": normalized_last[1],
            "accepted_at": normalized_last[2],
        }:
            raise HistoryValidationError("last accepted fields disagree with run index")
    nodes_raw = value["nodes"]
    if not isinstance(nodes_raw, Mapping):
        raise HistoryValidationError("history nodes must be an object")
    nodes: dict[str, dict[str, Any]] = {}
    names: set[str] = set()
    for candidate_key in sorted(nodes_raw):
        node = _validate_node(
            nodes_raw[candidate_key],
            str(candidate_key),
            active_key_version=key_version,
            active_epoch=epoch,
            reserved_names=reserved_names,
        )
        if node["output_name"] in names:
            raise HistoryValidationError("history output names are not unique")
        names.add(node["output_name"])
        nodes[node["candidate_id"]] = node
    accepted_index = {
        (item["run_id"], item["source_sha256"], item["accepted_at"]) for item in recent
    }
    for node in nodes.values():
        for observation in node["recent_observations"]:
            if (
                observation["run_id"],
                observation["source_sha256"],
                observation["accepted_at"],
            ) not in accepted_index:
                raise HistoryValidationError(
                    "node observation is not backed by an accepted run"
                )
        transition = node["last_transition"]
        if transition["reason"] not in {
            "identity_migrated",
            "legacy_identity_reappeared",
        } and (
            transition["run_id"],
            transition["source_sha256"],
            transition["at"],
        ) not in accepted_index:
            raise HistoryValidationError(
                "node transition is not backed by an accepted run"
            )
    return {
        "kind": HISTORY_KIND,
        "schema_version": HISTORY_SCHEMA_VERSION,
        "identity_key_version": key_version,
        "identity_epoch": epoch,
        "history_policy_version": HISTORY_POLICY_VERSION,
        "selection_policy_version": selection_policy,
        "last_accepted_run_id": normalized_last[0],
        "last_accepted_source_sha256": normalized_last[1],
        "last_accepted_at": normalized_last[2],
        "recent_accepted_runs": recent,
        "nodes": nodes,
    }


def empty_history(
    *, identity_key_version: str, identity_epoch: str, selection_policy_version: str
) -> dict[str, Any]:
    return validate_history(
        {
            "kind": HISTORY_KIND,
            "schema_version": HISTORY_SCHEMA_VERSION,
            "identity_key_version": identity_key_version,
            "identity_epoch": identity_epoch,
            "history_policy_version": HISTORY_POLICY_VERSION,
            "selection_policy_version": selection_policy_version,
            "last_accepted_run_id": None,
            "last_accepted_source_sha256": None,
            "last_accepted_at": None,
            "recent_accepted_runs": [],
            "nodes": {},
        }
    )


def history_json_bytes(history: Mapping[str, Any]) -> bytes:
    normalized = validate_history(history)
    return (
        json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def load_history(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise HistoryValidationError("history file is invalid JSON") from exc
    return validate_history(payload)


def write_history_atomic(path: str | Path, history: Mapping[str, Any]) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_bytes(history_json_bytes(history))
    temporary.replace(destination)
    return destination


def _source_state(raw: Any) -> str:
    if raw is None:
        return "present"
    if isinstance(raw, Mapping):
        if set(raw) != {"state"}:
            raise HistoryValidationError("source event fields are unexpected")
        raw = raw.get("state")
    if not isinstance(raw, str) or raw != raw.strip():
        raise HistoryValidationError("source event state is invalid")
    state = raw
    if state not in SOURCE_STATES:
        raise HistoryValidationError("source event state is invalid")
    return state


def _decision(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise HistoryValidationError("selection decision must be an object")
    allowed = {"is_asia", "proposed_state", "source_alias", "selected", "region_cache"}
    if set(raw) - allowed:
        raise HistoryValidationError("selection decision fields are unexpected")
    if not isinstance(raw.get("is_asia"), bool):
        raise HistoryValidationError("selection decision is_asia must be boolean")
    state = raw.get("proposed_state")
    if state not in PUBLISHABLE_STATES | {"unknown_region"}:
        raise HistoryValidationError("selection decision proposed_state is invalid")
    selected = raw.get("selected", state in PUBLISHABLE_STATES)
    if not isinstance(selected, bool):
        raise HistoryValidationError("selection decision selected must be boolean")
    if raw["is_asia"] and state not in {
        "asia_core",
        "asia_flexible",
        "asia_manual_candidate",
        "unknown_region",
    }:
        raise HistoryValidationError("Asia decision has a non-Asia proposed state")
    if not raw["is_asia"] and state not in {"non_asia_stable", "unknown_region"}:
        raise HistoryValidationError("non-Asia decision has an Asia proposed state")
    source_alias = raw.get("source_alias", "")
    if not isinstance(source_alias, str):
        raise HistoryValidationError("selection decision source_alias must be text")
    return {
        "is_asia": raw["is_asia"],
        "proposed_state": state,
        "source_alias": source_alias,
        "selected": selected,
        "region_cache": _validate_region_cache(raw.get("region_cache")),
    }


def _normalize_candidate_mapping(
    raw: Any,
    *,
    label: str,
    normalize_value: Any,
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise HistoryValidationError(f"{label} must be an object")
    normalized: dict[str, Any] = {}
    for raw_candidate, value in raw.items():
        cid = validate_public_id(raw_candidate, "candidate")
        if cid in normalized:
            raise HistoryValidationError(f"{label} contains duplicate candidate IDs")
        normalized[cid] = normalize_value(value)
    return normalized


def _transition(
    from_state: str | None,
    to_state: str,
    reason: str,
    run: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "from_state": from_state,
        "to_state": to_state,
        "reason": reason,
        "run_id": run["run_id"],
        "source_sha256": run["source_sha256"],
        "at": run["accepted_at"],
    }


def _observation(
    run: Mapping[str, Any],
    measurement: Mapping[str, Any] | None,
    *,
    counted_bad: bool,
    state: str,
    reason: str,
    source_state: str,
) -> dict[str, Any]:
    values = (
        dict(measurement)
        if measurement is not None
        else {field: None for field in MEASUREMENT_FIELDS}
    )
    return {
        "run_id": run["run_id"],
        "source_sha256": run["source_sha256"],
        "accepted_at": run["accepted_at"],
        "measurement_available": measurement is not None,
        **values,
        "counted_bad": counted_bad,
        "state": state,
        "reason": reason,
        "source_state": source_state,
    }


def _new_node(
    cid: str,
    output_name: str,
    state: str,
    run: Mapping[str, Any],
    measurement: Mapping[str, Any],
    decision: Mapping[str, Any],
    source_state: str,
) -> dict[str, Any]:
    reason = "first_responsive_observation"
    return {
        "candidate_id": cid,
        "identity_key_version": run["identity_key_version"],
        "identity_epoch": run["identity_epoch"],
        "legacy_identity": False,
        "tombstone_expires_at": None,
        "output_name": output_name,
        "current_state": state,
        "previous_state": None,
        "transition_reason": reason,
        "last_transition": _transition(None, state, reason, run),
        "bad_run_streak": 0,
        "last_counted_bad_source_sha256": None,
        "last_counted_bad_at": None,
        "recent_observations": [
            _observation(
                run,
                measurement,
                counted_bad=False,
                state=state,
                reason=reason,
                source_state=source_state,
            )
        ],
        "first_seen_at": run["accepted_at"],
        "last_seen_at": run["accepted_at"],
        "last_selected_at": run["accepted_at"] if decision["selected"] else None,
        "source_state": source_state,
        "last_measurement": dict(measurement),
        "region_cache": copy.deepcopy(decision["region_cache"]),
        "removed": False,
        "removed_at": None,
        "removed_reason": None,
    }


def _mark_removed(
    node: dict[str, Any], state: str, reason: str, run: Mapping[str, Any]
) -> None:
    old_state = node["current_state"]
    node["previous_state"] = old_state
    node["current_state"] = state
    node["transition_reason"] = reason
    node["last_transition"] = _transition(old_state, state, reason, run)
    node["removed"] = True
    node["removed_at"] = run["accepted_at"]
    node["removed_reason"] = reason
    removed_at = _datetime(run["accepted_at"], "accepted_at")
    node["tombstone_expires_at"] = _format_time(
        removed_at + timedelta(days=TOMBSTONE_RETENTION_DAYS)
    )


def reduce_history(
    previous: Mapping[str, Any],
    *,
    run_context: Mapping[str, Any],
    source_events: Mapping[str, Any],
    measurements: Mapping[str, Any],
    decisions: Mapping[str, Any],
    minimum_bad_spacing_seconds: int = BAD_RUN_SPACING_SECONDS,
) -> dict[str, Any]:
    """Stage one accepted run without mutating the previous history object."""

    before = validate_history(previous)
    if minimum_bad_spacing_seconds < 0:
        raise HistoryValidationError("minimum bad-run spacing must be non-negative")
    valid_run = run_context.get("valid_run")
    accepted = run_context.get("accepted")
    if not isinstance(valid_run, bool) or not isinstance(accepted, bool):
        raise HistoryValidationError("run valid/accepted flags must be boolean")
    if not valid_run or not accepted:
        return copy.deepcopy(before)
    run = {
        "run_id": _run_id(run_context.get("run_id")),
        "source_sha256": _sha256(run_context.get("source_sha256")),
        "accepted_at": _timestamp(run_context.get("accepted_at"), "accepted_at"),
        "identity_key_version": _version(
            run_context.get("identity_key_version"), "identity_key_version"
        ),
        "identity_epoch": _version(run_context.get("identity_epoch"), "identity_epoch"),
        "selection_policy_version": _version(
            run_context.get("selection_policy_version"), "selection_policy_version"
        ),
    }
    if (
        run["identity_key_version"] != before["identity_key_version"]
        or run["identity_epoch"] != before["identity_epoch"]
        or run["selection_policy_version"] != before["selection_policy_version"]
    ):
        raise HistoryValidationError("run identity or policy version disagrees with history")
    if any(
        item["run_id"] == run["run_id"]
        or item["source_sha256"] == run["source_sha256"]
        for item in before["recent_accepted_runs"]
    ):
        return copy.deepcopy(before)
    if before["last_accepted_at"] is not None and _datetime(
        run["accepted_at"], "accepted_at"
    ) <= _datetime(before["last_accepted_at"], "last_accepted_at"):
        raise HistoryValidationError("accepted run is not newer than history")

    normalized_measurements = _normalize_candidate_mapping(
        measurements,
        label="measurements",
        normalize_value=_normalize_measurement,
    )
    normalized_decisions = _normalize_candidate_mapping(
        decisions,
        label="decisions",
        normalize_value=_decision,
    )
    normalized_sources = _normalize_candidate_mapping(
        source_events,
        label="source_events",
        normalize_value=_source_state,
    )

    staged = copy.deepcopy(before)
    aliases: dict[str, str] = {}
    for cid, measurement in normalized_measurements.items():
        if cid in staged["nodes"] or measurement["response_count"] < 1:
            continue
        decision = normalized_decisions.get(cid)
        if decision is None:
            raise HistoryValidationError("responsive new candidate lacks a staged decision")
        aliases[cid] = decision["source_alias"]
    names = allocate_stable_output_names(staged["nodes"], aliases)

    candidate_ids = sorted(
        set(normalized_measurements)
        | set(normalized_decisions)
        | set(normalized_sources)
    )
    for cid in candidate_ids:
        node = staged["nodes"].get(cid)
        measurement = normalized_measurements.get(cid)
        decision = normalized_decisions.get(cid)
        source_state = normalized_sources.get(cid, "present")

        if node is None:
            if source_state in {"confirmed_missing", "invalid_config"}:
                continue
            if measurement is None or measurement["response_count"] == 0:
                continue
            if decision is None:
                raise HistoryValidationError("new candidate lacks a staged decision")
            staged["nodes"][cid] = _new_node(
                cid,
                names[cid],
                decision["proposed_state"],
                run,
                measurement,
                decision,
                source_state,
            )
            continue

        node["source_state"] = source_state
        reason = "temporary_source_failure"
        counted_bad = False
        if source_state == "confirmed_missing":
            _mark_removed(node, "removed_source_missing", "source_confirmed_missing", run)
            reason = "source_confirmed_missing"
        elif source_state == "invalid_config":
            _mark_removed(node, "removed_invalid_config", "invalid_config", run)
            reason = "invalid_config"
        elif measurement is None:
            reason = "temporary_source_failure"
        elif measurement["response_count"] > 0:
            if node["legacy_identity"]:
                raise HistoryMigrationError(
                    "responsive legacy tombstone must be migrated before history reduction"
                )
            if decision is None:
                raise HistoryValidationError(
                    "responsive existing candidate lacks a staged decision"
                )
            target = decision["proposed_state"]
            if target in REMOVED_STATES or target == "history_protected":
                raise HistoryValidationError("responsive candidate has an invalid staged state")
            old_state = node["current_state"]
            recovering = node["removed"] or old_state == "history_protected" or node["bad_run_streak"]
            if recovering:
                reason = (
                    "recovered_quality"
                    if target in {"asia_core", "asia_flexible", "non_asia_stable"}
                    else "recovered_response"
                )
            elif target != old_state:
                reason = "selection_changed"
            else:
                reason = "responsive_observation"
            if reason != "responsive_observation":
                node["previous_state"] = old_state
                node["current_state"] = target
                node["transition_reason"] = reason
                node["last_transition"] = _transition(old_state, target, reason, run)
            node["bad_run_streak"] = 0
            node["removed"] = False
            node["removed_at"] = None
            node["removed_reason"] = None
            node["tombstone_expires_at"] = None
            node["last_seen_at"] = run["accepted_at"]
            if decision is not None and decision["selected"]:
                node["last_selected_at"] = run["accepted_at"]
            if decision is not None and decision["region_cache"] is not None:
                node["region_cache"] = copy.deepcopy(decision["region_cache"])
        elif source_state in {"temporary_failure", "last_good"}:
            reason = "temporary_source_failure"
        elif (
            node["current_state"] in ASIA_STATES
            and not node["removed"]
            and (decision is None or decision["is_asia"])
        ):
            old_state = node["current_state"]
            can_count = source_state == "present"
            if node["last_counted_bad_source_sha256"] == run["source_sha256"]:
                can_count = False
            if node["last_counted_bad_at"] is not None:
                elapsed = (
                    _datetime(run["accepted_at"], "accepted_at")
                    - _datetime(node["last_counted_bad_at"], "last_counted_bad_at")
                ).total_seconds()
                if elapsed < minimum_bad_spacing_seconds:
                    can_count = False
            counted_bad = can_count
            if counted_bad:
                node["bad_run_streak"] = min(node["bad_run_streak"] + 1, 3)
                node["last_counted_bad_source_sha256"] = run["source_sha256"]
                node["last_counted_bad_at"] = run["accepted_at"]
            if node["bad_run_streak"] >= 3:
                reason = "bad_streak_limit"
                _mark_removed(node, "removed_bad_streak", reason, run)
            else:
                reason = "zero_response_bad_run" if counted_bad else "zero_response_not_counted"
                node["previous_state"] = old_state
                node["current_state"] = "history_protected"
                node["transition_reason"] = reason
                node["last_transition"] = _transition(
                    old_state, "history_protected", reason, run
                )
        elif measurement is not None:
            target = decision["proposed_state"] if decision is not None else node["current_state"]
            if target != node["current_state"]:
                old_state = node["current_state"]
                reason = "selection_changed"
                node["previous_state"] = old_state
                node["current_state"] = target
                node["transition_reason"] = reason
                node["last_transition"] = _transition(old_state, target, reason, run)
                node["removed"] = False
                node["removed_at"] = None
                node["removed_reason"] = None
                node["tombstone_expires_at"] = None
            else:
                reason = "zero_response_not_counted"

        if measurement is not None:
            node["last_measurement"] = dict(measurement)
        if source_state == "present":
            node["last_seen_at"] = run["accepted_at"]
        if decision is not None and decision["selected"] and not node["removed"]:
            node["last_selected_at"] = run["accepted_at"]
        observation = _observation(
            run,
            measurement,
            counted_bad=counted_bad,
            state=node["current_state"],
            reason=reason,
            source_state=source_state,
        )
        node["recent_observations"] = (
            node["recent_observations"] + [observation]
        )[-RECENT_OBSERVATION_LIMIT:]

    accepted_run = {
        "run_id": run["run_id"],
        "source_sha256": run["source_sha256"],
        "accepted_at": run["accepted_at"],
    }
    staged["last_accepted_run_id"] = run["run_id"]
    staged["last_accepted_source_sha256"] = run["source_sha256"]
    staged["last_accepted_at"] = run["accepted_at"]
    staged["recent_accepted_runs"] = staged["recent_accepted_runs"] + [accepted_run]
    return validate_history(staged)


def _validated_legacy_profile_proxies(profile: Any) -> list[Mapping[str, Any]]:
    if not isinstance(profile, Mapping):
        raise HistoryMigrationError("legacy profile must be a mapping")
    proxies = profile.get("proxies")
    if not isinstance(proxies, list) or not proxies or not all(
        isinstance(item, Mapping) for item in proxies
    ):
        raise HistoryMigrationError("legacy profile contains no valid proxies")
    proxy_names: set[str] = set()
    for proxy in proxies:
        name = proxy.get("name")
        proxy_type = proxy.get("type")
        server = proxy.get("server")
        if (
            not isinstance(name, str)
            or not name.strip()
            or name != name.strip()
            or not isinstance(proxy_type, str)
            or not proxy_type.strip()
            or not isinstance(server, str)
            or not server.strip()
        ):
            raise HistoryMigrationError("legacy profile contains an invalid proxy")
        try:
            canonical_port(proxy.get("port"))
        except Exception as exc:
            raise HistoryMigrationError("legacy profile contains an invalid proxy") from exc
        if name in proxy_names:
            raise HistoryMigrationError("legacy profile contains missing or duplicate names")
        proxy_names.add(name)

    groups = profile.get("proxy-groups", [])
    if not isinstance(groups, list) or not all(isinstance(item, Mapping) for item in groups):
        raise HistoryMigrationError("legacy profile proxy groups are malformed")
    group_names: set[str] = set()
    for group in groups:
        name = group.get("name")
        if (
            not isinstance(name, str)
            or not name.strip()
            or name != name.strip()
            or name in group_names
            or name in proxy_names
        ):
            raise HistoryMigrationError("legacy profile proxy groups are malformed")
        group_names.add(name)
    allowed_references = proxy_names | group_names | BUILTIN_PROXY_NAMES
    for group in groups:
        references = group.get("proxies")
        if not isinstance(references, list) or any(
            not isinstance(reference, str) or reference not in allowed_references
            for reference in references
        ):
            raise HistoryMigrationError("legacy profile contains dangling group references")
    return proxies


def bootstrap_legacy_profile(
    profile_bytes: bytes,
    status: Mapping[str, Any],
    *,
    identity_settings: IdentitySettings,
    selection_policy_version: str,
) -> dict[str, Any]:
    """Create an explicit v1 history from one verified legacy GMGN profile."""

    if status.get("kind") != "cnb-gmgn-publish-status" or status.get("schema_version") != 1:
        raise HistoryMigrationError("legacy status kind or schema is unsupported")
    expected_sha = _sha256(status.get("profile_sha256"), "profile_sha256")
    if hashlib.sha256(profile_bytes).hexdigest() != expected_sha:
        raise HistoryMigrationError("legacy profile SHA-256 disagrees with status")
    try:
        profile = yaml.safe_load(profile_bytes.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise HistoryMigrationError("legacy profile is invalid YAML") from exc
    proxies = _validated_legacy_profile_proxies(profile)
    expected_count = _non_negative_int(status.get("published_count"), "published_count")
    if len(proxies) != expected_count:
        raise HistoryMigrationError("legacy profile count disagrees with status")
    accepted_at = _timestamp(status.get("run_at"), "legacy run_at")
    run = {
        "run_id": _run_id(status.get("run_id")),
        "source_sha256": _sha256(status.get("source_sha256")),
        "accepted_at": accepted_at,
        "identity_key_version": identity_settings.identity_key_version,
        "identity_epoch": identity_settings.identity_epoch,
    }
    aliases: dict[str, str] = {}
    private_bindings: list[tuple[str, str]] = []
    legacy_names = [str(item["name"]) for item in proxies]
    for proxy in proxies:
        cid = candidate_id(
            proxy,
            key=identity_settings.key,
            identity_key_version=identity_settings.identity_key_version,
            identity_epoch=identity_settings.identity_epoch,
        )
        aliases[cid] = str(proxy.get("name") or "")
        private_bindings.append((cid, canonical_proxy_fingerprint(proxy)))
    if len(aliases) != len(proxies):
        raise HistoryMigrationError("legacy profile contains duplicate proxy identities")
    assert_unique_public_id_bindings(private_bindings)
    names = allocate_stable_output_names({}, aliases)
    history = empty_history(
        identity_key_version=identity_settings.identity_key_version,
        identity_epoch=identity_settings.identity_epoch,
        selection_policy_version=selection_policy_version,
    )
    for cid in sorted(aliases):
        state = "unknown_region"
        reason = "bootstrap_legacy_profile"
        history["nodes"][cid] = {
            "candidate_id": cid,
            "identity_key_version": identity_settings.identity_key_version,
            "identity_epoch": identity_settings.identity_epoch,
            "legacy_identity": False,
            "tombstone_expires_at": None,
            "output_name": names[cid],
            "current_state": state,
            "previous_state": None,
            "transition_reason": reason,
            "last_transition": _transition(None, state, reason, run),
            "bad_run_streak": 0,
            "last_counted_bad_source_sha256": None,
            "last_counted_bad_at": None,
            "recent_observations": [
                _observation(
                    run,
                    None,
                    counted_bad=False,
                    state=state,
                    reason=reason,
                    source_state="present",
                )
            ],
            "first_seen_at": accepted_at,
            "last_seen_at": accepted_at,
            "last_selected_at": accepted_at,
            "source_state": "present",
            "last_measurement": None,
            "region_cache": None,
            "removed": False,
            "removed_at": None,
            "removed_reason": None,
        }
    history["last_accepted_run_id"] = run["run_id"]
    history["last_accepted_source_sha256"] = run["source_sha256"]
    history["last_accepted_at"] = accepted_at
    history["recent_accepted_runs"] = [
        {
            "run_id": run["run_id"],
            "source_sha256": run["source_sha256"],
            "accepted_at": accepted_at,
        }
    ]
    return validate_history(history)


def migrate_history_identity(
    previous: Mapping[str, Any],
    active_proxies: Sequence[Mapping[str, Any]],
    *,
    old_settings: IdentitySettings,
    new_settings: IdentitySettings,
    migrated_at: str,
    active_exit_ips: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Migrate all active nodes one-to-one and retain absent removed tombstones."""

    history = validate_history(previous)
    _timestamp(migrated_at, "migrated_at")
    if (
        history["identity_key_version"] != old_settings.identity_key_version
        or history["identity_epoch"] != old_settings.identity_epoch
    ):
        raise HistoryMigrationError("old identity settings disagree with history")
    mapping: dict[str, tuple[str, Mapping[str, Any]]] = {}
    bindings: list[tuple[str, str]] = []
    for proxy in active_proxies:
        old_id = candidate_id(
            proxy,
            key=old_settings.key,
            identity_key_version=old_settings.identity_key_version,
            identity_epoch=old_settings.identity_epoch,
        )
        new_id = candidate_id(
            proxy,
            key=new_settings.key,
            identity_key_version=new_settings.identity_key_version,
            identity_epoch=new_settings.identity_epoch,
        )
        if old_id in mapping:
            raise HistoryMigrationError("active identity migration is not one-to-one")
        mapping[old_id] = (new_id, proxy)
        bindings.append((new_id, canonical_proxy_fingerprint(proxy)))
    assert_unique_public_id_bindings(bindings)
    staged = copy.deepcopy(history)
    migrated_nodes: dict[str, dict[str, Any]] = {}
    retained_legacy_ids = {
        old_id
        for old_id, node in staged["nodes"].items()
        if old_id not in mapping and node["removed"]
    }
    migrated_active_ids = {new_id for new_id, _proxy in mapping.values()}
    if retained_legacy_ids & migrated_active_ids:
        raise HistoryMigrationError("active identity collides with a legacy tombstone")
    for old_id, node in staged["nodes"].items():
        if old_id in mapping:
            new_id, _proxy = mapping[old_id]
            if new_id in migrated_nodes:
                raise HistoryMigrationError("new identity collision during migration")
            migrated = copy.deepcopy(node)
            migrated["candidate_id"] = new_id
            migrated["identity_key_version"] = new_settings.identity_key_version
            migrated["identity_epoch"] = new_settings.identity_epoch
            migrated["legacy_identity"] = False
            if migrated["region_cache"] is not None and migrated["region_cache"]["exit_id"]:
                if active_exit_ips is None or old_id not in active_exit_ips:
                    raise HistoryMigrationError(
                        "active exit identity cannot be migrated without its public IP handoff"
                    )
                migrated["region_cache"]["exit_id"] = exit_id(
                    active_exit_ips[old_id],
                    key=new_settings.key,
                    identity_key_version=new_settings.identity_key_version,
                    identity_epoch=new_settings.identity_epoch,
                )
            migration_run = {
                "run_id": history["last_accepted_run_id"] or "identity-migration",
                "source_sha256": history["last_accepted_source_sha256"] or ("0" * 64),
                "accepted_at": migrated_at,
            }
            migrated["previous_state"] = migrated["current_state"]
            migrated["transition_reason"] = "identity_migrated"
            migrated["last_transition"] = _transition(
                migrated["current_state"],
                migrated["current_state"],
                "identity_migrated",
                migration_run,
            )
            migrated_nodes[new_id] = migrated
        else:
            if not node["removed"]:
                raise HistoryMigrationError(
                    "an active history node is missing from the migration snapshot"
                )
            legacy = copy.deepcopy(node)
            legacy["legacy_identity"] = True
            if old_id in migrated_nodes:
                raise HistoryMigrationError("legacy identity collision during migration")
            migrated_nodes[old_id] = legacy
    staged["identity_key_version"] = new_settings.identity_key_version
    staged["identity_epoch"] = new_settings.identity_epoch
    staged["nodes"] = migrated_nodes
    return validate_history(staged)


def reconcile_legacy_tombstone(
    previous: Mapping[str, Any],
    proxy: Mapping[str, Any],
    *,
    active_settings: IdentitySettings,
    legacy_key_registry: Mapping[tuple[str, str], bytes | str],
    observed_at: str,
) -> tuple[dict[str, Any], str, bool]:
    """Migrate a reappearing legacy tombstone to the active public identity."""

    history = validate_history(previous)
    _timestamp(observed_at, "observed_at")
    active_id = candidate_id(
        proxy,
        key=active_settings.key,
        identity_key_version=active_settings.identity_key_version,
        identity_epoch=active_settings.identity_epoch,
    )
    if active_id in history["nodes"]:
        if history["nodes"][active_id]["legacy_identity"]:
            raise HistoryMigrationError(
                "active identity collides with a legacy tombstone"
            )
        return copy.deepcopy(history), active_id, False
    match: str | None = None
    for cid, node in history["nodes"].items():
        if not node["legacy_identity"]:
            continue
        registry_key = (node["identity_key_version"], node["identity_epoch"])
        if registry_key not in legacy_key_registry:
            raise HistoryMigrationError("legacy identity key is unavailable")
        if candidate_id(
            proxy,
            key=legacy_key_registry[registry_key],
            identity_key_version=registry_key[0],
            identity_epoch=registry_key[1],
        ) == cid:
            if match is not None:
                raise HistoryMigrationError("legacy tombstone match is ambiguous")
            match = cid
    if match is None:
        return copy.deepcopy(history), active_id, False
    staged = copy.deepcopy(history)
    node = staged["nodes"].pop(match)
    node["candidate_id"] = active_id
    node["identity_key_version"] = active_settings.identity_key_version
    node["identity_epoch"] = active_settings.identity_epoch
    node["legacy_identity"] = False
    node["region_cache"] = None
    run = {
        "run_id": history["last_accepted_run_id"] or "identity-migration",
        "source_sha256": history["last_accepted_source_sha256"] or ("0" * 64),
        "accepted_at": observed_at,
    }
    node["previous_state"] = node["current_state"]
    node["transition_reason"] = "legacy_identity_reappeared"
    node["last_transition"] = _transition(
        node["current_state"],
        node["current_state"],
        "legacy_identity_reappeared",
        run,
    )
    staged["nodes"][active_id] = node
    return validate_history(staged), active_id, True


def garbage_collect_tombstones(
    previous: Mapping[str, Any],
    candidate_ids: Iterable[str],
    *,
    gc_at: str,
    audit_reason: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Explicitly remove expired tombstones and return public audit evidence."""

    history = validate_history(previous)
    now_text = _timestamp(gc_at, "gc_at")
    now = _datetime(now_text, "gc_at")
    if not isinstance(audit_reason, str) or audit_reason != audit_reason.strip():
        raise HistoryMigrationError("audited GC requires a safe reason")
    reason = audit_reason
    if (
        not RUN_ID_RE.fullmatch(reason)
        or URL_RE.search(reason)
        or FINGERPRINT_TEXT_RE.search(reason)
        or _contains_ip(reason)
    ):
        raise HistoryMigrationError("audited GC requires a safe reason")
    staged = copy.deepcopy(history)
    evidence: list[dict[str, Any]] = []
    for raw_cid in sorted(set(candidate_ids)):
        cid = validate_public_id(raw_cid, "candidate")
        node = staged["nodes"].get(cid)
        if node is None or not node["removed"]:
            raise HistoryMigrationError("audited GC target is not a removed tombstone")
        expires = _datetime(node["tombstone_expires_at"], "tombstone_expires_at")
        if now < expires:
            raise HistoryMigrationError("audited GC target has not reached retention age")
        last_seen = _datetime(node["last_seen_at"], "last_seen_at")
        evidence.append(
            {
                "candidate_id": cid,
                "output_name": node["output_name"],
                "removed_reason": node["removed_reason"],
                "last_seen_at": node["last_seen_at"],
                "age_seconds": int((now - last_seen).total_seconds()),
                "legacy_identity": node["legacy_identity"],
                "gc_at": now_text,
                "audit_reason": reason,
            }
        )
        del staged["nodes"][cid]
    return validate_history(staged), evidence


def legacy_tombstone_count(history: Mapping[str, Any]) -> int:
    normalized = validate_history(history)
    return sum(bool(node["legacy_identity"]) for node in normalized["nodes"].values())


__all__ = [
    "ASIA_STATES",
    "BAD_RUN_SPACING_SECONDS",
    "HISTORY_KIND",
    "HISTORY_POLICY_VERSION",
    "HISTORY_SCHEMA_VERSION",
    "HistoryError",
    "HistoryMigrationError",
    "HistoryValidationError",
    "REMOVED_STATES",
    "STATES",
    "allocate_stable_output_names",
    "bootstrap_legacy_profile",
    "empty_history",
    "garbage_collect_tombstones",
    "history_json_bytes",
    "legacy_tombstone_count",
    "load_history",
    "migrate_history_identity",
    "reconcile_legacy_tombstone",
    "reduce_history",
    "sanitize_output_alias",
    "validate_history",
    "write_history_atomic",
]
