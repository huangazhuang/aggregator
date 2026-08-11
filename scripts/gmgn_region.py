#!/usr/bin/env python3
"""Pure GMGN V2 exit-region planning and cache resolution.

The network-facing caller owns the provider request and the controlled identity
stage owns opaque ``exit_id``/``asn_id`` generation.  This module only validates
those precomputed observations and deterministically resolves them against the
validated C1 metadata and C3 history cache.
"""

from __future__ import annotations

import copy
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable, Mapping

from scripts.gmgn_history import validate_history
from scripts.proxy_identity import validate_identity_version, validate_public_id


REGION_POLICY_VERSION = "gmgn-region-v1"
REGION_OBSERVATION_KIND = "cnb-gmgn-region-observation"
REGION_OBSERVATION_SCHEMA_VERSION = 1
REGION_DECISION_KIND = "cnb-gmgn-region-decision"
REGION_DECISION_SCHEMA_VERSION = 1
REGION_PROVIDER_SCHEMA_VERSION = "provider-v1"
REGION_CACHE_TTL_SECONDS = 7 * 24 * 3600
HISTORY_CACHE_GRACE_SECONDS = 30 * 24 * 3600
TARGET_ASIA_REGIONS = ("HK", "JP", "KR", "SG", "TW")

_RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$"
)
_ASN_ID_RE = re.compile(r"^asn1_[0-9a-f]{24}$")
_REGION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_OBSERVATION_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "candidate_id",
        "identity_key_version",
        "identity_epoch",
        "country_code",
        "region_code",
        "exit_id",
        "asn_id",
        "observed_at",
        "provider_schema",
    }
)
_DECISION_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "candidate_id",
        "identity_key_version",
        "identity_epoch",
        "country_code",
        "region_code",
        "exit_id",
        "asn_id",
        "confidence",
        "verified_target_asia",
        "temporary_target_asia",
        "stale",
        "reason",
        "source_region",
        "cache",
    }
)
_CACHE_FIELDS = frozenset(
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
_CONFIDENCE = frozenset({"verified", "source-specific", "unknown", "conflict"})
_REASONS = frozenset(
    {
        "live_verified",
        "live_source_conflict",
        "cache_fresh",
        "cache_source_conflict",
        "history_cache_grace",
        "history_cache_grace_conflict",
        "source_specific_fallback",
        "region_unknown",
    }
)


class RegionError(ValueError):
    """A region observation/cache contract cannot be safely consumed."""


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _RFC3339_UTC_RE.fullmatch(value):
        raise RegionError(f"{label} must be a canonical UTC timestamp")
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RegionError(f"{label} is invalid") from exc
    return value


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _version(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _REGION_RE.fullmatch(value):
        raise RegionError(f"{label} is invalid")
    return value


def _country(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Z]{2}", value):
        raise RegionError("country_code must be an uppercase ISO-like code")
    return value


def _region_code(value: Any) -> str:
    if not isinstance(value, str) or (value and not _REGION_RE.fullmatch(value)):
        raise RegionError("region_code is invalid")
    return value


def _asn_id(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _ASN_ID_RE.fullmatch(value):
        raise RegionError("asn_id must be an opaque ASN identity")
    return value


def reliable_source_region(metadata: Mapping[str, Any]) -> str | None:
    """Return one unambiguous country-specific source hint, never a name hint."""

    evidence = metadata.get("region_evidence")
    if not isinstance(evidence, list):
        raise RegionError("candidate region evidence must be a list")
    regions = {
        match.group(1)
        for value in evidence
        if isinstance(value, str)
        for match in [re.fullmatch(r"source_hint:(HK|JP|KR|SG|TW)", value)]
        if match is not None
    }
    return next(iter(regions)) if len(regions) == 1 else None


def validate_region_observation(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or frozenset(raw) != _OBSERVATION_FIELDS:
        raise RegionError("region observation fields are incomplete or unexpected")
    value = dict(raw)
    if (
        value["kind"] != REGION_OBSERVATION_KIND
        or value["schema_version"] != REGION_OBSERVATION_SCHEMA_VERSION
    ):
        raise RegionError("region observation kind or schema is unsupported")
    provider_schema = _version(value["provider_schema"], "provider_schema")
    if provider_schema != REGION_PROVIDER_SCHEMA_VERSION:
        raise RegionError("region observation provider schema is unsupported")
    return {
        "kind": REGION_OBSERVATION_KIND,
        "schema_version": REGION_OBSERVATION_SCHEMA_VERSION,
        "candidate_id": validate_public_id(value["candidate_id"], "candidate"),
        "identity_key_version": validate_identity_version(
            value["identity_key_version"], "identity_key_version"
        ),
        "identity_epoch": validate_identity_version(
            value["identity_epoch"], "identity_epoch"
        ),
        "country_code": _country(value["country_code"]),
        "region_code": _region_code(value["region_code"]),
        "exit_id": validate_public_id(value["exit_id"], "exit"),
        "asn_id": _asn_id(value["asn_id"]),
        "observed_at": _timestamp(value["observed_at"], "observed_at"),
        "provider_schema": provider_schema,
    }


def _measurement_response_count(raw: Any) -> int:
    if not isinstance(raw, Mapping):
        raise RegionError("candidate measurement must be an object")
    value = raw.get("response_count")
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 20:
        raise RegionError("candidate response_count is invalid")
    return value


def build_region_query_plan(
    candidates: Mapping[str, Mapping[str, Any]],
    measurements: Mapping[str, Mapping[str, Any]],
    history: Mapping[str, Any],
) -> list[str]:
    """Plan only responders and still-protected historical candidates."""

    normalized_history = validate_history(history)
    if set(candidates) != set(measurements):
        raise RegionError("candidate and measurement identity sets disagree")
    planned: list[str] = []
    for raw_candidate in sorted(candidates):
        candidate_id = validate_public_id(raw_candidate, "candidate")
        response_count = _measurement_response_count(measurements[candidate_id])
        node = normalized_history["nodes"].get(candidate_id)
        protected = bool(
            node
            and not node["removed"]
            and node["current_state"] == "history_protected"
            and node["bad_run_streak"] in {1, 2}
        )
        if response_count >= 1 or protected:
            planned.append(candidate_id)
    return planned


def collect_region_observations(
    candidate_ids: Iterable[str],
    provider: Callable[[str], Mapping[str, Any] | None],
) -> dict[str, dict[str, Any]]:
    """Call a mockable provider adapter without embedding any network policy here."""

    observations: dict[str, dict[str, Any]] = {}
    for raw_candidate in sorted(set(candidate_ids)):
        candidate_id = validate_public_id(raw_candidate, "candidate")
        raw = provider(candidate_id)
        if raw is None:
            continue
        observation = validate_region_observation(raw)
        if observation["candidate_id"] != candidate_id:
            raise RegionError("region provider returned the wrong candidate identity")
        observations[candidate_id] = observation
    return observations


def _cache_from_observation(observation: Mapping[str, Any]) -> dict[str, Any]:
    observed_at = _datetime(str(observation["observed_at"]))
    return {
        "country_code": observation["country_code"],
        "region_code": observation["region_code"],
        "exit_id": observation["exit_id"],
        "asn_id": observation["asn_id"],
        "queried_at": observation["observed_at"],
        "expires_at": _format_timestamp(
            observed_at + timedelta(seconds=REGION_CACHE_TTL_SECONDS)
        ),
        "stale": False,
        "policy_version": REGION_POLICY_VERSION,
    }


def _validate_public_cache(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or frozenset(raw) != _CACHE_FIELDS:
        raise RegionError("region cache fields are incomplete or unexpected")
    value = dict(raw)
    country = _country(value["country_code"])
    region = _region_code(value["region_code"])
    exit_value = validate_public_id(value["exit_id"], "exit")
    asn = _asn_id(value["asn_id"])
    queried = _timestamp(value["queried_at"], "region_cache.queried_at")
    expires = _timestamp(value["expires_at"], "region_cache.expires_at")
    if _datetime(expires) <= _datetime(queried):
        raise RegionError("region cache expiry must follow its query time")
    if (_datetime(expires) - _datetime(queried)).total_seconds() != REGION_CACHE_TTL_SECONDS:
        raise RegionError("region cache TTL disagrees with the region policy")
    if not isinstance(value["stale"], bool):
        raise RegionError("region cache stale flag must be boolean")
    if value["policy_version"] != REGION_POLICY_VERSION:
        raise RegionError("region cache policy version is unsupported")
    return {
        "country_code": country,
        "region_code": region,
        "exit_id": exit_value,
        "asn_id": asn,
        "queried_at": queried,
        "expires_at": expires,
        "stale": value["stale"],
        "policy_version": REGION_POLICY_VERSION,
    }


def _history_cache(
    node: Mapping[str, Any] | None,
    *,
    now: datetime,
    allow_grace: bool,
) -> tuple[dict[str, Any] | None, bool]:
    if not node or node.get("region_cache") is None:
        return None, False
    cache = copy.deepcopy(dict(node["region_cache"]))
    if cache.get("policy_version") != REGION_POLICY_VERSION:
        return None, False
    queried_at = _datetime(_timestamp(cache.get("queried_at"), "region_cache.queried_at"))
    expires_at = _datetime(_timestamp(cache.get("expires_at"), "region_cache.expires_at"))
    if (expires_at - queried_at).total_seconds() != REGION_CACHE_TTL_SECONDS:
        return None, False
    if queried_at > now:
        return None, False
    if now <= expires_at:
        cache["stale"] = False
        return cache, False
    if allow_grace and (now - queried_at).total_seconds() <= HISTORY_CACHE_GRACE_SECONDS:
        cache["stale"] = True
        return cache, True
    return None, False


def _decision(
    *,
    candidate_id: str,
    identity_key_version: str,
    identity_epoch: str,
    country_code: str,
    region_code: str,
    exit_id: str | None,
    asn_id: str | None,
    confidence: str,
    stale: bool,
    reason: str,
    source_region: str | None,
    cache: Mapping[str, Any] | None,
) -> dict[str, Any]:
    value = {
        "kind": REGION_DECISION_KIND,
        "schema_version": REGION_DECISION_SCHEMA_VERSION,
        "candidate_id": candidate_id,
        "identity_key_version": identity_key_version,
        "identity_epoch": identity_epoch,
        "country_code": country_code,
        "region_code": region_code,
        "exit_id": exit_id,
        "asn_id": asn_id,
        "confidence": confidence,
        "verified_target_asia": confidence in {"verified", "conflict"}
        and country_code in TARGET_ASIA_REGIONS,
        "temporary_target_asia": confidence == "source-specific"
        and source_region in TARGET_ASIA_REGIONS,
        "stale": stale,
        "reason": reason,
        "source_region": source_region,
        "cache": copy.deepcopy(dict(cache)) if cache is not None else None,
    }
    return validate_region_decision(value)


def validate_region_decision(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or frozenset(raw) != _DECISION_FIELDS:
        raise RegionError("region decision fields are incomplete or unexpected")
    value = dict(raw)
    if (
        value["kind"] != REGION_DECISION_KIND
        or value["schema_version"] != REGION_DECISION_SCHEMA_VERSION
    ):
        raise RegionError("region decision kind or schema is unsupported")
    candidate_id = validate_public_id(value["candidate_id"], "candidate")
    key_version = validate_identity_version(
        value["identity_key_version"], "identity_key_version"
    )
    epoch = validate_identity_version(value["identity_epoch"], "identity_epoch")
    country = value["country_code"]
    if country != "":
        country = _country(country)
    region = _region_code(value["region_code"])
    exit_value = value["exit_id"]
    if exit_value is not None:
        exit_value = validate_public_id(exit_value, "exit")
    asn = _asn_id(value["asn_id"])
    confidence = value["confidence"]
    reason = value["reason"]
    source_region = value["source_region"]
    if confidence not in _CONFIDENCE or reason not in _REASONS:
        raise RegionError("region decision confidence or reason is unsupported")
    if source_region is not None and source_region not in TARGET_ASIA_REGIONS:
        raise RegionError("region decision source_region is unsupported")
    for name in ("verified_target_asia", "temporary_target_asia", "stale"):
        if not isinstance(value[name], bool):
            raise RegionError(f"region decision {name} must be boolean")
    if value["verified_target_asia"] != (
        confidence in {"verified", "conflict"} and country in TARGET_ASIA_REGIONS
    ):
        raise RegionError("verified_target_asia contradicts region evidence")
    if value["temporary_target_asia"] != (
        confidence == "source-specific" and source_region in TARGET_ASIA_REGIONS
    ):
        raise RegionError("temporary_target_asia contradicts source evidence")
    cache = value["cache"]
    if confidence in {"verified", "conflict"}:
        if cache is None or exit_value is None or not country:
            raise RegionError("verified region decision is missing cache identity")
        cache = _validate_public_cache(cache)
        if cache["country_code"] != country or cache["exit_id"] != exit_value:
            raise RegionError("region decision disagrees with its cache")
        if cache["asn_id"] != asn or cache["region_code"] != region or cache["stale"] != value["stale"]:
            raise RegionError("region decision cache metadata is inconsistent")
    elif cache is not None:
        raise RegionError("unverified region decision cannot expose a cache record")
    return {
        **value,
        "candidate_id": candidate_id,
        "identity_key_version": key_version,
        "identity_epoch": epoch,
        "country_code": country,
        "region_code": region,
        "exit_id": exit_value,
        "asn_id": asn,
        "cache": copy.deepcopy(dict(cache)) if cache is not None else None,
    }


def resolve_region_decisions(
    candidates: Mapping[str, Mapping[str, Any]],
    measurements: Mapping[str, Mapping[str, Any]],
    history: Mapping[str, Any],
    observations: Mapping[str, Mapping[str, Any]],
    *,
    now: str,
) -> dict[str, dict[str, Any]]:
    """Resolve real exit evidence first, then cache, then source-only fallback."""

    normalized_history = validate_history(history)
    key_version = normalized_history["identity_key_version"]
    epoch = normalized_history["identity_epoch"]
    now_value = _datetime(_timestamp(now, "now"))
    if set(candidates) != set(measurements):
        raise RegionError("candidate and measurement identity sets disagree")
    normalized_observations: dict[str, dict[str, Any]] = {}
    for raw_candidate, raw in observations.items():
        candidate_id = validate_public_id(raw_candidate, "candidate")
        if candidate_id not in candidates:
            raise RegionError("region observation references an unknown candidate")
        observation = validate_region_observation(raw)
        if observation["candidate_id"] != candidate_id:
            raise RegionError("region observation key and candidate_id disagree")
        if (
            observation["identity_key_version"] != key_version
            or observation["identity_epoch"] != epoch
        ):
            raise RegionError("region observation identity version mismatch")
        if _datetime(observation["observed_at"]) > now_value:
            raise RegionError("region observation is in the future")
        if (
            now_value - _datetime(observation["observed_at"])
        ).total_seconds() > REGION_CACHE_TTL_SECONDS:
            raise RegionError("region observation is older than the cache TTL")
        normalized_observations[candidate_id] = observation

    planned = set(build_region_query_plan(candidates, measurements, normalized_history))
    if not set(normalized_observations).issubset(planned):
        raise RegionError("region observation was not part of the query plan")

    decisions: dict[str, dict[str, Any]] = {}
    for raw_candidate in sorted(candidates):
        candidate_id = validate_public_id(raw_candidate, "candidate")
        metadata = candidates[candidate_id]
        source_region = reliable_source_region(metadata)
        observation = normalized_observations.get(candidate_id)
        node = normalized_history["nodes"].get(candidate_id)
        protected = bool(
            node
            and not node["removed"]
            and node["current_state"] == "history_protected"
            and node["bad_run_streak"] in {1, 2}
        )
        response_count = _measurement_response_count(measurements[candidate_id])
        if observation is not None:
            cache = _cache_from_observation(observation)
            conflict = source_region is not None and source_region != observation["country_code"]
            decisions[candidate_id] = _decision(
                candidate_id=candidate_id,
                identity_key_version=key_version,
                identity_epoch=epoch,
                country_code=observation["country_code"],
                region_code=observation["region_code"],
                exit_id=observation["exit_id"],
                asn_id=observation["asn_id"],
                confidence="conflict" if conflict else "verified",
                stale=False,
                reason="live_source_conflict" if conflict else "live_verified",
                source_region=source_region,
                cache=cache,
            )
            continue
        cache, stale = _history_cache(node, now=now_value, allow_grace=protected)
        if cache is not None:
            conflict = source_region is not None and source_region != cache["country_code"]
            if stale:
                reason = "history_cache_grace_conflict" if conflict else "history_cache_grace"
            else:
                reason = "cache_source_conflict" if conflict else "cache_fresh"
            decisions[candidate_id] = _decision(
                candidate_id=candidate_id,
                identity_key_version=key_version,
                identity_epoch=epoch,
                country_code=str(cache["country_code"]),
                region_code=str(cache["region_code"]),
                exit_id=cache["exit_id"],
                asn_id=cache["asn_id"],
                confidence="conflict" if conflict else "verified",
                stale=stale,
                reason=reason,
                source_region=source_region,
                cache=cache,
            )
            continue
        if source_region is not None and response_count >= 1:
            decisions[candidate_id] = _decision(
                candidate_id=candidate_id,
                identity_key_version=key_version,
                identity_epoch=epoch,
                country_code="",
                region_code="",
                exit_id=None,
                asn_id=None,
                confidence="source-specific",
                stale=False,
                reason="source_specific_fallback",
                source_region=source_region,
                cache=None,
            )
            continue
        decisions[candidate_id] = _decision(
            candidate_id=candidate_id,
            identity_key_version=key_version,
            identity_epoch=epoch,
            country_code="",
            region_code="",
            exit_id=None,
            asn_id=None,
            confidence="unknown",
            stale=False,
            reason="region_unknown",
            source_region=source_region,
            cache=None,
        )
    return decisions


__all__ = [
    "HISTORY_CACHE_GRACE_SECONDS",
    "REGION_CACHE_TTL_SECONDS",
    "REGION_DECISION_KIND",
    "REGION_DECISION_SCHEMA_VERSION",
    "REGION_OBSERVATION_KIND",
    "REGION_OBSERVATION_SCHEMA_VERSION",
    "REGION_POLICY_VERSION",
    "REGION_PROVIDER_SCHEMA_VERSION",
    "RegionError",
    "TARGET_ASIA_REGIONS",
    "build_region_query_plan",
    "collect_region_observations",
    "reliable_source_region",
    "resolve_region_decisions",
    "validate_region_decision",
    "validate_region_observation",
]
