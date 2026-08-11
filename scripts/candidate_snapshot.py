#!/usr/bin/env python3
"""Build and strictly validate GitHub candidate snapshot V2 artifacts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from scripts.candidate_sources import (
    ENDPOINT_SAFETY_POLICY_VERSION,
    SAFE_PUBLIC_ALIAS_RE,
    SOURCE_OUTCOMES,
    SOURCE_POLICY_VERSION,
    CandidateSourceError,
    merge_provenance_staging,
    utc_timestamp,
    validate_proxy_endpoint,
)
from scripts.asia_source_registry import estimate_gmgn_capacity
from scripts.pipeline_utils import BUILTIN_PROXY_NAMES, dump_clash_yaml
from scripts.proxy_identity import (
    IdentityError,
    IdentitySettings,
    assert_unique_public_id_bindings,
    canonical_endpoint,
    canonical_proxy_fingerprint,
    canonical_server,
    compute_public_ids,
    load_identity_test_vector,
    validate_public_id,
    verify_identity_test_vector,
)
from subscribe.asia import is_preferred_asian_proxy, preferred_asia_region_hints


IDENTITY_INPUT_KIND = "github-candidate-identity-input"
IDENTITY_INPUT_SCHEMA_VERSION = 1
CANDIDATE_STATUS_KIND = "github-candidate-status"
CANDIDATE_STATUS_SCHEMA_VERSION = 2
CANDIDATE_METADATA_KIND = "github-candidate-metadata"
CANDIDATE_METADATA_SCHEMA_VERSION = 1
IDENTITY_FIXTURE_VERSION = "identity-fixture-v1"
CANDIDATE_PUBLISH_POLICY_VERSION = "candidate-publish-v1"

LAST_GOOD_MAX_AGE_SECONDS = 48 * 3600
MISSING_CONFIRMATION_COUNT = 3
MISSING_CONFIRMATION_SPACING_SECONDS = 6 * 3600
MISSING_MIN_AGE_SECONDS = 48 * 3600
TOTAL_RETAIN_RATIO = 0.60
ASIA_RETAIN_RATIO = 0.70
REGION_RETAIN_RATIO = 0.50
SOURCE_QUORUM_RATIO = 0.80
REGION_ORDER = ("HK", "JP", "KR", "SG", "TW")

SNAPSHOT_ID_RE = re.compile(r"^candidate_[0-9a-f]{24}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAIN_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
SAFE_ALIAS_SECRET_RE = re.compile(
    r"://|\b(?:token|password|passwd|secret|authorization|subscription)\s*[=:]",
    flags=re.I,
)
DYNAMIC_ALIAS_SUFFIX_RE = re.compile(
    r"(?:\s*[-|/]\s*)?(?:\d+(?:\.\d+)?\s*ms|\d+(?:\.\d+)?\s*%|delay\s*[:=].*)$",
    flags=re.I,
)

IDENTITY_INPUT_FIELDS = {
    "kind",
    "schema_version",
    "source_policy_version",
    "endpoint_safety_policy_version",
    "endpoint_checked_at",
    "run_at",
    "mode",
    "main_sha",
    "profile_url",
    "candidate_metadata_url",
    "raw_count",
    "valid_config_count",
    "exact_unique_count",
    "unique_endpoint_count",
    "github_failed_count",
    "profile",
    "sources",
    "records",
    "previous_state",
    "previous_profile",
    "previous_status",
    "previous_metadata",
}
INPUT_RECORD_FIELDS = {
    "proxy",
    "alias",
    "source_id",
    "source_alias",
    "source_visibility",
    "source_last_success_at",
    "observed_at",
    "region_hints",
    "region_evidence",
}
METADATA_FIELDS = {
    "kind",
    "schema_version",
    "snapshot_id",
    "profile_sha256",
    "identity_key_version",
    "identity_epoch",
    "source_policy_version",
    "endpoint_safety_policy_version",
    "endpoint_checked_at",
    "candidate_count",
    "identity_preflight",
    "candidates",
    "sources",
}
PREFLIGHT_FIELDS = {
    "fixture_version",
    "candidate_id",
    "server_id",
    "endpoint_id",
    "exit_id",
}
CANDIDATE_FIELDS = {
    "aliases",
    "source_ids",
    "first_seen_at",
    "last_seen_at",
    "source_last_success_at",
    "region_hints",
    "region_evidence",
    "protected_asia",
    "github_check_state",
    "protocol",
    "server_id",
    "endpoint_id",
    "endpoint_safety_policy_version",
    "endpoint_checked_at",
}
SOURCE_FIELDS = {
    "alias",
    "visibility",
    "health_state",
    "last_event",
    "last_attempt_at",
    "last_success_at",
    "last_success_content_sha256",
    "last_success_candidate_count",
    "last_success_region_counts",
    "consecutive_failures",
    "candidate_count",
    "last_good_candidate_count",
    "missing_candidates",
}
REGION_COUNT_FIELDS = {*REGION_ORDER, "unknown"}
SOURCE_COUNT_FIELDS = {
    "configured",
    "healthy",
    "last_good",
    "observing",
    "confirmed_missing",
    "failed",
}
GITHUB_COUNT_FIELDS = {"passed", "failed", "bypassed_asia"}
PREVIOUS_FIELDS = {
    "state",
    "snapshot_id",
    "candidate_count",
    "protected_asia_count",
    "region_hint_counts",
}
CHANGES_FIELDS = {"candidate_count", "protected_asia_count", "regions"}
RETAIN_RATIO_FIELDS = {"candidate", "protected_asia", "regions"}
SOURCE_QUORUM_FIELDS = {"eligible", "healthy_or_last_good", "ratio", "required_ratio"}
PUBLISH_GATE_FIELDS = {"passed", "reasons", "policy_version"}
MISSING_FIELDS = {
    "last_seen_at",
    "confirmations",
    "first_missing_at",
    "last_missing_at",
    "confirmed_missing",
}
STATUS_FIELDS = {
    "kind",
    "schema_version",
    "snapshot_id",
    "run_at",
    "main_sha",
    "mode",
    "profile_url",
    "profile_sha256",
    "candidate_metadata_url",
    "candidate_metadata_sha256",
    "candidate_metadata_schema_version",
    "candidate_metadata_count",
    "identity_key_version",
    "identity_epoch",
    "source_policy_version",
    "endpoint_safety_policy_version",
    "policy_version",
    "raw_count",
    "valid_config_count",
    "exact_unique_count",
    "unique_endpoint_count",
    "candidate_count",
    "protected_asia_count",
    "region_hint_counts",
    "source_counts",
    "github_check_counts",
    "previous",
    "changes",
    "retain_ratios",
    "source_quorum",
    "publish_gate",
}


class CandidateSnapshotError(ValueError):
    """Raised when a candidate snapshot cannot be safely accepted."""


@dataclass(frozen=True)
class CandidateSnapshotEntry:
    candidate_id: str
    proxy: dict[str, Any]
    metadata: dict[str, Any]


@dataclass(frozen=True)
class CandidateSnapshot:
    profile_bytes: bytes
    status: dict[str, Any]
    metadata: dict[str, Any]
    ordered_candidates: tuple[CandidateSnapshotEntry, ...]
    snapshot_id: str
    main_sha: str
    profile_sha256: str
    metadata_sha256: str
    identity_key_version: str
    identity_epoch: str


def _parse_timestamp(value: Any) -> datetime:
    normalized = utc_timestamp(str(value or ""))
    return datetime.fromisoformat(normalized.replace("Z", "+00:00"))


def _seconds_between(later: Any, earlier: Any) -> float:
    return (_parse_timestamp(later) - _parse_timestamp(earlier)).total_seconds()


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _load_json_file(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    source = Path(path)
    if not source.is_file():
        return None
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CandidateSnapshotError("previous candidate JSON is unreadable") from exc
    if not isinstance(value, dict):
        raise CandidateSnapshotError("previous candidate JSON must be an object")
    return value


def _load_profile_file(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    source = Path(path)
    if not source.is_file():
        return None
    try:
        value = yaml.safe_load(source.read_bytes())
    except Exception as exc:
        raise CandidateSnapshotError("previous candidate profile is unreadable") from exc
    if not isinstance(value, dict):
        raise CandidateSnapshotError("previous candidate profile must be a mapping")
    return value


def _clash_module() -> Any:
    subscribe_dir = str(Path(__file__).resolve().parents[1] / "subscribe")
    if subscribe_dir not in sys.path:
        sys.path.insert(0, subscribe_dir)
    import clash  # type: ignore

    return clash


def _validated_proxy(proxy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(proxy, Mapping):
        raise CandidateSnapshotError("candidate proxy must be a mapping")
    candidate = copy.deepcopy(dict(proxy))
    try:
        valid = _clash_module().verify(candidate, mihomo=True)
    except Exception as exc:
        raise CandidateSnapshotError("candidate proxy validation failed") from exc
    if not valid:
        raise CandidateSnapshotError("candidate proxy validation failed")
    return candidate


def _profile_proxies(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    proxies = profile.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        raise CandidateSnapshotError("candidate profile contains no proxies")
    return [_validated_proxy(proxy) for proxy in proxies if isinstance(proxy, Mapping)]


def _safe_alias(value: Any) -> str:
    alias = "".join(char for char in str(value or "") if ord(char) >= 32 and ord(char) != 127)
    alias = re.sub(r"\s+", " ", alias).strip()
    alias = DYNAMIC_ALIAS_SUFFIX_RE.sub("", alias).strip(" -|/")
    if not alias or SAFE_ALIAS_SECRET_RE.search(alias):
        return ""
    return alias[:96].rstrip()


def _proxy_representative_key(proxy: Mapping[str, Any]) -> str:
    """Choose the same representative when duplicate configs arrive in any order."""

    value = copy.deepcopy(dict(proxy))
    value.pop("name", None)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _proxy_secret_values(proxy: Mapping[str, Any]) -> tuple[str, ...]:
    values: set[str] = set()
    for field in (
        "password",
        "uuid",
        "username",
        "token",
        "psk",
        "auth",
        "auth-str",
        "obfs-password",
        "private-key",
    ):
        value = str(proxy.get(field, "") or "").strip()
        if len(value) >= 6:
            values.add(value)
    return tuple(sorted(values))


def _safe_proxy_alias(value: Any, proxy: Mapping[str, Any]) -> str:
    alias = _safe_alias(value)
    if any(secret in alias for secret in _proxy_secret_values(proxy)):
        return ""
    return alias


def _read_github_failed_count(path: str | Path | None) -> int:
    if not path:
        return 0
    payload = _load_json_file(path)
    if not payload:
        return 0
    required = {"kind", "schema_version", "policy_version", "tested", "passed", "failed", "bypassed_asia"}
    if set(payload) != required or payload["kind"] != "github-reachability-report" or payload["schema_version"] != 1:
        raise CandidateSnapshotError("GitHub reachability report is malformed")
    values = {name: payload[name] for name in ("tested", "passed", "failed", "bypassed_asia")}
    if any(not isinstance(value, int) or value < 0 for value in values.values()):
        raise CandidateSnapshotError("GitHub reachability report counts are invalid")
    if values["passed"] + values["failed"] != values["tested"]:
        raise CandidateSnapshotError("GitHub reachability report counts are inconsistent")
    return values["failed"]


def prepare_candidate_identity_input(
    profile_bytes: bytes,
    provenance: Mapping[str, Any],
    *,
    run_at: str,
    mode: str,
    main_sha: str,
    profile_url: str,
    candidate_metadata_url: str,
    previous_state: str,
    previous_profile: Mapping[str, Any] | None = None,
    previous_status: Mapping[str, Any] | None = None,
    previous_metadata: Mapping[str, Any] | None = None,
    github_failed_count: int = 0,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Collection-stage validator that performs all DNS and untrusted-input work."""

    timestamp = utc_timestamp(run_at)
    try:
        parsed_profile = yaml.safe_load(profile_bytes)
    except Exception as exc:
        raise CandidateSnapshotError("candidate profile is invalid YAML") from exc
    if not isinstance(parsed_profile, dict):
        raise CandidateSnapshotError("candidate profile must be a mapping")
    current_proxies = _profile_proxies(parsed_profile)
    if previous_state not in {"confirmed_absent", "present"}:
        raise CandidateSnapshotError("previous candidate state is unsupported")
    if previous_state == "confirmed_absent":
        if any(value is not None for value in (previous_profile, previous_status, previous_metadata)):
            raise CandidateSnapshotError("confirmed-absent previous state contains artifacts")
    elif any(value is None for value in (previous_profile, previous_status, previous_metadata)):
        raise CandidateSnapshotError("present previous snapshot is incomplete")

    records = provenance.get("records") if isinstance(provenance, Mapping) else None
    sources = provenance.get("sources") if isinstance(provenance, Mapping) else None
    if not isinstance(records, list) or not isinstance(sources, list):
        raise CandidateSnapshotError("candidate provenance staging is malformed")

    endpoint_cache: dict[str, dict[str, Any]] = {}

    def validate_with_endpoint(proxy: Mapping[str, Any]) -> tuple[dict[str, Any], str]:
        validated = _validated_proxy(proxy)
        endpoint = canonical_endpoint(validated.get("server"), validated.get("port"))
        if endpoint not in endpoint_cache:
            endpoint_cache[endpoint] = validate_proxy_endpoint(
                validated,
                resolver=resolver,
                checked_at=timestamp,
            )
        return validated, canonical_proxy_fingerprint(validated)

    current_by_fingerprint: dict[str, dict[str, Any]] = {}
    for proxy in current_proxies:
        validated, fingerprint = validate_with_endpoint(proxy)
        previous_proxy = current_by_fingerprint.get(fingerprint)
        if previous_proxy is None or _proxy_representative_key(validated) < _proxy_representative_key(previous_proxy):
            current_by_fingerprint[fingerprint] = validated

    capacity = estimate_gmgn_capacity(len(current_by_fingerprint))
    if not capacity["below_candidate_hard_limit"] or not capacity["within_runtime_budget"]:
        raise CandidateSnapshotError("candidate pool exceeds the versioned GMGN capacity budget")

    raw_count = len(records)
    valid_records: list[dict[str, Any]] = []
    valid_fingerprints: set[str] = set()
    unique_endpoints: set[str] = set()
    for item in records:
        if not isinstance(item, Mapping) or set(item) != INPUT_RECORD_FIELDS:
            raise CandidateSnapshotError("candidate provenance record fields are invalid")
        try:
            validated, fingerprint = validate_with_endpoint(item["proxy"])
        except (CandidateSnapshotError, CandidateSourceError, IdentityError):
            continue
        valid_fingerprints.add(fingerprint)
        unique_endpoints.add(canonical_endpoint(validated["server"], validated["port"]))
        normalized = dict(item)
        normalized["proxy"] = validated
        normalized["alias"] = _safe_proxy_alias(item.get("alias"), validated)
        valid_records.append(normalized)

    covered = {canonical_proxy_fingerprint(item["proxy"]) for item in valid_records}
    if not set(current_by_fingerprint).issubset(covered):
        raise CandidateSnapshotError("candidate profile is not fully covered by safe provenance")

    safe_previous_profile = copy.deepcopy(previous_profile) if previous_profile is not None else None
    if safe_previous_profile is not None:
        previous_proxies = _profile_proxies(safe_previous_profile)
        for proxy in previous_proxies:
            validate_with_endpoint(proxy)
        safe_previous_profile["proxies"] = previous_proxies

    normalized_sources = [dict(item) for item in sources if isinstance(item, Mapping)]
    if len(normalized_sources) != len(sources):
        raise CandidateSnapshotError("candidate provenance sources are malformed")
    identity_input = {
        "kind": IDENTITY_INPUT_KIND,
        "schema_version": IDENTITY_INPUT_SCHEMA_VERSION,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "endpoint_safety_policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
        "endpoint_checked_at": timestamp,
        "run_at": timestamp,
        "mode": str(mode or "").strip(),
        "main_sha": str(main_sha or "").strip().lower(),
        "profile_url": str(profile_url or "").strip(),
        "candidate_metadata_url": str(candidate_metadata_url or "").strip(),
        "raw_count": raw_count,
        "valid_config_count": len(valid_records),
        "exact_unique_count": len(valid_fingerprints),
        "unique_endpoint_count": len(unique_endpoints),
        "github_failed_count": max(int(github_failed_count), 0),
        "profile": {**parsed_profile, "proxies": list(current_by_fingerprint.values())},
        "sources": normalized_sources,
        "records": valid_records,
        "previous_state": previous_state,
        "previous_profile": safe_previous_profile,
        "previous_status": copy.deepcopy(previous_status),
        "previous_metadata": copy.deepcopy(previous_metadata),
    }
    validate_candidate_identity_input(identity_input)
    return identity_input


def validate_candidate_identity_input(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != IDENTITY_INPUT_FIELDS:
        raise CandidateSnapshotError("candidate identity input fields are incomplete or unexpected")
    if payload["kind"] != IDENTITY_INPUT_KIND or payload["schema_version"] != IDENTITY_INPUT_SCHEMA_VERSION:
        raise CandidateSnapshotError("candidate identity input version is unsupported")
    if payload["source_policy_version"] != SOURCE_POLICY_VERSION:
        raise CandidateSnapshotError("candidate source policy is unsupported")
    if payload["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION:
        raise CandidateSnapshotError("candidate endpoint safety policy is unsupported")
    utc_timestamp(str(payload["endpoint_checked_at"]))
    utc_timestamp(str(payload["run_at"]))
    if not str(payload["mode"] or "").strip():
        raise CandidateSnapshotError("candidate mode is required")
    main_sha = str(payload["main_sha"] or "")
    if not MAIN_SHA_RE.fullmatch(main_sha):
        raise CandidateSnapshotError("candidate main SHA is malformed")
    for name in ("profile_url", "candidate_metadata_url"):
        if not str(payload[name] or "").startswith("https://"):
            raise CandidateSnapshotError("candidate artifact URL must use HTTPS")
    for name in ("raw_count", "valid_config_count", "exact_unique_count", "unique_endpoint_count", "github_failed_count"):
        if not isinstance(payload[name], int) or payload[name] < 0:
            raise CandidateSnapshotError("candidate input count is invalid")
    if not isinstance(payload["profile"], Mapping) or not isinstance(payload["sources"], list) or not isinstance(payload["records"], list):
        raise CandidateSnapshotError("candidate input collections are malformed")
    if payload["previous_state"] not in {"confirmed_absent", "present"}:
        raise CandidateSnapshotError("candidate previous state is unsupported")
    previous_values = (payload["previous_profile"], payload["previous_status"], payload["previous_metadata"])
    if payload["previous_state"] == "confirmed_absent" and any(value is not None for value in previous_values):
        raise CandidateSnapshotError("confirmed-absent candidate input contains previous artifacts")
    if payload["previous_state"] == "present" and any(not isinstance(value, Mapping) for value in previous_values):
        raise CandidateSnapshotError("present candidate input has incomplete previous artifacts")
    return dict(payload)


def write_candidate_identity_input(path: str | Path, payload: Mapping[str, Any]) -> None:
    validate_candidate_identity_input(payload)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_bytes(_json_bytes(dict(payload)))
    temporary.replace(destination)


def load_candidate_identity_input(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise CandidateSnapshotError("candidate identity input is invalid JSON") from exc
    return validate_candidate_identity_input(payload)


def _production_identity_preflight(settings: IdentitySettings, fixture_path: str | Path) -> dict[str, str]:
    verify_identity_test_vector(fixture_path)
    fixture = load_identity_test_vector(fixture_path)
    ids = compute_public_ids(
        fixture["proxy"],
        key=settings.key,
        identity_key_version=settings.identity_key_version,
        identity_epoch=settings.identity_epoch,
        public_ip=fixture["public_ipv4"],
    )
    return {"fixture_version": IDENTITY_FIXTURE_VERSION, **ids}


def _source_events(payload: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    events: dict[str, dict[str, Any]] = {}
    for raw in payload["sources"]:
        if not isinstance(raw, Mapping):
            raise CandidateSnapshotError("candidate source event is malformed")
        item = dict(raw)
        source_id = str(item.get("source_id", ""))
        if not source_id:
            raise CandidateSnapshotError("candidate source event has no source ID")
        previous = events.get(source_id)
        if previous is None:
            events[source_id] = item
        elif previous.get("outcome") != "success" and item.get("outcome") == "success":
            events[source_id] = item
        elif previous.get("outcome") == item.get("outcome") and str(item.get("observed_at", "")) > str(previous.get("observed_at", "")):
            events[source_id] = item
    return events


def _records_by_fingerprint(payload: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in payload["records"]:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("proxy"), Mapping):
            raise CandidateSnapshotError("candidate provenance record is malformed")
        item = dict(raw)
        fingerprint = canonical_proxy_fingerprint(item["proxy"])
        records[fingerprint].append(item)
    return records


def _candidate_primary_region(metadata: Mapping[str, Any]) -> str:
    hints = metadata.get("region_hints")
    if isinstance(hints, list):
        for region in REGION_ORDER:
            if region in hints:
                return region
    return "unknown"


def _previous_counts(status: Mapping[str, Any] | None, previous_state: str) -> dict[str, Any]:
    empty = {
        "state": previous_state,
        "snapshot_id": "",
        "candidate_count": 0,
        "protected_asia_count": 0,
        "region_hint_counts": {**{region: 0 for region in REGION_ORDER}, "unknown": 0},
    }
    if status is None:
        return empty
    return {
        "state": previous_state,
        "snapshot_id": str(status.get("snapshot_id", "")),
        "candidate_count": int(status.get("candidate_count", 0)),
        "protected_asia_count": int(status.get("protected_asia_count", 0)),
        "region_hint_counts": {
            region: int((status.get("region_hint_counts") or {}).get(region, 0))
            for region in (*REGION_ORDER, "unknown")
        },
    }


def _ratio(current: int, previous: int) -> float:
    return 1.0 if previous <= 0 else current / previous


def _evaluate_publish_gate(
    *,
    candidate_count: int,
    protected_asia_count: int,
    region_counts: Mapping[str, int],
    sources: Mapping[str, Mapping[str, Any]],
    previous: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    reasons: list[str] = []
    previous_total = int(previous["candidate_count"])
    previous_asia = int(previous["protected_asia_count"])
    if candidate_count < math.ceil(previous_total * TOTAL_RETAIN_RATIO):
        reasons.append("candidate_retention_below_60")
    if protected_asia_count < math.ceil(previous_asia * ASIA_RETAIN_RATIO):
        reasons.append("asia_retention_below_70")
    for region in REGION_ORDER:
        old = int(previous["region_hint_counts"].get(region, 0))
        current = int(region_counts.get(region, 0))
        if current < math.ceil(old * REGION_RETAIN_RATIO):
            reasons.append(f"region_{region}_retention_below_50")
        if old > 0 and current == 0:
            reasons.append(f"region_{region}_dropped_to_zero")

    eligible_sources = [
        item
        for item in sources.values()
        if item.get("visibility") in {"public", "opaque"}
        and item.get("health_state") != "confirmed_missing"
    ]
    eligible = len(eligible_sources)
    acceptable = sum(
        1
        for item in eligible_sources
        if item.get("health_state") in {"healthy", "recovered", "using_last_good"}
    )
    quorum_ratio = 1.0 if eligible <= 0 else acceptable / eligible
    if quorum_ratio < SOURCE_QUORUM_RATIO:
        reasons.append("source_quorum_below_80")

    retain_ratios = {
        "candidate": _ratio(candidate_count, previous_total),
        "protected_asia": _ratio(protected_asia_count, previous_asia),
        "regions": {
            region: _ratio(int(region_counts.get(region, 0)), int(previous["region_hint_counts"].get(region, 0)))
            for region in REGION_ORDER
        },
    }
    source_quorum = {
        "eligible": eligible,
        "healthy_or_last_good": acceptable,
        "ratio": quorum_ratio,
        "required_ratio": SOURCE_QUORUM_RATIO,
    }
    gate = {
        "passed": not reasons,
        "reasons": reasons,
        "policy_version": CANDIDATE_PUBLISH_POLICY_VERSION,
    }
    return retain_ratios, source_quorum, gate


def evaluate_candidate_publish_gate(
    *,
    candidate_count: int,
    protected_asia_count: int,
    region_counts: Mapping[str, int],
    sources: Mapping[str, Mapping[str, Any]],
    previous: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Public pure boundary for exact integer publish-gate tests and replay."""

    return _evaluate_publish_gate(
        candidate_count=candidate_count,
        protected_asia_count=protected_asia_count,
        region_counts=region_counts,
        sources=sources,
        previous=previous,
    )


def _missing_record(
    previous: Mapping[str, Any] | None,
    *,
    last_seen_at: str,
    run_at: str,
) -> dict[str, Any]:
    prior = dict(previous or {})
    confirmations = int(prior.get("confirmations", 0))
    last_missing_at = str(prior.get("last_missing_at", ""))
    if not last_missing_at or _seconds_between(run_at, last_missing_at) >= MISSING_CONFIRMATION_SPACING_SECONDS:
        confirmations += 1
        last_missing_at = run_at
    first_missing_at = str(prior.get("first_missing_at", "")) or run_at
    confirmed = confirmations >= MISSING_CONFIRMATION_COUNT and _seconds_between(run_at, last_seen_at) >= MISSING_MIN_AGE_SECONDS
    return {
        "last_seen_at": last_seen_at,
        "confirmations": confirmations,
        "first_missing_at": first_missing_at,
        "last_missing_at": last_missing_at,
        "confirmed_missing": confirmed,
    }


def _source_state(
    payload: Mapping[str, Any],
    current_candidate_sources: Mapping[str, set[str]],
    current_candidate_regions: Mapping[str, Mapping[str, str]],
    previous: CandidateSnapshot | None,
) -> dict[str, dict[str, Any]]:
    run_at = str(payload["run_at"])
    events = _source_events(payload)
    previous_sources = previous.metadata["sources"] if previous is not None else {}
    previous_candidates = previous.metadata["candidates"] if previous is not None else {}
    previous_by_source: dict[str, set[str]] = defaultdict(set)
    for candidate_id_value, metadata in previous_candidates.items():
        for source_id in metadata.get("source_ids", []):
            previous_by_source[str(source_id)].add(str(candidate_id_value))

    source_ids = sorted(set(events) | set(previous_sources))
    output: dict[str, dict[str, Any]] = {}
    for source_id in source_ids:
        event = events.get(source_id)
        old = previous_sources.get(source_id, {}) if isinstance(previous_sources, Mapping) else {}
        outcome = str((event or {}).get("outcome", "network_error"))
        last_attempt_at = str((event or {}).get("observed_at", run_at))
        old_last_success = str(old.get("last_success_at", ""))
        last_success_at = str((event or {}).get("last_success_at", "")) or old_last_success
        current_ids = set(current_candidate_sources.get(source_id, set()))
        current_regions = Counter(current_candidate_regions.get(source_id, {}).values())
        previous_ids = set(previous_by_source.get(source_id, set()))
        missing = copy.deepcopy(old.get("missing_candidates", {})) if isinstance(old.get("missing_candidates", {}), Mapping) else {}

        if outcome == "success":
            last_success_content_sha256 = hashlib.sha256(
                "\n".join(sorted(current_ids)).encode("utf-8")
            ).hexdigest()
            last_success_candidate_count = len(current_ids)
            last_success_region_counts = {
                region: current_regions[region] for region in (*REGION_ORDER, "unknown")
            }
            consecutive_failures = 0
            for candidate_id_value in list(missing):
                if candidate_id_value in current_ids:
                    missing.pop(candidate_id_value, None)
            for candidate_id_value in sorted(previous_ids - current_ids):
                previous_candidate = previous_candidates[candidate_id_value]
                missing[candidate_id_value] = _missing_record(
                    missing.get(candidate_id_value),
                    last_seen_at=str(previous_candidate["last_seen_at"]),
                    run_at=run_at,
                )
            prior_health = str(old.get("health_state", ""))
            health_state = "recovered" if prior_health in {"using_last_good", "observing_failure"} else "healthy"
            if not current_ids and missing and all(item.get("confirmed_missing") for item in missing.values()):
                health_state = "confirmed_missing"
        else:
            last_success_content_sha256 = str(old.get("last_success_content_sha256", ""))
            last_success_candidate_count = int(old.get("last_success_candidate_count", 0))
            previous_region_counts = old.get("last_success_region_counts", {})
            last_success_region_counts = {
                region: int(previous_region_counts.get(region, 0))
                for region in (*REGION_ORDER, "unknown")
            }
            consecutive_failures = int(old.get("consecutive_failures", 0)) + 1
            recent = bool(last_success_at) and _seconds_between(run_at, last_success_at) <= LAST_GOOD_MAX_AGE_SECONDS
            health_state = "using_last_good" if recent else "observing_failure"

        last_good_ids = {
            candidate_id_value
            for candidate_id_value in previous_ids
            if health_state == "using_last_good"
            or (
                outcome == "success"
                and not bool((missing.get(candidate_id_value) or {}).get("confirmed_missing"))
                and candidate_id_value not in current_ids
            )
        }
        output[source_id] = {
            "alias": str((event or {}).get("alias", old.get("alias", ""))),
            "visibility": str((event or {}).get("visibility", old.get("visibility", "opaque"))),
            "health_state": health_state,
            "last_event": outcome,
            "last_attempt_at": last_attempt_at,
            "last_success_at": last_success_at,
            "last_success_content_sha256": last_success_content_sha256,
            "last_success_candidate_count": last_success_candidate_count,
            "last_success_region_counts": last_success_region_counts,
            "consecutive_failures": consecutive_failures,
            "candidate_count": len(current_ids),
            "last_good_candidate_count": len(last_good_ids),
            "missing_candidates": {key: missing[key] for key in sorted(missing)},
        }
    return output


def _choose_names(entries: Mapping[str, dict[str, Any]]) -> dict[str, str]:
    reserved = set(BUILTIN_PROXY_NAMES) | {"automatic", "🌐 Proxy"}
    chosen: dict[str, str] = {}
    used = set(reserved)
    for candidate_id_value in sorted(entries):
        aliases = [_safe_alias(value) for value in entries[candidate_id_value]["metadata"]["aliases"]]
        aliases = sorted({alias for alias in aliases if alias})
        base = aliases[0] if aliases else "Node"
        name = base
        if name in used:
            name = f"{base} [{candidate_id_value[-6:]}]"
        if name in used:
            name = f"Node [{candidate_id_value}]"
        chosen[candidate_id_value] = name
        used.add(name)
    return chosen


def _build_profile(entries: Mapping[str, dict[str, Any]]) -> tuple[bytes, dict[str, dict[str, Any]]]:
    names = _choose_names(entries)
    proxies: list[dict[str, Any]] = []
    output_entries: dict[str, dict[str, Any]] = {}
    for candidate_id_value in sorted(entries):
        proxy = copy.deepcopy(entries[candidate_id_value]["proxy"])
        proxy["name"] = names[candidate_id_value]
        proxies.append(proxy)
        output_entries[candidate_id_value] = {
            "proxy": proxy,
            "metadata": copy.deepcopy(entries[candidate_id_value]["metadata"]),
        }
    profile = {
        "mixed-port": 7890,
        "external-controller": "127.0.0.1:9090",
        "mode": "Rule",
        "log-level": "silent",
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "automatic",
                "type": "url-test",
                "proxies": [proxy["name"] for proxy in proxies],
                "url": os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/"),
                "interval": 300,
            },
            {
                "name": "🌐 Proxy",
                "type": "select",
                "proxies": ["automatic"] + [proxy["name"] for proxy in proxies],
            },
        ],
        "rules": ["MATCH,🌐 Proxy"],
    }
    text, rejected = dump_clash_yaml(profile)
    if rejected:
        raise CandidateSnapshotError("candidate profile contains invalid REALITY short IDs")
    try:
        parsed = yaml.safe_load(text)
    except Exception as exc:
        raise CandidateSnapshotError("candidate output profile cannot be parsed") from exc
    if not isinstance(parsed, dict) or len(parsed.get("proxies", [])) != len(proxies):
        raise CandidateSnapshotError("candidate output profile round-trip failed")
    return text.encode("utf-8"), output_entries


def build_candidate_snapshot(
    identity_input: Mapping[str, Any],
    *,
    settings: IdentitySettings | None = None,
    fixture_path: str | Path = Path("tests/fixtures/gmgn_identity_v1.json"),
) -> CandidateSnapshot:
    payload = validate_candidate_identity_input(identity_input)
    identity = settings or IdentitySettings.from_environment()
    previous: CandidateSnapshot | None = None
    if payload["previous_state"] == "present":
        previous_profile_text, rejected = dump_clash_yaml(dict(payload["previous_profile"]))
        if rejected:
            raise CandidateSnapshotError("previous candidate profile contains invalid REALITY fields")
        previous = validate_candidate_snapshot(
            previous_profile_text.encode("utf-8"),
            dict(payload["previous_status"]),
            dict(payload["previous_metadata"]),
            settings=identity,
            fixture_path=fixture_path,
        )

    records = _records_by_fingerprint(payload)
    current_profile = dict(payload["profile"])
    current_proxies = _profile_proxies(current_profile)
    entries: dict[str, dict[str, Any]] = {}
    current_candidate_sources: dict[str, set[str]] = defaultdict(set)
    current_candidate_regions: dict[str, dict[str, str]] = defaultdict(dict)
    collision_bindings: list[tuple[str, str]] = []
    run_at = str(payload["run_at"])

    # Source health follows what collection actually observed, not what the
    # downstream GitHub reachability filter chose to publish. Otherwise a
    # currently supplied non-Asia node that failed a strict check would look
    # source-missing and could be incorrectly restored from last-good.
    for related in records.values():
        proxy = related[0]["proxy"]
        public_ids = compute_public_ids(
            proxy,
            key=identity.key,
            identity_key_version=identity.identity_key_version,
            identity_epoch=identity.identity_epoch,
        )
        candidate_id_value = public_ids["candidate_id"]
        related_regions = sorted(
            {region for item in related for region in item.get("region_hints", [])},
            key=lambda region: REGION_ORDER.index(region),
        )
        primary_region = related_regions[0] if related_regions else "unknown"
        for source_id in {str(item["source_id"]) for item in related}:
            current_candidate_sources[source_id].add(candidate_id_value)
            current_candidate_regions[source_id][candidate_id_value] = primary_region
        collision_bindings.extend(
            (
                (candidate_id_value, canonical_proxy_fingerprint(proxy)),
                (public_ids["server_id"], canonical_server(proxy["server"])),
                (public_ids["endpoint_id"], canonical_endpoint(proxy["server"], proxy["port"])),
            )
        )

    for proxy in current_proxies:
        fingerprint = canonical_proxy_fingerprint(proxy)
        related = records.get(fingerprint, [])
        if not related:
            raise CandidateSnapshotError("candidate proxy has no provenance")
        public_ids = compute_public_ids(
            proxy,
            key=identity.key,
            identity_key_version=identity.identity_key_version,
            identity_epoch=identity.identity_epoch,
        )
        candidate_id_value = public_ids["candidate_id"]
        aliases = sorted({_safe_proxy_alias(item.get("alias"), proxy) for item in related} - {""})
        source_ids = sorted({str(item["source_id"]) for item in related})
        region_hints = sorted(
            {region for item in related for region in item.get("region_hints", [])},
            key=lambda region: REGION_ORDER.index(region),
        )
        region_evidence = sorted({value for item in related for value in item.get("region_evidence", [])})
        protected_asia = bool(region_hints or "explicit:asia_keep" in region_evidence or is_preferred_asian_proxy(proxy))
        source_success = max(str(item["source_last_success_at"]) for item in related)
        old_metadata = previous.metadata["candidates"].get(candidate_id_value) if previous is not None else None
        first_seen_at = str(old_metadata["first_seen_at"]) if old_metadata else run_at
        entries[candidate_id_value] = {
            "proxy": proxy,
            "metadata": {
                "aliases": sorted(set(aliases) | set((old_metadata or {}).get("aliases", []))),
                "source_ids": sorted(set(source_ids) | set((old_metadata or {}).get("source_ids", []))),
                "first_seen_at": first_seen_at,
                "last_seen_at": run_at,
                "source_last_success_at": max(source_success, str((old_metadata or {}).get("source_last_success_at", ""))),
                "region_hints": sorted(
                    set(region_hints) | set((old_metadata or {}).get("region_hints", [])),
                    key=lambda region: REGION_ORDER.index(region),
                ),
                "region_evidence": sorted(set(region_evidence) | set((old_metadata or {}).get("region_evidence", []))),
                "protected_asia": protected_asia or bool((old_metadata or {}).get("protected_asia", False)),
                "github_check_state": "bypassed_asia" if protected_asia else "passed",
                "protocol": str(proxy.get("type", "")).lower(),
                "server_id": public_ids["server_id"],
                "endpoint_id": public_ids["endpoint_id"],
                "endpoint_safety_policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
                "endpoint_checked_at": str(payload["endpoint_checked_at"]),
            },
        }
        collision_bindings.extend(
            (
                (candidate_id_value, fingerprint),
                (public_ids["server_id"], canonical_server(proxy["server"])),
                (public_ids["endpoint_id"], canonical_endpoint(proxy["server"], proxy["port"])),
            )
        )

    sources = _source_state(
        payload,
        current_candidate_sources,
        current_candidate_regions,
        previous,
    )
    if previous is not None:
        previous_proxy_by_id = {entry.candidate_id: entry.proxy for entry in previous.ordered_candidates}
        for candidate_id_value, old_metadata in previous.metadata["candidates"].items():
            if candidate_id_value in entries:
                continue
            retain_sources: list[str] = []
            for source_id in old_metadata["source_ids"]:
                source = sources.get(source_id)
                missing = (source or {}).get("missing_candidates", {}).get(candidate_id_value, {})
                if not source or missing.get("confirmed_missing"):
                    continue
                if source["health_state"] == "using_last_good" or (
                    source["last_event"] == "success" and candidate_id_value in source["missing_candidates"]
                ):
                    retain_sources.append(source_id)
            if not retain_sources:
                continue
            proxy = copy.deepcopy(previous_proxy_by_id[candidate_id_value])
            public_ids = compute_public_ids(
                proxy,
                key=identity.key,
                identity_key_version=identity.identity_key_version,
                identity_epoch=identity.identity_epoch,
            )
            if public_ids["candidate_id"] != candidate_id_value:
                raise CandidateSnapshotError("previous candidate identity changed")
            metadata = copy.deepcopy(old_metadata)
            metadata["source_ids"] = sorted(set(metadata["source_ids"]) | set(retain_sources))
            metadata["endpoint_checked_at"] = str(payload["endpoint_checked_at"])
            entries[candidate_id_value] = {"proxy": proxy, "metadata": metadata}
            collision_bindings.extend(
                (
                    (candidate_id_value, canonical_proxy_fingerprint(proxy)),
                    (public_ids["server_id"], canonical_server(proxy["server"])),
                    (public_ids["endpoint_id"], canonical_endpoint(proxy["server"], proxy["port"])),
                )
            )

    assert_unique_public_id_bindings(collision_bindings)
    if not entries:
        raise CandidateSnapshotError("candidate snapshot contains no publishable candidates")
    final_capacity = estimate_gmgn_capacity(len(entries))
    if not final_capacity["below_candidate_hard_limit"] or not final_capacity["within_runtime_budget"]:
        raise CandidateSnapshotError("candidate pool exceeds the versioned GMGN capacity budget")
    profile_bytes, entries = _build_profile(entries)
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    snapshot_id = "candidate_" + hashlib.sha256(
        f"{payload['run_at']}\0{payload['main_sha']}\0{profile_sha256}".encode("utf-8")
    ).hexdigest()[:24]
    metadata = {
        "kind": CANDIDATE_METADATA_KIND,
        "schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "profile_sha256": profile_sha256,
        "identity_key_version": identity.identity_key_version,
        "identity_epoch": identity.identity_epoch,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "endpoint_safety_policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
        "endpoint_checked_at": str(payload["endpoint_checked_at"]),
        "candidate_count": len(entries),
        "identity_preflight": _production_identity_preflight(identity, fixture_path),
        "candidates": {candidate_id_value: entries[candidate_id_value]["metadata"] for candidate_id_value in sorted(entries)},
        "sources": {source_id: sources[source_id] for source_id in sorted(sources)},
    }
    metadata_bytes = _json_bytes(metadata)
    metadata_sha256 = hashlib.sha256(metadata_bytes).hexdigest()
    region_counts = {**{region: 0 for region in REGION_ORDER}, "unknown": 0}
    protected_asia_count = 0
    github_counts = {"passed": 0, "failed": int(payload["github_failed_count"]), "bypassed_asia": 0}
    for item in metadata["candidates"].values():
        region_counts[_candidate_primary_region(item)] += 1
        protected_asia_count += int(item["protected_asia"])
        github_counts[item["github_check_state"]] += 1
    source_counts = {
        "configured": len(sources),
        "healthy": sum(item["health_state"] in {"healthy", "recovered"} for item in sources.values()),
        "last_good": sum(item["health_state"] == "using_last_good" for item in sources.values()),
        "observing": sum(item["health_state"] == "observing_failure" for item in sources.values()),
        "confirmed_missing": sum(item["health_state"] == "confirmed_missing" for item in sources.values()),
        "failed": sum(item["last_event"] != "success" and item["health_state"] != "using_last_good" for item in sources.values()),
    }
    previous_counts = _previous_counts(previous.status if previous is not None else None, str(payload["previous_state"]))
    retain_ratios, source_quorum, publish_gate = _evaluate_publish_gate(
        candidate_count=len(entries),
        protected_asia_count=protected_asia_count,
        region_counts=region_counts,
        sources=sources,
        previous=previous_counts,
    )
    changes = {
        "candidate_count": len(entries) - int(previous_counts["candidate_count"]),
        "protected_asia_count": protected_asia_count - int(previous_counts["protected_asia_count"]),
        "regions": {
            region: region_counts[region] - int(previous_counts["region_hint_counts"].get(region, 0))
            for region in REGION_ORDER
        },
    }
    status = {
        "kind": CANDIDATE_STATUS_KIND,
        "schema_version": CANDIDATE_STATUS_SCHEMA_VERSION,
        "snapshot_id": snapshot_id,
        "run_at": str(payload["run_at"]),
        "main_sha": str(payload["main_sha"]),
        "mode": str(payload["mode"]),
        "profile_url": str(payload["profile_url"]),
        "profile_sha256": profile_sha256,
        "candidate_metadata_url": str(payload["candidate_metadata_url"]),
        "candidate_metadata_sha256": metadata_sha256,
        "candidate_metadata_schema_version": CANDIDATE_METADATA_SCHEMA_VERSION,
        "candidate_metadata_count": len(entries),
        "identity_key_version": identity.identity_key_version,
        "identity_epoch": identity.identity_epoch,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "endpoint_safety_policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
        "policy_version": CANDIDATE_PUBLISH_POLICY_VERSION,
        "raw_count": int(payload["raw_count"]),
        "valid_config_count": int(payload["valid_config_count"]),
        "exact_unique_count": int(payload["exact_unique_count"]),
        "unique_endpoint_count": int(payload["unique_endpoint_count"]),
        "candidate_count": len(entries),
        "protected_asia_count": protected_asia_count,
        "region_hint_counts": region_counts,
        "source_counts": source_counts,
        "github_check_counts": github_counts,
        "previous": previous_counts,
        "changes": changes,
        "retain_ratios": retain_ratios,
        "source_quorum": source_quorum,
        "publish_gate": publish_gate,
    }
    if not publish_gate["passed"]:
        raise CandidateSnapshotError("candidate publish gate rejected the staged snapshot")
    return validate_candidate_snapshot(
        profile_bytes,
        status,
        metadata,
        settings=identity,
        fixture_path=fixture_path,
    )


def _strict_mapping(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CandidateSnapshotError(f"{label} fields are incomplete or unexpected")
    return dict(value)


def _strict_nonnegative_counts(value: Any, fields: set[str], label: str) -> dict[str, int]:
    item = _strict_mapping(value, fields, label)
    if any(isinstance(count, bool) or not isinstance(count, int) or count < 0 for count in item.values()):
        raise CandidateSnapshotError(f"{label} contains an invalid count")
    return {str(name): int(count) for name, count in item.items()}


def _validate_source_metadata(sources: Any, *, run_at: str) -> dict[str, Any]:
    if not isinstance(sources, Mapping):
        raise CandidateSnapshotError("candidate sources must be a mapping")
    output: dict[str, Any] = {}
    for source_id, raw in sources.items():
        if not re.fullmatch(r"(?:public|opaque)_[0-9a-f]{24}", str(source_id)):
            raise CandidateSnapshotError("candidate source ID is malformed")
        item = _strict_mapping(raw, SOURCE_FIELDS, "candidate source")
        if item["visibility"] not in {"public", "opaque"}:
            raise CandidateSnapshotError("candidate source visibility is unsupported")
        if item["health_state"] not in {"healthy", "using_last_good", "observing_failure", "confirmed_missing", "recovered"}:
            raise CandidateSnapshotError("candidate source health state is unsupported")
        if item["last_event"] not in SOURCE_OUTCOMES:
            raise CandidateSnapshotError("candidate source event is unsupported")
        success_health = {"healthy", "recovered", "confirmed_missing"}
        if (item["last_event"] == "success") != (item["health_state"] in success_health):
            raise CandidateSnapshotError("candidate source event contradicts its health state")
        alias = str(item["alias"] or "")
        if alias and not SAFE_PUBLIC_ALIAS_RE.fullmatch(alias):
            raise CandidateSnapshotError("candidate source alias is unsafe")
        if item["visibility"] == "opaque" and alias:
            raise CandidateSnapshotError("opaque candidate source cannot expose an alias")
        utc_timestamp(item["last_attempt_at"])
        if item["last_success_at"]:
            utc_timestamp(item["last_success_at"])
        if _seconds_between(run_at, item["last_attempt_at"]) < 0:
            raise CandidateSnapshotError("candidate source attempt is in the future")
        if item["last_success_at"] and _seconds_between(run_at, item["last_success_at"]) < 0:
            raise CandidateSnapshotError("candidate source success is in the future")
        if item["last_event"] == "success" and not item["last_success_at"]:
            raise CandidateSnapshotError("successful candidate source has no success time")
        content_sha256 = str(item["last_success_content_sha256"])
        if item["last_success_at"]:
            if not re.fullmatch(r"[0-9a-f]{64}", content_sha256):
                raise CandidateSnapshotError("candidate source content hash is malformed")
        elif content_sha256:
            raise CandidateSnapshotError("candidate source without a success cannot have a content hash")
        if (
            isinstance(item["last_success_candidate_count"], bool)
            or not isinstance(item["last_success_candidate_count"], int)
            or item["last_success_candidate_count"] < 0
        ):
            raise CandidateSnapshotError("candidate source last-success count is invalid")
        last_success_regions = _strict_nonnegative_counts(
            item["last_success_region_counts"],
            set((*REGION_ORDER, "unknown")),
            "candidate source last-success regions",
        )
        if sum(last_success_regions.values()) != item["last_success_candidate_count"]:
            raise CandidateSnapshotError("candidate source last-success regions are inconsistent")
        if not item["last_success_at"] and item["last_success_candidate_count"] != 0:
            raise CandidateSnapshotError("candidate source without a success cannot have last-success counts")
        if (
            isinstance(item["consecutive_failures"], bool)
            or not isinstance(item["consecutive_failures"], int)
            or item["consecutive_failures"] < 0
        ):
            raise CandidateSnapshotError("candidate source failure streak is invalid")
        if (item["last_event"] == "success") != (item["consecutive_failures"] == 0):
            raise CandidateSnapshotError("candidate source failure streak contradicts its last event")
        for name in ("candidate_count", "last_good_candidate_count"):
            if not isinstance(item[name], int) or item[name] < 0:
                raise CandidateSnapshotError("candidate source count is invalid")
        if item["last_event"] == "success" and item["candidate_count"] != item["last_success_candidate_count"]:
            raise CandidateSnapshotError("candidate source success counts are inconsistent")
        if not isinstance(item["missing_candidates"], Mapping):
            raise CandidateSnapshotError("candidate missing state is malformed")
        for candidate_id_value, missing_raw in item["missing_candidates"].items():
            validate_public_id(candidate_id_value, "candidate")
            missing = _strict_mapping(missing_raw, MISSING_FIELDS, "candidate missing state")
            utc_timestamp(missing["last_seen_at"])
            utc_timestamp(missing["first_missing_at"])
            utc_timestamp(missing["last_missing_at"])
            if not isinstance(missing["confirmations"], int) or missing["confirmations"] < 1:
                raise CandidateSnapshotError("candidate missing confirmations are invalid")
            if not isinstance(missing["confirmed_missing"], bool):
                raise CandidateSnapshotError("candidate missing flag must be boolean")
            if (
                _seconds_between(missing["first_missing_at"], missing["last_seen_at"]) < 0
                or _seconds_between(missing["last_missing_at"], missing["first_missing_at"]) < 0
                or _seconds_between(run_at, missing["last_missing_at"]) < 0
            ):
                raise CandidateSnapshotError("candidate missing timestamps are inconsistent")
            if missing["confirmed_missing"] and (
                missing["confirmations"] < MISSING_CONFIRMATION_COUNT
                or _seconds_between(run_at, missing["last_seen_at"]) < MISSING_MIN_AGE_SECONDS
            ):
                raise CandidateSnapshotError("candidate confirmed-missing evidence is insufficient")
        output[str(source_id)] = item
    return output


def validate_candidate_snapshot(
    profile_bytes: bytes,
    status: Mapping[str, Any],
    metadata: Mapping[str, Any],
    *,
    settings: IdentitySettings | None = None,
    fixture_path: str | Path = Path("tests/fixtures/gmgn_identity_v1.json"),
) -> CandidateSnapshot:
    """Strict C1/C2 boundary validator with production-key identity preflight."""

    identity = settings or IdentitySettings.from_environment()
    status_value = _strict_mapping(status, STATUS_FIELDS, "candidate status")
    metadata_value = _strict_mapping(metadata, METADATA_FIELDS, "candidate metadata")
    if status_value["kind"] != CANDIDATE_STATUS_KIND or status_value["schema_version"] != CANDIDATE_STATUS_SCHEMA_VERSION:
        raise CandidateSnapshotError("candidate status version is unsupported")
    if metadata_value["kind"] != CANDIDATE_METADATA_KIND or metadata_value["schema_version"] != CANDIDATE_METADATA_SCHEMA_VERSION:
        raise CandidateSnapshotError("candidate metadata version is unsupported")
    snapshot_id = str(status_value["snapshot_id"])
    if not SNAPSHOT_ID_RE.fullmatch(snapshot_id) or metadata_value["snapshot_id"] != snapshot_id:
        raise CandidateSnapshotError("candidate snapshot ID is invalid or inconsistent")
    if status_value["identity_key_version"] != identity.identity_key_version or metadata_value["identity_key_version"] != identity.identity_key_version:
        raise CandidateSnapshotError("candidate identity key version mismatch")
    if status_value["identity_epoch"] != identity.identity_epoch or metadata_value["identity_epoch"] != identity.identity_epoch:
        raise CandidateSnapshotError("candidate identity epoch mismatch")
    if status_value["source_policy_version"] != SOURCE_POLICY_VERSION or metadata_value["source_policy_version"] != SOURCE_POLICY_VERSION:
        raise CandidateSnapshotError("candidate source policy mismatch")
    if status_value["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION or metadata_value["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION:
        raise CandidateSnapshotError("candidate endpoint safety policy mismatch")
    utc_timestamp(status_value["run_at"])
    utc_timestamp(metadata_value["endpoint_checked_at"])
    if not str(status_value["mode"] or "").strip():
        raise CandidateSnapshotError("candidate mode is required")
    if metadata_value["endpoint_checked_at"] != status_value["run_at"]:
        raise CandidateSnapshotError("candidate endpoint check time does not match the run")
    if not MAIN_SHA_RE.fullmatch(str(status_value["main_sha"])):
        raise CandidateSnapshotError("candidate main SHA is malformed")
    for name in ("profile_url", "candidate_metadata_url"):
        if not str(status_value[name]).startswith("https://"):
            raise CandidateSnapshotError("candidate artifact URL must use HTTPS")
    profile_sha256 = hashlib.sha256(profile_bytes).hexdigest()
    if status_value["profile_sha256"] != profile_sha256 or metadata_value["profile_sha256"] != profile_sha256:
        raise CandidateSnapshotError("candidate profile hash mismatch")
    metadata_sha256 = hashlib.sha256(_json_bytes(metadata_value)).hexdigest()
    if status_value["candidate_metadata_sha256"] != metadata_sha256:
        raise CandidateSnapshotError("candidate metadata hash mismatch")
    if status_value["candidate_metadata_schema_version"] != CANDIDATE_METADATA_SCHEMA_VERSION:
        raise CandidateSnapshotError("candidate metadata schema binding mismatch")
    expected_snapshot_id = "candidate_" + hashlib.sha256(
        f"{status_value['run_at']}\0{status_value['main_sha']}\0{profile_sha256}".encode("utf-8")
    ).hexdigest()[:24]
    if snapshot_id != expected_snapshot_id:
        raise CandidateSnapshotError("candidate snapshot ID does not match its bound inputs")
    preflight = _strict_mapping(metadata_value["identity_preflight"], PREFLIGHT_FIELDS, "identity preflight")
    if preflight != _production_identity_preflight(identity, fixture_path):
        raise CandidateSnapshotError("candidate identity preflight mismatch")
    sources = _validate_source_metadata(metadata_value["sources"], run_at=str(status_value["run_at"]))
    status_region_counts = _strict_nonnegative_counts(
        status_value["region_hint_counts"], REGION_COUNT_FIELDS, "candidate region counts"
    )
    status_source_counts = _strict_nonnegative_counts(
        status_value["source_counts"], SOURCE_COUNT_FIELDS, "candidate source counts"
    )
    status_github_counts = _strict_nonnegative_counts(
        status_value["github_check_counts"], GITHUB_COUNT_FIELDS, "candidate GitHub check counts"
    )
    previous_counts = _strict_mapping(status_value["previous"], PREVIOUS_FIELDS, "candidate previous counts")
    if previous_counts["state"] not in {"confirmed_absent", "present"}:
        raise CandidateSnapshotError("candidate previous state is unsupported")
    previous_region_counts = _strict_nonnegative_counts(
        previous_counts["region_hint_counts"], REGION_COUNT_FIELDS, "candidate previous region counts"
    )
    for name in ("candidate_count", "protected_asia_count"):
        if isinstance(previous_counts[name], bool) or not isinstance(previous_counts[name], int) or previous_counts[name] < 0:
            raise CandidateSnapshotError("candidate previous count is invalid")
    previous_snapshot_id = str(previous_counts["snapshot_id"] or "")
    if previous_counts["state"] == "confirmed_absent":
        if (
            previous_snapshot_id
            or previous_counts["candidate_count"]
            or previous_counts["protected_asia_count"]
            or any(previous_region_counts.values())
        ):
            raise CandidateSnapshotError("confirmed-absent candidate previous counts are not empty")
    elif not SNAPSHOT_ID_RE.fullmatch(previous_snapshot_id):
        raise CandidateSnapshotError("candidate previous snapshot ID is malformed")
    changes = _strict_mapping(status_value["changes"], CHANGES_FIELDS, "candidate changes")
    change_regions = _strict_mapping(changes["regions"], set(REGION_ORDER), "candidate region changes")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (
        changes["candidate_count"], changes["protected_asia_count"], *change_regions.values()
    )):
        raise CandidateSnapshotError("candidate change count is invalid")
    retain_ratios = _strict_mapping(
        status_value["retain_ratios"], RETAIN_RATIO_FIELDS, "candidate retain ratios"
    )
    retain_region_ratios = _strict_mapping(
        retain_ratios["regions"], set(REGION_ORDER), "candidate region retain ratios"
    )
    if any(
        isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)) or value < 0
        for value in (retain_ratios["candidate"], retain_ratios["protected_asia"], *retain_region_ratios.values())
    ):
        raise CandidateSnapshotError("candidate retain ratio is invalid")
    source_quorum = _strict_mapping(
        status_value["source_quorum"], SOURCE_QUORUM_FIELDS, "candidate source quorum"
    )
    if any(
        isinstance(source_quorum[name], bool)
        or not isinstance(source_quorum[name], int)
        or source_quorum[name] < 0
        for name in ("eligible", "healthy_or_last_good")
    ) or any(
        isinstance(source_quorum[name], bool)
        or not isinstance(source_quorum[name], (int, float))
        or not math.isfinite(float(source_quorum[name]))
        or source_quorum[name] < 0
        for name in ("ratio", "required_ratio")
    ):
        raise CandidateSnapshotError("candidate source quorum is invalid")
    publish_gate = _strict_mapping(status_value["publish_gate"], PUBLISH_GATE_FIELDS, "candidate publish gate")
    if (
        not isinstance(publish_gate["passed"], bool)
        or not isinstance(publish_gate["reasons"], list)
        or any(not isinstance(reason, str) for reason in publish_gate["reasons"])
        or publish_gate["policy_version"] != CANDIDATE_PUBLISH_POLICY_VERSION
    ):
        raise CandidateSnapshotError("candidate publish gate is malformed")

    expected_source_counts = {
        "configured": len(sources),
        "healthy": sum(item["health_state"] in {"healthy", "recovered"} for item in sources.values()),
        "last_good": sum(item["health_state"] == "using_last_good" for item in sources.values()),
        "observing": sum(item["health_state"] == "observing_failure" for item in sources.values()),
        "confirmed_missing": sum(item["health_state"] == "confirmed_missing" for item in sources.values()),
        "failed": sum(
            item["last_event"] != "success" and item["health_state"] != "using_last_good"
            for item in sources.values()
        ),
    }
    if status_source_counts != expected_source_counts:
        raise CandidateSnapshotError("candidate source counts do not match metadata")

    try:
        profile = yaml.safe_load(profile_bytes)
    except Exception as exc:
        raise CandidateSnapshotError("candidate profile is invalid YAML") from exc
    if not isinstance(profile, Mapping):
        raise CandidateSnapshotError("candidate profile must be a mapping")
    proxies = _profile_proxies(profile)
    candidate_values = metadata_value["candidates"]
    if not isinstance(candidate_values, Mapping):
        raise CandidateSnapshotError("candidate metadata entries must be a mapping")
    ordered: list[CandidateSnapshotEntry] = []
    seen_ids: set[str] = set()
    names: set[str] = set()
    collision_bindings: list[tuple[str, str]] = []
    for proxy in proxies:
        name = str(proxy.get("name", ""))
        if not name or name in names:
            raise CandidateSnapshotError("candidate profile names are empty or duplicated")
        names.add(name)
        public_ids = compute_public_ids(
            proxy,
            key=identity.key,
            identity_key_version=identity.identity_key_version,
            identity_epoch=identity.identity_epoch,
        )
        candidate_id_value = public_ids["candidate_id"]
        if candidate_id_value in seen_ids or candidate_id_value not in candidate_values:
            raise CandidateSnapshotError("candidate profile mapping is duplicated or missing")
        seen_ids.add(candidate_id_value)
        item = _strict_mapping(candidate_values[candidate_id_value], CANDIDATE_FIELDS, "candidate metadata entry")
        if item["server_id"] != public_ids["server_id"] or item["endpoint_id"] != public_ids["endpoint_id"]:
            raise CandidateSnapshotError("candidate server or endpoint identity mismatch")
        if item["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION:
            raise CandidateSnapshotError("candidate endpoint policy mismatch")
        if item["endpoint_checked_at"] != metadata_value["endpoint_checked_at"]:
            raise CandidateSnapshotError("candidate endpoint check time mismatch")
        utc_timestamp(item["endpoint_checked_at"])
        for field in ("first_seen_at", "last_seen_at", "source_last_success_at"):
            utc_timestamp(item[field])
        if (
            _seconds_between(item["last_seen_at"], item["first_seen_at"]) < 0
            or _seconds_between(status_value["run_at"], item["last_seen_at"]) < 0
            or _seconds_between(status_value["run_at"], item["source_last_success_at"]) < 0
        ):
            raise CandidateSnapshotError("candidate observation timestamps are inconsistent")
        if item["github_check_state"] not in {"passed", "failed", "bypassed_asia"}:
            raise CandidateSnapshotError("candidate GitHub check state is unsupported")
        if item["github_check_state"] == "failed":
            raise CandidateSnapshotError("failed candidate cannot appear in the profile")
        if item["protocol"] != str(proxy.get("type", "")).lower():
            raise CandidateSnapshotError("candidate protocol does not match the profile")
        aliases = item["aliases"]
        if (
            not isinstance(aliases, list)
            or any(not isinstance(alias, str) for alias in aliases)
            or aliases != sorted(set(aliases))
            or any(_safe_proxy_alias(alias, proxy) != alias for alias in aliases)
        ):
            raise CandidateSnapshotError("candidate aliases are malformed")
        source_ids = item["source_ids"]
        if (
            not isinstance(source_ids, list)
            or not source_ids
            or any(not isinstance(source_id, str) for source_id in source_ids)
            or source_ids != sorted(set(source_ids))
        ):
            raise CandidateSnapshotError("candidate source IDs are malformed")
        if any(source_id not in sources for source_id in source_ids):
            raise CandidateSnapshotError("candidate references an unknown source")
        region_hints = item["region_hints"]
        if (
            not isinstance(region_hints, list)
            or any(region not in REGION_ORDER for region in region_hints)
            or region_hints != sorted(set(region_hints), key=REGION_ORDER.index)
        ):
            raise CandidateSnapshotError("candidate region hints are malformed")
        region_evidence = item["region_evidence"]
        if (
            not isinstance(region_evidence, list)
            or any(not isinstance(value, str) for value in region_evidence)
            or region_evidence != sorted(set(region_evidence))
            or any(
                not re.fullmatch(r"(?:name_hint|source_hint):(HK|JP|KR|SG|TW)|explicit:asia_keep", str(value))
                for value in region_evidence
            )
            or not isinstance(item["protected_asia"], bool)
        ):
            raise CandidateSnapshotError("candidate region evidence is malformed")
        if (item["github_check_state"] == "bypassed_asia") != item["protected_asia"]:
            raise CandidateSnapshotError("candidate GitHub check state contradicts Asia protection")
        ordered.append(CandidateSnapshotEntry(candidate_id_value, proxy, item))
        collision_bindings.extend(
            (
                (candidate_id_value, canonical_proxy_fingerprint(proxy)),
                (public_ids["server_id"], canonical_server(proxy["server"])),
                (public_ids["endpoint_id"], canonical_endpoint(proxy["server"], proxy["port"])),
            )
        )
    assert_unique_public_id_bindings(collision_bindings)
    if set(candidate_values) != seen_ids:
        raise CandidateSnapshotError("candidate metadata contains orphan entries")
    candidate_count = len(proxies)
    if isinstance(metadata_value["candidate_count"], bool) or not isinstance(metadata_value["candidate_count"], int):
        raise CandidateSnapshotError("candidate metadata count is invalid")
    if metadata_value["candidate_count"] != candidate_count or status_value["candidate_count"] != candidate_count:
        raise CandidateSnapshotError("candidate count mismatch")
    if status_value["candidate_metadata_count"] != candidate_count:
        raise CandidateSnapshotError("candidate metadata count binding mismatch")
    for name in (
        "raw_count",
        "valid_config_count",
        "exact_unique_count",
        "unique_endpoint_count",
        "candidate_count",
        "protected_asia_count",
        "candidate_metadata_schema_version",
        "candidate_metadata_count",
    ):
        if isinstance(status_value[name], bool) or not isinstance(status_value[name], int) or status_value[name] < 0:
            raise CandidateSnapshotError("candidate status count is invalid")
    if not (
        status_value["raw_count"] >= status_value["valid_config_count"] >= status_value["exact_unique_count"]
        and status_value["exact_unique_count"] >= status_value["unique_endpoint_count"]
    ):
        raise CandidateSnapshotError("candidate staging counts are inconsistent")
    region_counts = {**{region: 0 for region in REGION_ORDER}, "unknown": 0}
    protected_count = 0
    github_counts = {"passed": 0, "bypassed_asia": 0}
    for entry in ordered:
        region_counts[_candidate_primary_region(entry.metadata)] += 1
        protected_count += int(entry.metadata["protected_asia"])
        github_counts[entry.metadata["github_check_state"]] += 1
    if status_region_counts != region_counts or status_value["protected_asia_count"] != protected_count:
        raise CandidateSnapshotError("candidate region counts do not match metadata")
    if (
        status_github_counts["passed"] != github_counts["passed"]
        or status_github_counts["bypassed_asia"] != github_counts["bypassed_asia"]
    ):
        raise CandidateSnapshotError("candidate GitHub check counts do not match metadata")
    expected_changes = {
        "candidate_count": candidate_count - int(previous_counts["candidate_count"]),
        "protected_asia_count": protected_count - int(previous_counts["protected_asia_count"]),
        "regions": {
            region: region_counts[region] - int(previous_region_counts[region])
            for region in REGION_ORDER
        },
    }
    if changes != expected_changes:
        raise CandidateSnapshotError("candidate changes do not match current and previous counts")
    expected_retain, expected_quorum, expected_gate = _evaluate_publish_gate(
        candidate_count=candidate_count,
        protected_asia_count=protected_count,
        region_counts=region_counts,
        sources=sources,
        previous={
            **previous_counts,
            "region_hint_counts": previous_region_counts,
        },
    )
    if retain_ratios != expected_retain:
        raise CandidateSnapshotError("candidate retain ratios do not match the publish policy")
    if source_quorum != expected_quorum:
        raise CandidateSnapshotError("candidate source quorum does not match source metadata")
    if publish_gate != expected_gate or publish_gate["passed"] is not True:
        raise CandidateSnapshotError("candidate publish gate did not pass")
    if status_value["policy_version"] != CANDIDATE_PUBLISH_POLICY_VERSION:
        raise CandidateSnapshotError("candidate publish policy is unsupported")
    return CandidateSnapshot(
        profile_bytes=profile_bytes,
        status=status_value,
        metadata=metadata_value,
        ordered_candidates=tuple(ordered),
        snapshot_id=snapshot_id,
        main_sha=str(status_value["main_sha"]),
        profile_sha256=profile_sha256,
        metadata_sha256=metadata_sha256,
        identity_key_version=identity.identity_key_version,
        identity_epoch=identity.identity_epoch,
    )


def write_candidate_snapshot(output_dir: str | Path, snapshot: CandidateSnapshot) -> None:
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "clash.yaml").write_bytes(snapshot.profile_bytes)
    (destination / "candidate-metadata.json").write_bytes(_json_bytes(snapshot.metadata))
    (destination / "status.json").write_bytes(_json_bytes(snapshot.status))
    run_at = str(snapshot.status["run_at"])
    (destination / "last-run.txt").write_text(run_at + "\n", encoding="utf-8")
    (destination / "README.md").write_text(
        "# Clash Verge Candidate Snapshot V2\n\n"
        "This is a broad candidate pool. Asia-labelled candidates may be retained without a GitHub liveness check.\n\n"
        f"Subscription URL:\n\n{snapshot.status['profile_url']}\n\n"
        f"Candidate metadata:\n\n{snapshot.status['candidate_metadata_url']}\n\n"
        f"Last run: {run_at}\n",
        encoding="utf-8",
    )


def _prepare_command(args: argparse.Namespace) -> int:
    provenance = merge_provenance_staging(args.provenance)
    previous_profile = _load_profile_file(args.previous_profile)
    previous_status = _load_json_file(args.previous_status)
    previous_metadata = _load_json_file(args.previous_metadata)
    payload = prepare_candidate_identity_input(
        Path(args.profile).read_bytes(),
        provenance,
        run_at=args.run_at or utc_timestamp(),
        mode=args.mode,
        main_sha=args.main_sha,
        profile_url=args.profile_url,
        candidate_metadata_url=args.candidate_metadata_url,
        previous_state=args.previous_state,
        previous_profile=previous_profile,
        previous_status=previous_status,
        previous_metadata=previous_metadata,
        github_failed_count=_read_github_failed_count(args.github_check_report),
    )
    write_candidate_identity_input(args.output, payload)
    return 0


def _build_command(args: argparse.Namespace) -> int:
    snapshot = build_candidate_snapshot(load_candidate_identity_input(args.input))
    write_candidate_snapshot(args.output_dir, snapshot)
    return 0


def _validate_command(args: argparse.Namespace) -> int:
    status = _load_json_file(args.status)
    metadata = _load_json_file(args.metadata)
    if status is None or metadata is None:
        raise CandidateSnapshotError("candidate validation files are missing")
    validate_candidate_snapshot(Path(args.profile).read_bytes(), status, metadata)
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--provenance", action="append", required=True)
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--run-at", default="")
    prepare.add_argument("--mode", required=True)
    prepare.add_argument("--main-sha", required=True)
    prepare.add_argument("--profile-url", required=True)
    prepare.add_argument("--candidate-metadata-url", required=True)
    prepare.add_argument("--previous-state", choices=("confirmed_absent", "present"), required=True)
    prepare.add_argument("--previous-profile", default="")
    prepare.add_argument("--previous-status", default="")
    prepare.add_argument("--previous-metadata", default="")
    prepare.add_argument("--github-check-report", default="")
    build = commands.add_parser("build")
    build.add_argument("--input", required=True)
    build.add_argument("--output-dir", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--profile", required=True)
    validate.add_argument("--status", required=True)
    validate.add_argument("--metadata", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.command == "prepare":
        return _prepare_command(args)
    if args.command == "build":
        return _build_command(args)
    return _validate_command(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CandidateSnapshotError, CandidateSourceError, IdentityError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


__all__ = [
    "CANDIDATE_METADATA_KIND",
    "CANDIDATE_METADATA_SCHEMA_VERSION",
    "CANDIDATE_STATUS_KIND",
    "CANDIDATE_STATUS_SCHEMA_VERSION",
    "CandidateSnapshot",
    "CandidateSnapshotEntry",
    "CandidateSnapshotError",
    "build_candidate_snapshot",
    "evaluate_candidate_publish_gate",
    "load_candidate_identity_input",
    "prepare_candidate_identity_input",
    "validate_candidate_identity_input",
    "validate_candidate_snapshot",
    "write_candidate_identity_input",
    "write_candidate_snapshot",
]
