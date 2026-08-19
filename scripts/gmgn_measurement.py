#!/usr/bin/env python3
"""GMGN V2 measurement contracts, scheduler, and strict shard summaries.

This module is intentionally independent from the legacy schema-v2 shadow
pipeline.  C5 may wire these pure functions into CNB jobs without changing the
current production path.  Candidate identities are consumed from C1/C3; this
module never derives or hashes proxy identities itself.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import secrets
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

from scripts.candidate_contract import CANDIDATE_METADATA_SCHEMA_VERSION
from scripts.proxy_identity import validate_public_id


MANIFEST_KIND = "cnb-gmgn-shadow-manifest"
MANIFEST_SCHEMA_VERSION = 3
PRIVATE_FRAGMENT_KIND = "cnb-gmgn-private-fragment"
PRIVATE_FRAGMENT_SCHEMA_VERSION = 2
REDACTED_FRAGMENT_KIND = "cnb-gmgn-redacted-fragment"
REDACTED_FRAGMENT_SCHEMA_VERSION = 3
VALIDITY_RESULT_KIND = "cnb-gmgn-validity-result"
VALIDITY_RESULT_SCHEMA_VERSION = 1

TOTAL_ROUNDS = 20
SHARD_COUNT = 4
REQUEST_TIMEOUT_MS = 3000
QUALIFIED_DELAY_MS = 1000
MINIMUM_OBSERVATION_WINDOW_SECONDS = 900.0
DEFAULT_WORKERS = 16
SHARD_STAGGER_SECONDS = (0, 15, 30, 45)
SHARD_CONTROLLER_PORTS = (19090, 19091, 19092, 19093)
SHARD_MIXED_PORTS = (17890, 17891, 17892, 17893)
SCHEDULER_POLICY_VERSION = "gmgn-scheduler-v1"
VALIDITY_POLICY_VERSION = "gmgn-validity-v6"
CANARY_POLICY_VERSION = "gmgn-canary-v3"
RESOLVER_POLICY_VERSION = "gmgn-resolver-v4"
NETWORK_GUARD_POLICY_VERSION = "gmgn-network-guard-v3"
SOURCE_MAX_AGE_SECONDS = 36_000
SOURCE_FUTURE_SKEW_SECONDS = 300
ALLOWED_WORKER_COUNTS = frozenset({8, 16, 24, 32})
BENCHMARK_EVIDENCE_FIELDS = frozenset(
    {
        "run_id",
        "workers",
        "valid_run",
        "cohort_sha256",
        "runtime_sha256",
        "wall_seconds",
        "throughput_attempts_per_second",
        "candidate_no_result_rate",
        "target_403_429_rate",
        "controller_request_rate",
        "controller_unhealthy_count",
        "control_canary_passed",
        "shard_duration_skew",
        "cpu_percent_peak",
        "memory_bytes_peak",
    }
)

ERROR_CATEGORIES = (
    "target_403",
    "target_429",
    "target_5xx",
    "dns",
    "tls",
    "connect",
    "proxy_auth",
    "client_timeout",
    "controller_request",
    "controller_unhealthy",
    "other",
)

SAMPLE_FIELDS = frozenset(
    {"candidate_id", "round", "started_at", "finished_at", "delay_ms", "error_category"}
)
CONTROL_SAMPLE_FIELDS = frozenset({"round", "delay_ms", "error_category"})
CANARY_SAMPLE_FIELDS = frozenset({"canary_id", *CONTROL_SAMPLE_FIELDS})
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

MANIFEST_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "created_at",
        "trigger_type",
        "attempt_id",
        "retry_of",
        "snapshot_id",
        "source_run_at",
        "main_sha",
        "source_sha256",
        "profile_sha256",
        "candidate_metadata_sha256",
        "candidate_metadata_schema_version",
        "candidate_metadata_count",
        "candidate_count",
        "identity_key_version",
        "identity_epoch",
        "target_url",
        "expected_status",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "minimum_observation_window_seconds",
        "shard_count",
        "workers_per_shard",
        "shard_stagger_seconds",
        "scheduler_policy_version",
        "validity_policy_version",
        "canary_policy_version",
        "canary_set_sha256",
        "python_version",
        "pyyaml_version",
        "mihomo_version",
        "mihomo_sha256",
        "resolver_policy_version",
        "network_guard_policy_version",
        "shards",
    }
)

MANIFEST_SHARD_FIELDS = frozenset(
    {
        "shard_index",
        "candidate_count",
        "candidate_ids_sha256",
        "stagger_seconds",
        "controller_port",
        "mixed_port",
        "runtime_subdir",
        "private_fragment_file",
        "controller_secret_sha256",
    }
)

PRIVATE_FRAGMENT_FIELDS = frozenset(
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
        "controller_port",
        "mixed_port",
        "runtime_subdir",
        "private_fragment_file",
        "controller_secret_sha256",
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
        "controller_checks",
        "control_samples",
        "canary_samples",
        "egress",
    }
)


class MeasurementError(ValueError):
    """Raised when a V2 measurement contract is incomplete or inconsistent."""


@dataclass(frozen=True)
class ScheduledRun:
    samples: tuple[dict[str, Any], ...]
    round_trends: tuple[dict[str, Any], ...]
    control_samples: tuple[dict[str, Any], ...]
    canary_samples: tuple[dict[str, Any], ...]
    controller_checks: tuple[dict[str, Any], ...]
    egress_before: dict[str, Any]
    egress_after: dict[str, Any]


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def candidate_ids_sha256(candidate_ids: Iterable[str]) -> str:
    normalized = [validate_public_id(value, "candidate") for value in candidate_ids]
    return hashlib.sha256(("\n".join(normalized) + "\n").encode("ascii")).hexdigest()


def _candidate_id(candidate: Any) -> str:
    if isinstance(candidate, Mapping):
        value = candidate.get("candidate_id")
    else:
        value = getattr(candidate, "candidate_id", None)
    return validate_public_id(value, "candidate")


def _candidate_proxy(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, Mapping):
        proxy = candidate.get("proxy")
    else:
        proxy = getattr(candidate, "proxy", None)
    if not isinstance(proxy, Mapping):
        raise MeasurementError("candidate proxy must be a mapping")
    return copy.deepcopy(dict(proxy))


def normalize_candidate(candidate: Any) -> dict[str, Any]:
    return {"candidate_id": _candidate_id(candidate), "proxy": _candidate_proxy(candidate)}


def partition_candidates(
    candidates: Iterable[Any], shard_count: int = SHARD_COUNT
) -> list[list[dict[str, Any]]]:
    """Sort by C3 candidate ID and round-robin into stable balanced shards."""

    if shard_count < 1:
        raise MeasurementError("shard_count must be positive")
    normalized = [normalize_candidate(candidate) for candidate in candidates]
    normalized.sort(key=lambda item: item["candidate_id"])
    ids = [item["candidate_id"] for item in normalized]
    if not ids:
        raise MeasurementError("candidate snapshot is empty")
    if len(ids) != len(set(ids)):
        raise MeasurementError("candidate snapshot contains duplicate candidate IDs")
    shards: list[list[dict[str, Any]]] = [[] for _ in range(shard_count)]
    for index, candidate in enumerate(normalized):
        shards[index % shard_count].append(candidate)
    return shards


def build_manifest_v3(
    snapshot: Any,
    *,
    run_id: str,
    created_at: str,
    trigger_type: str,
    attempt_id: str,
    retry_of: str | None,
    source_run_at: str,
    source_sha256: str,
    canary_set: Sequence[str],
    python_version: str,
    pyyaml_version: str,
    mihomo_version: str,
    mihomo_sha256: str,
    resolver_policy_version: str,
    network_guard_policy_version: str,
    controller_secret_sha256s: Sequence[str],
    workers_per_shard: int = DEFAULT_WORKERS,
) -> tuple[dict[str, Any], list[list[dict[str, Any]]]]:
    """Build manifest v3 from a C1 ``CandidateSnapshot`` after identity preflight."""

    ordered_candidates = getattr(snapshot, "ordered_candidates", None)
    if ordered_candidates is None:
        raise MeasurementError("snapshot must be a validated CandidateSnapshot")
    status = getattr(snapshot, "status", None)
    if not isinstance(status, Mapping):
        raise MeasurementError("snapshot status binding is missing")
    shards = partition_candidates(ordered_candidates, SHARD_COUNT)
    canaries = sorted(str(value).strip() for value in canary_set)
    if not canaries or any(not value for value in canaries) or len(canaries) != len(set(canaries)):
        raise MeasurementError("canary set must contain stable non-empty IDs")
    metadata = getattr(snapshot, "metadata", {})
    metadata_schema = metadata.get("schema_version") if isinstance(metadata, Mapping) else None
    metadata_count = metadata.get("candidate_count") if isinstance(metadata, Mapping) else None
    expected_status_bindings = {
        "snapshot_id": getattr(snapshot, "snapshot_id", ""),
        "main_sha": getattr(snapshot, "main_sha", ""),
        "profile_sha256": getattr(snapshot, "profile_sha256", ""),
        "candidate_metadata_sha256": getattr(snapshot, "metadata_sha256", ""),
        "candidate_metadata_schema_version": metadata_schema,
        "candidate_metadata_count": metadata_count,
        "candidate_count": len(ordered_candidates),
        "identity_key_version": getattr(snapshot, "identity_key_version", ""),
        "identity_epoch": getattr(snapshot, "identity_epoch", ""),
        "run_at": source_run_at,
    }
    for field, expected_value in expected_status_bindings.items():
        if status.get(field) != expected_value:
            raise MeasurementError(f"snapshot status {field} binding mismatch")
    secret_hashes = [str(value).lower() for value in controller_secret_sha256s]
    if len(secret_hashes) != SHARD_COUNT or len(secret_hashes) != len(set(secret_hashes)):
        raise MeasurementError("four unique controller secret hashes are required")
    for secret_hash in secret_hashes:
        _hex(secret_hash, 64, "controller_secret_sha256")
    manifest = {
        "kind": MANIFEST_KIND,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "run_id": str(run_id),
        "created_at": str(created_at),
        "trigger_type": str(trigger_type),
        "attempt_id": str(attempt_id),
        "retry_of": retry_of,
        "snapshot_id": str(getattr(snapshot, "snapshot_id", "")),
        "source_run_at": str(source_run_at),
        "main_sha": str(getattr(snapshot, "main_sha", "")),
        "source_sha256": str(source_sha256),
        "profile_sha256": str(getattr(snapshot, "profile_sha256", "")),
        "candidate_metadata_sha256": str(getattr(snapshot, "metadata_sha256", "")),
        "candidate_metadata_schema_version": metadata_schema,
        "candidate_metadata_count": metadata_count,
        "candidate_count": len(ordered_candidates),
        "identity_key_version": str(getattr(snapshot, "identity_key_version", "")),
        "identity_epoch": str(getattr(snapshot, "identity_epoch", "")),
        "target_url": "https://gmgn.ai/",
        "expected_status": 200,
        "request_timeout_ms": REQUEST_TIMEOUT_MS,
        "qualified_delay_ms": QUALIFIED_DELAY_MS,
        "total_rounds": TOTAL_ROUNDS,
        "minimum_observation_window_seconds": MINIMUM_OBSERVATION_WINDOW_SECONDS,
        "shard_count": SHARD_COUNT,
        "workers_per_shard": workers_per_shard,
        "shard_stagger_seconds": list(SHARD_STAGGER_SECONDS),
        "scheduler_policy_version": SCHEDULER_POLICY_VERSION,
        "validity_policy_version": VALIDITY_POLICY_VERSION,
        "canary_policy_version": CANARY_POLICY_VERSION,
        "canary_set_sha256": _sha256_json(canaries),
        "python_version": str(python_version),
        "pyyaml_version": str(pyyaml_version),
        "mihomo_version": str(mihomo_version),
        "mihomo_sha256": str(mihomo_sha256),
        "resolver_policy_version": str(resolver_policy_version),
        "network_guard_policy_version": str(network_guard_policy_version),
        "shards": [
            {
                "shard_index": index,
                "candidate_count": len(shard),
                "candidate_ids_sha256": candidate_ids_sha256(
                    item["candidate_id"] for item in shard
                ),
                "stagger_seconds": SHARD_STAGGER_SECONDS[index],
                "controller_port": SHARD_CONTROLLER_PORTS[index],
                "mixed_port": SHARD_MIXED_PORTS[index],
                "runtime_subdir": f"shards/shard-{index}",
                "private_fragment_file": f"fragments/shard-{index}.json",
                "controller_secret_sha256": secret_hashes[index],
            }
            for index, shard in enumerate(shards)
        ],
    }
    validate_manifest_v3(manifest)
    return manifest, shards


def _hex(value: Any, length: int, label: str) -> str:
    text = str(value or "").lower()
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", text):
        raise MeasurementError(f"{label} is malformed")
    return text


def _timestamp(value: Any, label: str) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MeasurementError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise MeasurementError(f"{label} must include a timezone")
    return text


def _parsed_timestamp(value: Any, label: str) -> datetime:
    text = _timestamp(value, label)
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def validate_manifest_v3(manifest: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, Mapping) or frozenset(manifest) != MANIFEST_FIELDS:
        raise MeasurementError("manifest fields are incomplete or unexpected")
    value = dict(manifest)
    if value["kind"] != MANIFEST_KIND or value["schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise MeasurementError("unsupported GMGN manifest")
    if not re.fullmatch(r"gmgnv2_[A-Za-z0-9._-]{8,96}", str(value["run_id"])):
        raise MeasurementError("manifest run_id is malformed")
    created_at = _parsed_timestamp(value["created_at"], "created_at")
    source_run_at = _parsed_timestamp(value["source_run_at"], "source_run_at")
    source_age = (created_at - source_run_at).total_seconds()
    if not -SOURCE_FUTURE_SKEW_SECONDS <= source_age <= SOURCE_MAX_AGE_SECONDS:
        raise MeasurementError("manifest source snapshot is stale or from the future")
    if not re.fullmatch(r"candidate_[0-9a-f]{24}", str(value["snapshot_id"])):
        raise MeasurementError("manifest snapshot/trigger fields are missing")
    trigger_type = value["trigger_type"]
    attempt_id = str(value["attempt_id"] or "")
    retry_of = value["retry_of"]
    if trigger_type not in {"manual", "retry"} or not re.fullmatch(
        r"[0-9a-f]{24}", attempt_id
    ):
        raise MeasurementError("manifest attempt relation is malformed")
    if trigger_type == "manual":
        if retry_of is not None:
            raise MeasurementError("manual manifest cannot declare retry_of")
    elif (
        not isinstance(retry_of, str)
        or not re.fullmatch(r"[0-9a-f]{24}", retry_of)
        or retry_of == attempt_id
    ):
        raise MeasurementError("retry manifest lacks a valid retry_of")
    _hex(value["main_sha"], 40, "main_sha")
    for name in (
        "source_sha256",
        "profile_sha256",
        "candidate_metadata_sha256",
        "mihomo_sha256",
        "canary_set_sha256",
    ):
        _hex(value[name], 64, name)
    if value["target_url"] != "https://gmgn.ai/" or value["expected_status"] != 200:
        raise MeasurementError("manifest target contract is invalid")
    if value["request_timeout_ms"] != REQUEST_TIMEOUT_MS or value["qualified_delay_ms"] != QUALIFIED_DELAY_MS:
        raise MeasurementError("manifest delay contract is invalid")
    if value["total_rounds"] != TOTAL_ROUNDS or value["shard_count"] != SHARD_COUNT:
        raise MeasurementError("manifest rounds/shards contract is invalid")
    if float(value["minimum_observation_window_seconds"]) != MINIMUM_OBSERVATION_WINDOW_SECONDS:
        raise MeasurementError("manifest observation window is invalid")
    if (
        isinstance(value["workers_per_shard"], bool)
        or not isinstance(value["workers_per_shard"], int)
        or value["workers_per_shard"] not in ALLOWED_WORKER_COUNTS
    ):
        raise MeasurementError("manifest workers_per_shard is invalid")
    if value["shard_stagger_seconds"] != list(SHARD_STAGGER_SECONDS):
        raise MeasurementError("manifest shard stagger is invalid")
    if value["scheduler_policy_version"] != SCHEDULER_POLICY_VERSION or value["validity_policy_version"] != VALIDITY_POLICY_VERSION:
        raise MeasurementError("manifest policy version is invalid")
    if (
        isinstance(value["candidate_metadata_schema_version"], bool)
        or not isinstance(value["candidate_metadata_schema_version"], int)
        or value["candidate_metadata_schema_version"]
        != CANDIDATE_METADATA_SCHEMA_VERSION
    ):
        raise MeasurementError("manifest candidate metadata schema is invalid")
    if value["candidate_metadata_count"] != value["candidate_count"]:
        raise MeasurementError("manifest candidate metadata count mismatch")
    for field in (
        "identity_key_version",
        "identity_epoch",
        "python_version",
        "pyyaml_version",
        "mihomo_version",
    ):
        if not isinstance(value[field], str) or not value[field].strip():
            raise MeasurementError(f"manifest {field} is missing")
    if value["canary_policy_version"] != CANARY_POLICY_VERSION:
        raise MeasurementError("manifest canary policy version is invalid")
    if value["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
        raise MeasurementError("manifest resolver policy version is invalid")
    if value["network_guard_policy_version"] != NETWORK_GUARD_POLICY_VERSION:
        raise MeasurementError("manifest network guard policy version is invalid")
    count = int(value["candidate_count"])
    if isinstance(value["candidate_count"], bool) or not isinstance(value["candidate_count"], int) or count < 1:
        raise MeasurementError("manifest candidate_count is invalid")
    shards = value["shards"]
    if not isinstance(shards, list) or len(shards) != SHARD_COUNT:
        raise MeasurementError("manifest shard list is incomplete")
    seen: set[int] = set()
    controller_ports: set[int] = set()
    mixed_ports: set[int] = set()
    runtime_subdirs: set[str] = set()
    private_fragment_files: set[str] = set()
    secret_hashes: set[str] = set()
    total = 0
    for shard in shards:
        if not isinstance(shard, Mapping) or frozenset(shard) != MANIFEST_SHARD_FIELDS:
            raise MeasurementError("manifest shard fields are invalid")
        raw_index = shard["shard_index"]
        if isinstance(raw_index, bool) or not isinstance(raw_index, int):
            raise MeasurementError("manifest shard index is invalid")
        index = raw_index
        if index in seen or index not in range(SHARD_COUNT):
            raise MeasurementError("manifest shard indices are invalid")
        seen.add(index)
        shard_count = shard["candidate_count"]
        if isinstance(shard_count, bool) or not isinstance(shard_count, int) or shard_count < 0:
            raise MeasurementError("manifest shard candidate_count is invalid")
        total += shard_count
        _hex(shard["candidate_ids_sha256"], 64, "candidate_ids_sha256")
        stagger = shard["stagger_seconds"]
        if isinstance(stagger, bool) or not isinstance(stagger, int) or stagger != SHARD_STAGGER_SECONDS[index]:
            raise MeasurementError("manifest shard stagger drift")
        controller_port = shard["controller_port"]
        mixed_port = shard["mixed_port"]
        if (
            isinstance(controller_port, bool)
            or not isinstance(controller_port, int)
            or controller_port != SHARD_CONTROLLER_PORTS[index]
            or isinstance(mixed_port, bool)
            or not isinstance(mixed_port, int)
            or mixed_port != SHARD_MIXED_PORTS[index]
        ):
            raise MeasurementError("manifest shard port contract is invalid")
        runtime_subdir = str(shard["runtime_subdir"])
        private_fragment_file = str(shard["private_fragment_file"])
        for path_value, expected_value, label in (
            (runtime_subdir, f"shards/shard-{index}", "runtime_subdir"),
            (
                private_fragment_file,
                f"fragments/shard-{index}.json",
                "private_fragment_file",
            ),
        ):
            path = PurePosixPath(path_value)
            if path.is_absolute() or ".." in path.parts or path_value != expected_value:
                raise MeasurementError(f"manifest shard {label} is invalid")
        secret_hash = _hex(
            shard["controller_secret_sha256"], 64, "controller_secret_sha256"
        )
        controller_ports.add(controller_port)
        mixed_ports.add(mixed_port)
        runtime_subdirs.add(runtime_subdir)
        private_fragment_files.add(private_fragment_file)
        secret_hashes.add(secret_hash)
    if total != count:
        raise MeasurementError("manifest shard counts do not match candidate_count")
    shard_sizes = [int(shard["candidate_count"]) for shard in shards]
    if max(shard_sizes) - min(shard_sizes) > 1:
        raise MeasurementError("manifest shards are not balanced")
    if not all(
        len(values) == SHARD_COUNT
        for values in (
            controller_ports,
            mixed_ports,
            runtime_subdirs,
            private_fragment_files,
            secret_hashes,
        )
    ):
        raise MeasurementError("manifest shard runtimes are not independent")
    if controller_ports & mixed_ports:
        raise MeasurementError("manifest controller and mixed ports overlap")
    return value


def classify_error(
    error: Any = None,
    *,
    target_status: int | None = None,
    controller_status: int | None = None,
    controller_healthy: bool = True,
) -> str:
    """Normalize private errors to the only public-safe V2 categories."""

    if not controller_healthy:
        return "controller_unhealthy"
    if target_status == 403:
        return "target_403"
    if target_status == 429:
        return "target_429"
    if target_status is not None and 500 <= target_status <= 599:
        return "target_5xx"
    text = str(error or "").lower()
    if "403" in text and "target" in text:
        return "target_403"
    if "429" in text and "target" in text:
        return "target_429"
    if re.search(r"target[^0-9]{0,24}5\d\d", text):
        return "target_5xx"
    if "dns" in text or "name resolution" in text or "no such host" in text:
        return "dns"
    if "tls" in text or "certificate" in text or "handshake" in text:
        return "tls"
    if "auth" in text or "407" in text:
        return "proxy_auth"
    if "timeout" in text or "timed out" in text or "deadline" in text or controller_status == 504:
        return "client_timeout"
    if any(token in text for token in ("connect", "refused", "reset", "eof", "network unreachable")):
        return "connect"
    if controller_status is not None or "controller" in text:
        return "controller_request"
    return "other"


def normalize_outcome(outcome: Mapping[str, Any] | None) -> tuple[int | None, str | None]:
    value = dict(outcome or {})
    target_status = value.get("target_status")
    controller_status = value.get("controller_status")
    for status, label in ((target_status, "target_status"), (controller_status, "controller_status")):
        if status is not None and (isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599):
            raise MeasurementError(f"{label} must be a valid HTTP status")
    if controller_status is not None and controller_status != 200:
        return None, classify_error(
            value.get("error"),
            target_status=target_status,
            controller_status=controller_status,
            controller_healthy=bool(value.get("controller_healthy", True)),
        )
    if target_status is not None and target_status != 200:
        return None, classify_error(
            value.get("error"),
            target_status=target_status,
            controller_status=controller_status,
            controller_healthy=bool(value.get("controller_healthy", True)),
        )
    delay = value.get("delay_ms")
    if delay is not None:
        if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(float(delay)) or float(delay) <= 0:
            raise MeasurementError("delay_ms must be a positive finite number")
        if value.get("error_category") is not None or value.get("error") is not None or value.get("controller_healthy") is False:
            raise MeasurementError("responsive outcome cannot also contain an error")
        return int(math.ceil(float(delay))), None
    category = value.get("error_category")
    if category is None:
        category = classify_error(
            value.get("error"),
            target_status=value.get("target_status"),
            controller_status=value.get("controller_status"),
            controller_healthy=bool(value.get("controller_healthy", True)),
        )
    if category not in ERROR_CATEGORIES:
        raise MeasurementError("unknown error category")
    return None, str(category)


def _validate_terminal_sample(sample: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(sample, Mapping) or frozenset(sample) != SAMPLE_FIELDS:
        raise MeasurementError("candidate sample fields are incomplete or unexpected")
    value = dict(sample)
    value["candidate_id"] = validate_public_id(value["candidate_id"], "candidate")
    round_number = value["round"]
    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number not in range(1, TOTAL_ROUNDS + 1):
        raise MeasurementError("candidate sample round is invalid")
    for field in ("started_at", "finished_at"):
        timestamp = value[field]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)) or not math.isfinite(float(timestamp)):
            raise MeasurementError("candidate sample timestamp is invalid")
        value[field] = float(timestamp)
    if value["finished_at"] < value["started_at"]:
        raise MeasurementError("sample finished before it started")
    delay = value["delay_ms"]
    category = value["error_category"]
    if delay is None:
        if category not in ERROR_CATEGORIES:
            raise MeasurementError("candidate sample has unknown error category")
    else:
        if isinstance(delay, bool) or not isinstance(delay, int) or delay <= 0 or category is not None:
            raise MeasurementError("responsive candidate sample is invalid")
    return value


def _expected_round_trends(
    samples: Sequence[Mapping[str, Any]], *, candidate_count: int
) -> list[dict[str, Any]]:
    by_round: dict[int, list[dict[str, Any]]] = {
        round_number: [] for round_number in range(1, TOTAL_ROUNDS + 1)
    }
    for sample in samples:
        normalized = _validate_terminal_sample(sample)
        by_round[int(normalized["round"])].append(normalized)
    output: list[dict[str, Any]] = []
    for round_number in range(1, TOTAL_ROUNDS + 1):
        current = by_round[round_number]
        if len(current) != candidate_count:
            raise MeasurementError("round does not contain exactly one sample per candidate")
        error_counts = {category: 0 for category in ERROR_CATEGORIES}
        within = slow = no_result = 0
        for sample in current:
            delay = sample["delay_ms"]
            if delay is None:
                no_result += 1
                error_counts[str(sample["error_category"])] += 1
            elif int(delay) <= QUALIFIED_DELAY_MS:
                within += 1
            else:
                slow += 1
        output.append(
            {
                "round": round_number,
                "attempt_count": candidate_count,
                "within_1000_count": within,
                "slow_response_count": slow,
                "no_result_count": no_result,
                "error_counts": error_counts,
            }
        )
    return output


def _terminal_sample(
    candidate_id: str,
    round_number: int,
    started_at: float,
    finished_at: float,
    outcome: Mapping[str, Any] | None,
) -> dict[str, Any]:
    delay, category = normalize_outcome(outcome)
    if finished_at < started_at:
        raise MeasurementError("sample finished before it started")
    return {
        "candidate_id": candidate_id,
        "round": round_number,
        "started_at": round(float(started_at), 6),
        "finished_at": round(float(finished_at), 6),
        "delay_ms": delay,
        "error_category": category,
    }


def run_measurement_schedule(
    candidates: Sequence[Any],
    attempt: Callable[[dict[str, Any], int], Mapping[str, Any]],
    *,
    workers: int = DEFAULT_WORKERS,
    total_rounds: int = TOTAL_ROUNDS,
    minimum_observation_window_seconds: float = MINIMUM_OBSERVATION_WINDOW_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    health_check: Callable[[str, int], Mapping[str, Any] | None] | None = None,
    control_probe: Callable[[int], Mapping[str, Any]] | None = None,
    canary_probe: Callable[[str, int], Mapping[str, Any]] | None = None,
    canary_ids: Sequence[str] = (),
    egress_probe: Callable[[str], Mapping[str, Any]] | None = None,
    stagger_seconds: int = 0,
) -> ScheduledRun:
    """Run barriered rounds with one in-flight request per candidate.

    Round zero establishes ``anchor=max(round0.started_at)``.  Rounds 1..19
    are submitted no earlier than the evenly spaced 900-second pacing slots.
    """

    normalized = [normalize_candidate(candidate) for candidate in candidates]
    if not normalized:
        raise MeasurementError("measurement shard is empty")
    if workers < 1 or total_rounds < 2 or minimum_observation_window_seconds <= 0:
        raise MeasurementError("scheduler settings are invalid")
    if (
        isinstance(stagger_seconds, bool)
        or not isinstance(stagger_seconds, int)
        or stagger_seconds not in SHARD_STAGGER_SECONDS
    ):
        raise MeasurementError("scheduler shard stagger is invalid")
    ids = [item["candidate_id"] for item in normalized]
    if len(ids) != len(set(ids)):
        raise MeasurementError("measurement shard contains duplicate candidate IDs")
    health = health_check or (lambda _phase, _round: {"healthy": True})
    egress = egress_probe or (lambda _phase: {})
    samples: list[dict[str, Any]] = []
    trends: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    canaries: list[dict[str, Any]] = []
    controller_checks: list[dict[str, Any]] = []
    if stagger_seconds:
        sleeper(float(stagger_seconds))
    egress_before = dict(egress("before"))
    anchor: float | None = None

    with ThreadPoolExecutor(max_workers=min(workers, len(normalized))) as executor:
        for round_index in range(total_rounds):
            round_number = round_index + 1
            if anchor is not None:
                target = anchor + round_index * minimum_observation_window_seconds / (total_rounds - 1)
                remaining = target - clock()
                if remaining > 0:
                    sleeper(remaining)
            before = dict(health("before", round_number) or {})
            before.setdefault("healthy", True)
            before.update({"phase": "before", "round": round_number})
            controller_checks.append(before)
            if not before["healthy"]:
                raise MeasurementError("controller unhealthy before round")
            if control_probe is not None:
                try:
                    control_outcome = control_probe(round_number)
                except Exception as exc:
                    control_outcome = {"error": str(exc)}
                delay, category = normalize_outcome(control_outcome)
                controls.append({"round": round_number, "delay_ms": delay, "error_category": category})
            if canary_probe is not None:
                for canary_id in canary_ids:
                    try:
                        canary_outcome = canary_probe(str(canary_id), round_number)
                    except Exception as exc:
                        canary_outcome = {"error": str(exc)}
                    delay, category = normalize_outcome(canary_outcome)
                    canaries.append({"canary_id": str(canary_id), "round": round_number, "delay_ms": delay, "error_category": category})

            # Stable rotation avoids permanently leaving one candidate at the queue tail.
            offset = round_index % len(normalized)
            ordered = normalized[offset:] + normalized[:offset]

            def invoke(candidate: dict[str, Any]) -> dict[str, Any]:
                started = clock()
                try:
                    outcome = attempt(copy.deepcopy(candidate), round_number)
                except Exception as exc:  # raw text is classified then discarded
                    outcome = {"error": str(exc)}
                finished = clock()
                return _terminal_sample(candidate["candidate_id"], round_number, started, finished, outcome)

            futures = [executor.submit(invoke, candidate) for candidate in ordered]
            current = [future.result() for future in as_completed(futures)]
            if round_index == 0:
                anchor = max(float(sample["started_at"]) for sample in current)
            current.sort(key=lambda item: item["candidate_id"])
            samples.extend(current)
            error_counts = {category: 0 for category in ERROR_CATEGORIES}
            within = slow = no_result = 0
            for sample in current:
                delay = sample["delay_ms"]
                if delay is None:
                    no_result += 1
                    error_counts[str(sample["error_category"])] += 1
                elif int(delay) <= QUALIFIED_DELAY_MS:
                    within += 1
                else:
                    slow += 1
            trends.append(
                {
                    "round": round_number,
                    "attempt_count": len(current),
                    "within_1000_count": within,
                    "slow_response_count": slow,
                    "no_result_count": no_result,
                    "error_counts": error_counts,
                }
            )
            after = dict(health("after", round_number) or {})
            after.setdefault("healthy", True)
            after.update({"phase": "after", "round": round_number})
            controller_checks.append(after)
            if not after["healthy"]:
                raise MeasurementError("controller unhealthy after round")

    egress_after = dict(egress("after"))
    grouped: dict[str, list[dict[str, Any]]] = {candidate_id: [] for candidate_id in ids}
    for sample in samples:
        grouped[sample["candidate_id"]].append(sample)
    for candidate_id, candidate_samples in grouped.items():
        candidate_samples.sort(key=lambda item: int(item["round"]))
        if [item["round"] for item in candidate_samples] != list(range(1, total_rounds + 1)):
            raise MeasurementError(f"candidate {candidate_id} does not have exactly one terminal sample per round")
        span = float(candidate_samples[-1]["started_at"]) - float(candidate_samples[0]["started_at"])
        if span + 1e-6 < minimum_observation_window_seconds:
            raise MeasurementError(f"candidate {candidate_id} observation window is too short")
    samples.sort(key=lambda item: (item["candidate_id"], int(item["round"])))
    return ScheduledRun(
        samples=tuple(samples),
        round_trends=tuple(trends),
        control_samples=tuple(controls),
        canary_samples=tuple(canaries),
        controller_checks=tuple(controller_checks),
        egress_before=egress_before,
        egress_after=egress_after,
    )


def nearest_rank(values: Sequence[int], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(int(value) for value in values)
    index = max(math.ceil(min(max(float(quantile), 0.0), 1.0) * len(ordered)) - 1, 0)
    return float(ordered[index])


def summarize_candidate_samples(
    samples: Sequence[Mapping[str, Any]], *, qualified_delay_ms: int = QUALIFIED_DELAY_MS
) -> dict[str, Any]:
    if len(samples) != TOTAL_ROUNDS:
        raise MeasurementError("candidate must have exactly 20 samples")
    if qualified_delay_ms != QUALIFIED_DELAY_MS:
        raise MeasurementError("candidate summary qualified delay policy mismatch")
    ordered = sorted(
        (_validate_terminal_sample(sample) for sample in samples),
        key=lambda item: int(item["round"]),
    )
    candidate_ids = {str(item["candidate_id"]) for item in ordered}
    if len(candidate_ids) != 1 or [int(item["round"]) for item in ordered] != list(range(1, TOTAL_ROUNDS + 1)):
        raise MeasurementError("candidate samples are incomplete or mixed")
    delays = [int(item["delay_ms"]) for item in ordered if item.get("delay_ms") is not None]
    within = [delay for delay in delays if delay <= qualified_delay_ms]
    slow = [delay for delay in delays if delay > qualified_delay_ms]
    error_counts = {category: 0 for category in ERROR_CATEGORIES}
    for item in ordered:
        if item["delay_ms"] is None:
            error_counts[str(item["error_category"])] += 1
    flags = [item.get("delay_ms") is not None and int(item["delay_ms"]) <= qualified_delay_ms for item in ordered]
    median = float(statistics.median(delays)) if delays else None
    jitter = float(statistics.pstdev(delays)) if len(delays) > 1 else (0.0 if delays else None)
    span = float(ordered[-1]["started_at"]) - float(ordered[0]["started_at"])
    return {
        "candidate_id": next(iter(candidate_ids)),
        "attempt_count": TOTAL_ROUNDS,
        "response_count": len(delays),
        "within_1000_count": len(within),
        "slow_response_count": len(slow),
        "no_result_count": TOTAL_ROUNDS - len(delays),
        "min_delay_ms": min(delays) if delays else None,
        "median_delay_ms": round(median, 2) if median is not None else None,
        "p90_delay_ms": nearest_rank(delays, 0.90),
        "max_delay_ms": max(delays) if delays else None,
        "jitter_ms": round(jitter, 2) if jitter is not None else None,
        "first_half_within_1000_count": sum(flags[:10]),
        "second_half_within_1000_count": sum(flags[10:]),
        "five_round_within_1000_counts": [sum(flags[index : index + 5]) for index in range(0, 20, 5)],
        "observation_span_seconds": round(span, 6),
        "error_counts": error_counts,
    }


def summarize_control(samples: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    if len(samples) != TOTAL_ROUNDS:
        raise MeasurementError("control must contain exactly 20 samples")
    ordered: list[dict[str, Any]] = []
    for item in samples:
        if not isinstance(item, Mapping) or frozenset(item) != CONTROL_SAMPLE_FIELDS:
            raise MeasurementError("control sample fields are incomplete or unexpected")
        value = dict(item)
        round_number = value["round"]
        if isinstance(round_number, bool) or not isinstance(round_number, int):
            raise MeasurementError("control sample round is invalid")
        delay = value["delay_ms"]
        category = value["error_category"]
        if delay is None:
            if category not in ERROR_CATEGORIES:
                raise MeasurementError("control sample error category is invalid")
        elif isinstance(delay, bool) or not isinstance(delay, int) or delay <= 0 or category is not None:
            raise MeasurementError("responsive control sample is invalid")
        ordered.append(value)
    ordered.sort(key=lambda item: int(item["round"]))
    if [int(item["round"]) for item in ordered] != list(range(1, TOTAL_ROUNDS + 1)):
        raise MeasurementError("control samples must cover rounds 1 through 20 exactly once")
    success_flags = [item.get("delay_ms") is not None for item in ordered]
    longest = current = 0
    for succeeded in success_flags:
        current = 0 if succeeded else current + 1
        longest = max(longest, current)
    delays = [int(item["delay_ms"]) for item in ordered if item.get("delay_ms") is not None]
    return {
        "attempt_count": TOTAL_ROUNDS,
        "success_count": len(delays),
        "failure_count": TOTAL_ROUNDS - len(delays),
        "max_consecutive_failures": longest,
        "median_delay_ms": float(statistics.median(delays)) if delays else None,
    }


def summarize_canaries(samples: Sequence[Mapping[str, Any]], canary_ids: Sequence[str]) -> list[dict[str, Any]]:
    normalized_ids = [str(value).strip() for value in canary_ids]
    if (
        not normalized_ids
        or any(not value for value in normalized_ids)
        or len(normalized_ids) != len(set(normalized_ids))
    ):
        raise MeasurementError("canary IDs must be unique and non-empty")
    normalized_samples: list[dict[str, Any]] = []
    for item in samples:
        if not isinstance(item, Mapping) or frozenset(item) != CANARY_SAMPLE_FIELDS:
            raise MeasurementError("canary sample fields are incomplete or unexpected")
        canary_id = str(item["canary_id"]).strip()
        if canary_id not in normalized_ids:
            raise MeasurementError("canary sample belongs to an unknown canary")
        normalized_samples.append(dict(item))
    output: list[dict[str, Any]] = []
    for canary_id in normalized_ids:
        selected = [
            {key: value for key, value in item.items() if key != "canary_id"}
            for item in normalized_samples
            if str(item["canary_id"]) == canary_id
        ]
        summary = summarize_control(selected)
        output.append({"canary_id": canary_id, **summary})
    return output


def canonical_json_sha256(value: Any) -> str:
    return _sha256_json(value)


def build_private_fragment(
    manifest: Mapping[str, Any],
    *,
    shard_index: int,
    shard_candidates: Sequence[Any],
    scheduled: ScheduledRun,
) -> dict[str, Any]:
    """Build the credential-bearing shard artifact; never publish this mapping."""

    normalized_manifest = validate_manifest_v3(manifest)
    if shard_index not in range(SHARD_COUNT):
        raise MeasurementError("private fragment shard_index is invalid")
    normalized = [normalize_candidate(candidate) for candidate in shard_candidates]
    expected = normalized_manifest["shards"][shard_index]
    ids = [item["candidate_id"] for item in normalized]
    if len(ids) != expected["candidate_count"] or candidate_ids_sha256(ids) != expected["candidate_ids_sha256"]:
        raise MeasurementError("private fragment candidate binding mismatch")
    grouped: dict[str, list[dict[str, Any]]] = {candidate_id: [] for candidate_id in ids}
    for sample in scheduled.samples:
        candidate_id_value = validate_public_id(sample.get("candidate_id"), "candidate")
        if candidate_id_value not in grouped:
            raise MeasurementError("scheduled sample belongs to another shard")
        grouped[candidate_id_value].append(dict(sample))
    expected_trends = _expected_round_trends(
        scheduled.samples, candidate_count=len(normalized)
    )
    if [dict(item) for item in scheduled.round_trends] != expected_trends:
        raise MeasurementError("scheduled round trends do not match terminal samples")
    results = []
    by_id = {item["candidate_id"]: item for item in normalized}
    for candidate_id_value in ids:
        samples = sorted(grouped[candidate_id_value], key=lambda item: int(item["round"]))
        results.append(
            {
                "candidate_id": candidate_id_value,
                "proxy": copy.deepcopy(by_id[candidate_id_value]["proxy"]),
                "samples": samples,
                "summary": summarize_candidate_samples(samples),
            }
        )
    return {
        "kind": PRIVATE_FRAGMENT_KIND,
        "schema_version": PRIVATE_FRAGMENT_SCHEMA_VERSION,
        "manifest_sha256": canonical_json_sha256(normalized_manifest),
        "run_id": normalized_manifest["run_id"],
        "source_sha256": normalized_manifest["source_sha256"],
        "main_sha": normalized_manifest["main_sha"],
        "profile_sha256": normalized_manifest["profile_sha256"],
        "candidate_metadata_sha256": normalized_manifest["candidate_metadata_sha256"],
        "candidate_metadata_schema_version": normalized_manifest[
            "candidate_metadata_schema_version"
        ],
        "candidate_metadata_count": normalized_manifest["candidate_metadata_count"],
        "identity_key_version": normalized_manifest["identity_key_version"],
        "identity_epoch": normalized_manifest["identity_epoch"],
        "request_timeout_ms": normalized_manifest["request_timeout_ms"],
        "qualified_delay_ms": normalized_manifest["qualified_delay_ms"],
        "total_rounds": normalized_manifest["total_rounds"],
        "minimum_observation_window_seconds": normalized_manifest[
            "minimum_observation_window_seconds"
        ],
        "shard_count": normalized_manifest["shard_count"],
        "workers_per_shard": normalized_manifest["workers_per_shard"],
        "stagger_seconds": expected["stagger_seconds"],
        "controller_port": expected["controller_port"],
        "mixed_port": expected["mixed_port"],
        "runtime_subdir": expected["runtime_subdir"],
        "private_fragment_file": expected["private_fragment_file"],
        "controller_secret_sha256": expected["controller_secret_sha256"],
        "validity_policy_version": normalized_manifest["validity_policy_version"],
        "scheduler_policy_version": normalized_manifest["scheduler_policy_version"],
        "canary_policy_version": normalized_manifest["canary_policy_version"],
        "canary_set_sha256": normalized_manifest["canary_set_sha256"],
        "python_version": normalized_manifest["python_version"],
        "pyyaml_version": normalized_manifest["pyyaml_version"],
        "mihomo_version": normalized_manifest["mihomo_version"],
        "mihomo_sha256": normalized_manifest["mihomo_sha256"],
        "resolver_policy_version": normalized_manifest["resolver_policy_version"],
        "network_guard_policy_version": normalized_manifest[
            "network_guard_policy_version"
        ],
        "shard_index": shard_index,
        "candidate_count": len(normalized),
        "candidate_ids_sha256": candidate_ids_sha256(ids),
        "results": results,
        "round_trends": [copy.deepcopy(item) for item in scheduled.round_trends],
        "controller_checks": [copy.deepcopy(item) for item in scheduled.controller_checks],
        "control_samples": [copy.deepcopy(item) for item in scheduled.control_samples],
        "canary_samples": [copy.deepcopy(item) for item in scheduled.canary_samples],
        "egress": {
            "before": copy.deepcopy(scheduled.egress_before),
            "after": copy.deepcopy(scheduled.egress_after),
        },
    }


def build_redacted_fragment(
    manifest: Mapping[str, Any],
    private_fragment: Mapping[str, Any],
    *,
    exit_id_resolver: Callable[[str], str],
) -> dict[str, Any]:
    """Project a private shard through an injected C3 ``exit_id`` stage."""

    normalized_manifest = validate_manifest_v3(manifest)
    if not isinstance(private_fragment, Mapping) or frozenset(private_fragment) != PRIVATE_FRAGMENT_FIELDS:
        raise MeasurementError("private fragment fields are incomplete or unexpected")
    private = dict(private_fragment)
    if private["kind"] != PRIVATE_FRAGMENT_KIND or private["schema_version"] != PRIVATE_FRAGMENT_SCHEMA_VERSION:
        raise MeasurementError("unsupported private fragment")
    if private["manifest_sha256"] != canonical_json_sha256(normalized_manifest):
        raise MeasurementError("private fragment manifest hash mismatch")
    for field in (
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
    ):
        if private[field] != normalized_manifest[field]:
            raise MeasurementError(f"private fragment {field} mismatch")
    shard_index = private["shard_index"]
    if isinstance(shard_index, bool) or not isinstance(shard_index, int) or shard_index not in range(SHARD_COUNT):
        raise MeasurementError("private fragment shard index is invalid")
    expected_shard = normalized_manifest["shards"][shard_index]
    if private["stagger_seconds"] != expected_shard["stagger_seconds"]:
        raise MeasurementError("private fragment shard stagger mismatch")
    for field in (
        "controller_port",
        "mixed_port",
        "runtime_subdir",
        "private_fragment_file",
        "controller_secret_sha256",
    ):
        if private[field] != expected_shard[field]:
            raise MeasurementError(f"private fragment shard {field} mismatch")
    if (
        private["candidate_count"] != expected_shard["candidate_count"]
        or private["candidate_ids_sha256"] != expected_shard["candidate_ids_sha256"]
    ):
        raise MeasurementError("private fragment candidate binding mismatch")
    controller_checks = [dict(item) for item in private["controller_checks"]]
    if len(controller_checks) != TOTAL_ROUNDS * 2:
        raise MeasurementError("controller health evidence is incomplete")
    expected_checks = {
        (phase, round_number)
        for round_number in range(1, TOTAL_ROUNDS + 1)
        for phase in ("before", "after")
    }
    observed_checks: set[tuple[str, int]] = set()
    for item in controller_checks:
        phase = item.get("phase")
        round_number = item.get("round")
        if (
            phase not in {"before", "after"}
            or isinstance(round_number, bool)
            or not isinstance(round_number, int)
            or not isinstance(item.get("healthy"), bool)
        ):
            raise MeasurementError("controller health evidence is malformed")
        observed_checks.add((str(phase), round_number))
    if observed_checks != expected_checks:
        raise MeasurementError("controller health evidence does not cover every round")
    versions = {str(item.get("version") or "") for item in controller_checks}
    if versions != {normalized_manifest["mihomo_version"]}:
        raise MeasurementError("controller version evidence is incomplete or inconsistent")
    unhealthy_count = sum(not bool(item.get("healthy")) for item in controller_checks)
    canary_ids = sorted({str(item.get("canary_id")) for item in private["canary_samples"]})
    if not canary_ids or "" in canary_ids:
        raise MeasurementError("private fragment canary evidence is incomplete")
    if _sha256_json(canary_ids) != normalized_manifest["canary_set_sha256"]:
        raise MeasurementError("private fragment canary set hash mismatch")

    def redact_egress(point: Mapping[str, Any]) -> dict[str, str]:
        required = {"public_ip", "country", "region", "org"}
        if not isinstance(point, Mapping) or set(point) != required:
            raise MeasurementError("private egress handoff is incomplete or unexpected")
        public_ip = str(point["public_ip"])
        try:
            opaque_exit_id = exit_id_resolver(public_ip)
        except Exception:
            raise MeasurementError("egress identity projection failed") from None
        return {
            "country": str(point["country"]),
            "region": str(point["region"]),
            "org": str(point["org"]),
            "exit_id": validate_public_id(opaque_exit_id, "exit"),
        }

    redacted = {
        "kind": REDACTED_FRAGMENT_KIND,
        "schema_version": REDACTED_FRAGMENT_SCHEMA_VERSION,
        "manifest_sha256": private["manifest_sha256"],
        "run_id": private["run_id"],
        "source_sha256": private["source_sha256"],
        "main_sha": private["main_sha"],
        "profile_sha256": private["profile_sha256"],
        "candidate_metadata_sha256": private["candidate_metadata_sha256"],
        "candidate_metadata_schema_version": private[
            "candidate_metadata_schema_version"
        ],
        "candidate_metadata_count": private["candidate_metadata_count"],
        "identity_key_version": private["identity_key_version"],
        "identity_epoch": private["identity_epoch"],
        "request_timeout_ms": private["request_timeout_ms"],
        "qualified_delay_ms": private["qualified_delay_ms"],
        "total_rounds": private["total_rounds"],
        "minimum_observation_window_seconds": private[
            "minimum_observation_window_seconds"
        ],
        "shard_count": private["shard_count"],
        "workers_per_shard": private["workers_per_shard"],
        "stagger_seconds": private["stagger_seconds"],
        "validity_policy_version": private["validity_policy_version"],
        "scheduler_policy_version": private["scheduler_policy_version"],
        "canary_policy_version": private["canary_policy_version"],
        "canary_set_sha256": private["canary_set_sha256"],
        "python_version": private["python_version"],
        "pyyaml_version": private["pyyaml_version"],
        "mihomo_version": private["mihomo_version"],
        "mihomo_sha256": private["mihomo_sha256"],
        "resolver_policy_version": private["resolver_policy_version"],
        "network_guard_policy_version": private["network_guard_policy_version"],
        "shard_index": private["shard_index"],
        "candidate_count": private["candidate_count"],
        "candidate_ids_sha256": private["candidate_ids_sha256"],
        "results": [copy.deepcopy(item["summary"]) for item in private["results"]],
        "round_trends": [copy.deepcopy(item) for item in private["round_trends"]],
        "controller": {
            "healthy_check_count": len(controller_checks),
            "unhealthy_count": unhealthy_count,
            "version": next(iter(versions)),
            "mihomo_sha256": private["mihomo_sha256"],
        },
        "control": summarize_control(private["control_samples"]),
        "canaries": summarize_canaries(private["canary_samples"], canary_ids),
        "egress": {
            "before": redact_egress(private["egress"]["before"]),
            "after": redact_egress(private["egress"]["after"]),
        },
    }
    from scripts.gmgn_validity import validate_redacted_fragment

    validate_redacted_fragment(normalized_manifest, redacted)
    return redacted


def write_private_fragment(
    path: str | Path, payload: Mapping[str, Any], *, private_root: str | Path
) -> None:
    """Atomically write a private fragment inside ``.cnb-runtime`` with 0600."""

    target = Path(path).resolve()
    root = Path(private_root).resolve()
    parts = {part.lower() for part in root.parts}
    if ".cnb-runtime" not in parts or any(part == ".git" or part.startswith("public-cn") for part in parts):
        raise MeasurementError("private root must be an isolated .cnb-runtime directory")
    try:
        relative = target.relative_to(root)
    except ValueError as exc:
        raise MeasurementError("private fragment path escapes private root") from exc
    if not relative.parts:
        raise MeasurementError("private fragment path must name a file")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.{secrets.token_hex(8)}.tmp")
    content = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.chmod(0o600)
        temporary.replace(target)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def validate_benchmark_evidence(item: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(item, Mapping) or frozenset(item) != BENCHMARK_EVIDENCE_FIELDS:
        raise MeasurementError("benchmark evidence fields are incomplete or unexpected")
    value = dict(item)
    if not re.fullmatch(r"gmgnv2_[A-Za-z0-9._-]{8,96}", str(value["run_id"])):
        raise MeasurementError("benchmark run_id is malformed")
    workers = value["workers"]
    if isinstance(workers, bool) or not isinstance(workers, int) or workers not in ALLOWED_WORKER_COUNTS:
        raise MeasurementError("benchmark workers value is invalid")
    if not isinstance(value["valid_run"], bool) or not isinstance(value["control_canary_passed"], bool):
        raise MeasurementError("benchmark boolean evidence is invalid")
    _hex(value["cohort_sha256"], 64, "benchmark cohort_sha256")
    _hex(value["runtime_sha256"], 64, "benchmark runtime_sha256")
    for field in ("wall_seconds", "throughput_attempts_per_second"):
        metric = value[field]
        if isinstance(metric, bool) or not isinstance(metric, (int, float)) or not math.isfinite(float(metric)) or float(metric) <= 0:
            raise MeasurementError(f"benchmark {field} must be positive and finite")
    for field in (
        "candidate_no_result_rate",
        "target_403_429_rate",
        "controller_request_rate",
        "shard_duration_skew",
    ):
        metric = value[field]
        if isinstance(metric, bool) or not isinstance(metric, (int, float)) or not math.isfinite(float(metric)) or not 0 <= float(metric) <= 1:
            raise MeasurementError(f"benchmark {field} must be a finite ratio")
    unhealthy = value["controller_unhealthy_count"]
    memory = value["memory_bytes_peak"]
    if isinstance(unhealthy, bool) or not isinstance(unhealthy, int) or unhealthy < 0:
        raise MeasurementError("benchmark controller_unhealthy_count is invalid")
    if isinstance(memory, bool) or not isinstance(memory, int) or memory < 0:
        raise MeasurementError("benchmark memory_bytes_peak is invalid")
    cpu = value["cpu_percent_peak"]
    if isinstance(cpu, bool) or not isinstance(cpu, (int, float)) or not math.isfinite(float(cpu)) or float(cpu) < 0:
        raise MeasurementError("benchmark cpu_percent_peak is invalid")
    return value


def benchmark_recommendation(evidence: Sequence[Mapping[str, Any]]) -> str:
    """Return a policy recommendation without changing the default workers."""

    grouped: dict[int, list[Mapping[str, Any]]] = {}
    seen_run_ids: set[str] = set()
    for item in evidence:
        normalized = validate_benchmark_evidence(item)
        if not normalized["valid_run"]:
            continue
        run_id = str(normalized["run_id"])
        if run_id in seen_run_ids:
            raise MeasurementError("benchmark evidence contains a duplicate run_id")
        seen_run_ids.add(run_id)
        grouped.setdefault(int(normalized["workers"]), []).append(normalized)
    if any(len(grouped.get(workers, [])) < 2 for workers in (8, 16, 24, 32)):
        raise MeasurementError("benchmark requires at least two valid runs for 8/16/24/32 workers")
    cohorts = {str(item.get("cohort_sha256")) for values in grouped.values() for item in values}
    runtimes = {str(item.get("runtime_sha256")) for values in grouped.values() for item in values}
    if len(cohorts) != 1 or len(runtimes) != 1:
        raise MeasurementError("benchmark cohort/runtime mismatch")

    def p50(workers: int, field: str) -> float:
        return float(statistics.median(float(item[field]) for item in grouped[workers]))

    baseline_wall = p50(16, "wall_seconds")
    if any(
        int(item["controller_unhealthy_count"]) != 0
        or not bool(item["control_canary_passed"])
        for item in grouped[16]
    ):
        raise MeasurementError("benchmark baseline control evidence is invalid")
    eligible: list[tuple[float, int]] = []
    for workers in (8, 24, 32):
        wall = p50(workers, "wall_seconds")
        improvement = (baseline_wall - wall) / baseline_wall
        no_result_delta = p50(workers, "candidate_no_result_rate") - p50(16, "candidate_no_result_rate")
        controller_delta = p50(workers, "controller_request_rate") - p50(16, "controller_request_rate")
        unhealthy = any(int(item.get("controller_unhealthy_count", 0)) for item in grouped[workers])
        controls_ok = all(bool(item.get("control_canary_passed")) for item in grouped[workers])
        skew_ok = all(float(item.get("shard_duration_skew", 1.0)) <= 0.10 for item in grouped[workers])
        if (
            improvement >= 0.10 - 1e-12
            and no_result_delta <= 0.02 + 1e-12
            and controller_delta <= 0.005 + 1e-12
            and not unhealthy
            and controls_ok
            and skew_ok
        ):
            eligible.append((wall, workers))
    if eligible:
        _wall, workers = min(eligible)
        return f"eligible_for_policy_change:{workers}"
    return "keep_16"


__all__ = [
    "CANARY_POLICY_VERSION",
    "BENCHMARK_EVIDENCE_FIELDS",
    "DEFAULT_WORKERS",
    "ERROR_CATEGORIES",
    "MANIFEST_SCHEMA_VERSION",
    "MINIMUM_OBSERVATION_WINDOW_SECONDS",
    "MeasurementError",
    "QUALIFIED_DELAY_MS",
    "REQUEST_TIMEOUT_MS",
    "SHARD_COUNT",
    "SHARD_STAGGER_SECONDS",
    "ScheduledRun",
    "TOTAL_ROUNDS",
    "VALIDITY_POLICY_VERSION",
    "benchmark_recommendation",
    "build_private_fragment",
    "build_redacted_fragment",
    "build_manifest_v3",
    "candidate_ids_sha256",
    "canonical_json_sha256",
    "classify_error",
    "normalize_candidate",
    "normalize_outcome",
    "partition_candidates",
    "run_measurement_schedule",
    "summarize_canaries",
    "summarize_candidate_samples",
    "summarize_control",
    "validate_manifest_v3",
    "validate_benchmark_evidence",
    "write_private_fragment",
]
