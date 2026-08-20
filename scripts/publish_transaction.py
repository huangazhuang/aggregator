#!/usr/bin/env python3
"""Build and transactionally publish a branch-neutral GMGN V2 bundle.

This module owns only the publication boundary.  Candidate identity,
measurement validity, history reduction, region resolution, and selection are
validated by their respective owner modules before a bundle reaches here.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

from scripts.gmgn_history import (
    HISTORY_POLICY_VERSION,
    HISTORY_SCHEMA_VERSION,
    validate_history,
)
from scripts.gmgn_measurement import (
    ERROR_CATEGORIES,
    MINIMUM_OBSERVATION_WINDOW_SECONDS,
    SHARD_COUNT,
    TOTAL_ROUNDS,
    VALIDITY_POLICY_VERSION,
)
from scripts.gmgn_selection import (
    DESIRED_CAPACITY,
    MAX_NODES,
    NODE_STATUS_KIND,
    NODE_STATUS_SCHEMA_VERSION,
    REGION_POLICY_VERSION,
    SELECTION_POLICY_VERSION,
    SELECTION_RESULT_KIND,
    SELECTION_RESULT_SCHEMA_VERSION,
    V2_GROUP_NAMES,
    public_selection_status,
    render_selection_profile,
)
from scripts.gmgn_validity import contains_ip_literal
from scripts.proxy_identity import validate_identity_version, validate_public_id


BUNDLE_KIND = "cnb-gmgn-publish-bundle"
BUNDLE_SCHEMA_VERSION = 1
PUBLISH_STATUS_KIND = "cnb-gmgn-v2-publish-status"
PUBLISH_STATUS_SCHEMA_VERSION = 1
RUN_INDEX_KIND = "cnb-gmgn-run-index"
RUN_INDEX_SCHEMA_VERSION = 1
RUN_DIAGNOSTICS_KIND = "cnb-gmgn-run-diagnostics"
RUN_DIAGNOSTICS_SCHEMA_VERSION = 1
PUBLISH_POLICY_VERSION = "gmgn-publication-v6"
SUPPORTED_PUBLICATION_POLICY_TRIPLES = frozenset(
    {
        ("gmgn-publication-v1", "gmgn-validity-v5", "gmgn-region-v1"),
        ("gmgn-publication-v2", "gmgn-validity-v6", "gmgn-region-v1"),
        ("gmgn-publication-v3", "gmgn-validity-v7", "gmgn-region-v1"),
        ("gmgn-publication-v4", "gmgn-validity-v8", "gmgn-region-v1"),
        ("gmgn-publication-v5", "gmgn-validity-v8", "gmgn-region-v2"),
        (PUBLISH_POLICY_VERSION, VALIDITY_POLICY_VERSION, REGION_POLICY_VERSION),
    }
)
SUPPORTED_PUBLISH_POLICY_VERSIONS = frozenset(
    item[0] for item in SUPPORTED_PUBLICATION_POLICY_TRIPLES
)
PUBLIC_ALLOWLIST_VERSION = "gmgn-public-allowlist-v1"
AUTHORITATIVE_BRANCH = "clash-cn-gmgn-v2-shadow"
STAGING_BRANCH_PREFIX = "clash-cn-gmgn-v2-staging"
RECENT_RUN_LIMIT = 5

# Capacity is deliberately a soft target.  A valid run may publish fewer than
# ``DESIRED_CAPACITY`` nodes, but an empty result must never replace the last
# good bundle.  The retention floor only protects an already published bundle
# from an accidental/partial result; it is not a quality target or a request to
# pad the output with slow nodes.
PUBLICATION_MIN_COUNT = 1
PUBLICATION_MIN_RETAIN_RATIO = 0.40

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
ABSOLUTE_URL_RE = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
WINDOWS_ABSOLUTE_PATH_RE = re.compile(r"^[A-Za-z]:[\\/]")

BRANCH_NEUTRAL_FORBIDDEN_KEYS = frozenset(
    {
        "branch",
        "channel",
        "mode",
        "profile_url",
        "subscription_url",
        "promotion_time",
        "promoted_at",
    }
)
PUBLIC_SENSITIVE_KEYS = frozenset(
    {
        "fingerprint",
        "proxy",
        "server",
        "port",
        "uuid",
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "source_url",
        "subscription",
        "exit_ip",
        "public_ip",
        "runner_ip",
        "raw_error",
        "private_path",
        "work_dir",
    }
)

BUNDLE_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "bundle_hash",
        "public_allowlist_version",
        "run_id",
        "attempt_id",
        "retry_of",
        "accepted_at",
        "source_run_at",
        "source_sha256",
        "main_sha",
        "identity_key_version",
        "identity_epoch",
        "files",
    }
)
BUNDLE_FILE_FIELDS = frozenset(
    {"path", "sha256", "size", "kind", "schema_version"}
)
STATUS_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "bundle_hash",
        "public_allowlist_version",
        "publish_policy_version",
        "run_id",
        "attempt_id",
        "retry_of",
        "accepted_at",
        "source_run_at",
        "source_sha256",
        "main_sha",
        "source_profile_sha256",
        "candidate_metadata_sha256",
        "output_profile_sha256",
        "identity_key_version",
        "identity_epoch",
        "selection_policy_version",
        "region_policy_version",
        "history_policy_version",
        "validity_policy_version",
        "published_count",
        "source_candidate_count",
        "stable_capacity_count",
        "desired_capacity",
        "desired_capacity_reached",
        "max_nodes",
        "tier_counts",
        "region_counts",
        "total_rounds",
        "shard_count",
        "minimum_observation_window_seconds",
        "runtime",
        "diagnostics_path",
        "history_schema_version",
        "node_status_schema_version",
        "run_index_schema_version",
        "selection_summary",
    }
)
RUNTIME_FIELDS = frozenset(
    {"python_version", "pyyaml_version", "mihomo_version", "mihomo_sha256"}
)
RUN_INDEX_FIELDS = frozenset(
    {"kind", "schema_version", "bundle_hash", "current_run_id", "entries"}
)
RUN_INDEX_ENTRY_FIELDS = frozenset(
    {
        "run_id",
        "attempt_id",
        "retry_of",
        "source_sha256",
        "accepted_at",
        "source_run_at",
        "diagnostics_sha256",
        "output_profile_sha256",
    }
)
DIAGNOSTICS_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "bundle_hash",
        "run_id",
        "attempt_id",
        "retry_of",
        "accepted_at",
        "source_run_at",
        "source_sha256",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "identity_key_version",
        "identity_epoch",
        "selection_policy_version",
        "region_policy_version",
        "validity_policy_version",
        "total_rounds",
        "shard_count",
        "minimum_observation_window_seconds",
        "valid_run",
        "validity_reasons",
        "metrics",
        "shards",
    }
)
NODE_STATUS_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "bundle_hash",
        "run_id",
        "source_sha256",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "identity_key_version",
        "identity_epoch",
        "selection_policy_version",
        "region_policy_version",
        "summary",
        "nodes",
    }
)
NODE_STATUS_ENTRY_FIELDS = frozenset(
    {
        "candidate_id",
        "output_name",
        "tier",
        "eligible_tier",
        "reason",
        "selected",
        "priority_selected",
        "auto_selected",
        "country_code",
        "region_confidence",
        "region_stale",
        "within_1000_count",
        "under_1000_count",
        "response_count",
        "slow_response_count",
        "over_1000_count",
        "no_result_count",
        "timeout_count",
        "error_counts",
        "first_half_within_1000_count",
        "second_half_within_1000_count",
        "median_delay_ms",
        "p90_delay_ms",
        "jitter_ms",
        "history_transition",
        "concentration_flags",
    }
)
SELECTION_SUMMARY_FIELDS = frozenset(
    {
        "source_candidate_count",
        "published_count",
        "stable_capacity_count",
        "desired_capacity",
        "desired_capacity_reached",
        "max_nodes",
        "asia_core_count",
        "asia_flexible_count",
        "asia_manual_candidate_count",
        "history_protected_count",
        "non_asia_stable_count",
        "unknown_region_count",
        "region_counts",
        "capacity_trimmed_count",
        "diversity_trimmed_count",
        "diversity_limits",
    }
)
TIER_COUNT_FIELDS = frozenset(
    {
        "asia_core",
        "asia_flexible",
        "asia_manual_candidate",
        "history_protected",
        "non_asia_stable",
    }
)
REGION_COUNT_FIELDS = frozenset({"HK", "JP", "KR", "SG", "TW"})
DIVERSITY_LIMIT_FIELDS = frozenset(
    {"exit_id_cap", "server_id_cap", "asn_id_cap", "source_id_cap"}
)
DIAGNOSTIC_SHARD_FIELDS = frozenset(
    {
        "shard_index",
        "candidate_count",
        "controller_healthy_check_count",
        "controller_unhealthy_count",
        "egress_country",
        "egress_region",
        "canary_count",
    }
)


class PublicationError(ValueError):
    """The publication input or public bundle violates the V2 contract."""


class PreviousStateError(PublicationError):
    """The authoritative previous state cannot be safely established."""


class PublicationTransactionError(RuntimeError):
    """A remote staging, promotion, smoke, or rollback step failed."""


@dataclass(frozen=True)
class PublishBundle:
    files: dict[str, bytes]
    bundle_hash: str
    run_id: str
    attempt_id: str
    retry_of: str | None
    source_sha256: str
    accepted_at: str
    source_run_at: str


@dataclass(frozen=True)
class PreviousState:
    exists: bool
    observed_tip: str | None
    bundle: PublishBundle | None


@dataclass(frozen=True)
class TransactionResult:
    commit: str
    staging_ref: str
    authoritative_ref: str
    previous_tip: str | None
    bundle_hash: str


def _strict_mapping(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != fields:
        raise PublicationError(f"{label} fields are incomplete or unexpected")
    return copy.deepcopy(dict(value))


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise PublicationError(f"{label} must be a canonical SHA-256")
    return value


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GIT_SHA_RE.fullmatch(value):
        raise PreviousStateError(f"{label} must be a canonical Git object ID")
    return value


def _attempt_id(value: Any, label: str) -> str:
    text = str(value or "").lower()
    if not re.fullmatch(r"[0-9a-f]{24}", text):
        raise PublicationError(f"{label} is malformed")
    return text


def _retry_of(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _attempt_id(value, label)


def _non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PublicationError(f"{label} must be a non-negative integer")
    return value


def validate_publication_capacity(
    published_count: Any,
    previous_published_count: Any = 0,
    *,
    desired_capacity: int = DESIRED_CAPACITY,
    max_nodes: int = MAX_NODES,
    minimum_count: int = PUBLICATION_MIN_COUNT,
    retain_ratio: float = PUBLICATION_MIN_RETAIN_RATIO,
) -> dict[str, Any]:
    """Validate the soft-capacity publication policy.

    ``desired_capacity`` is informational: it describes the preferred size,
    not a lower bound.  The only unconditional lower bound is one usable
    proxy.  When a previous bundle exists, a modest retention floor protects
    against an accidentally partial result while still allowing a substantial
    quality-driven reduction.
    """

    count = _non_negative_int(published_count, "published_count")
    previous = _non_negative_int(previous_published_count, "previous_published_count")
    desired = _non_negative_int(desired_capacity, "desired_capacity")
    maximum = _non_negative_int(max_nodes, "max_nodes")
    minimum = _non_negative_int(minimum_count, "minimum_count")
    if (
        maximum < 1
        or desired < 1
        or desired > maximum
        or minimum < 1
        or minimum > maximum
    ):
        raise PublicationError("publication capacity bounds are invalid")
    if not isinstance(retain_ratio, (int, float)) or isinstance(retain_ratio, bool):
        raise PublicationError("publication retain ratio is invalid")
    ratio = float(retain_ratio)
    if ratio < 0 or ratio > 1 or not math.isfinite(ratio):
        raise PublicationError("publication retain ratio is invalid")
    if count > maximum:
        raise PublicationError(
            f"publication contains {count} nodes; the hard cap is {maximum}"
        )
    previous_baseline = min(previous, desired)
    required = minimum
    if previous > 0:
        required = max(required, math.ceil(previous_baseline * ratio))
    if count < required:
        if count == 0:
            raise PublicationError(
                "publication produced no usable nodes (all candidates may be "
                "unknown, unreachable, or unverified); refusing to replace "
                "the last-good profile"
            )
        raise PublicationError(
            f"publication shrank to {count} nodes; at least {required} are "
            "required by the last-good retention floor; refusing to replace "
            "the last-good profile"
        )
    return {
        "published_count": count,
        "previous_published_count": previous,
        "previous_publish_baseline": previous_baseline,
        "minimum_required": required,
        "desired_capacity": desired,
        "desired_capacity_reached": count >= desired,
        "max_nodes": maximum,
        "retain_ratio": ratio,
    }


def validate_selection_publication(
    summary: Mapping[str, Any],
    previous_published_count: Any = 0,
) -> dict[str, Any]:
    """Apply the publication gate to a normalized V2 selection summary."""

    value = _validate_selection_summary(summary)
    source_count = value["source_candidate_count"]
    if source_count < 1:
        raise PublicationError(
            "publication has no source candidates; refusing to replace the "
            "last-good profile"
        )
    if value["unknown_region_count"] >= source_count:
        raise PublicationError(
            "publication classified every candidate region as unknown; "
            "refusing to replace the last-good profile"
        )
    return validate_publication_capacity(
        value["published_count"],
        previous_published_count,
        desired_capacity=value["desired_capacity"],
        max_nodes=value["max_nodes"],
    )


def _positive_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PublicationError(f"{label} must be a positive number")
    normalized = float(value)
    if normalized <= 0 or normalized == float("inf") or normalized != normalized:
        raise PublicationError(f"{label} must be a positive finite number")
    return normalized


def _optional_non_negative_number(value: Any, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PublicationError(f"{label} must be null or a non-negative number")
    normalized = float(value)
    if normalized < 0 or normalized == float("inf") or normalized != normalized:
        raise PublicationError(f"{label} must be null or a finite non-negative number")
    return normalized


def _timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PublicationError(f"{label} must be canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PublicationError(f"{label} must be canonical UTC") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise PublicationError(f"{label} must be canonical UTC")
    canonical = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise PublicationError(f"{label} must be canonical UTC")
    return value


def _parsed_timestamp(value: Any, label: str) -> datetime:
    return datetime.fromisoformat(_timestamp(value, label).replace("Z", "+00:00"))


def _canonical_json_bytes(value: Mapping[str, Any], *, strip_bundle_hash: bool) -> bytes:
    normalized = copy.deepcopy(dict(value))
    if strip_bundle_hash:
        normalized.pop("bundle_hash", None)
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PublicationError("public JSON payload is not canonicalizable") from exc


def public_json_bytes(value: Mapping[str, Any]) -> bytes:
    return _canonical_json_bytes(value, strip_bundle_hash=False) + b"\n"


def _load_json_bytes(content: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except Exception as exc:
        raise PublicationError(f"{label} is invalid UTF-8 JSON") from exc
    if not isinstance(value, Mapping):
        raise PublicationError(f"{label} must contain a JSON object")
    return dict(value)


def _safe_relative_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise PublicationError("bundle path is malformed")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise PublicationError("bundle path escapes the public root")
    return path.as_posix()


def _walk_json(value: Any, *, path: str = "$") -> Iterable[tuple[str, str | None, Any]]:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized_key = str(key)
            yield f"{path}.{normalized_key}", normalized_key, child
            yield from _walk_json(child, path=f"{path}.{normalized_key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_json(child, path=f"{path}[{index}]")


def validate_public_json_safety(value: Mapping[str, Any], *, label: str) -> None:
    for path, key, child in _walk_json(value):
        normalized_key = key.casefold() if key is not None else ""
        if normalized_key in BRANCH_NEUTRAL_FORBIDDEN_KEYS:
            raise PublicationError(f"{label} contains branch-specific field {path}")
        if normalized_key in PUBLIC_SENSITIVE_KEYS:
            raise PublicationError(f"{label} contains private field {path}")
        if isinstance(child, str):
            if ABSOLUTE_URL_RE.search(child):
                raise PublicationError(f"{label} contains an absolute URL at {path}")
            if WINDOWS_ABSOLUTE_PATH_RE.match(child) or child.startswith("/home/"):
                raise PublicationError(f"{label} contains a private path at {path}")


def _public_region(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PublicationError(f"{label} is missing")
    text = value.strip()
    if contains_ip_literal(text):
        raise PublicationError(f"{label} contains an IP address")
    return text


def compute_logical_bundle_hash(files: Mapping[str, bytes]) -> str:
    """Compute the frozen non-recursive logical bundle hash."""

    digest = hashlib.sha256()
    payload_paths = sorted(path for path in files if path != "bundle.json")
    if not payload_paths or "clash.yaml" not in payload_paths:
        raise PublicationError("bundle payload is incomplete")
    for raw_path in payload_paths:
        path = _safe_relative_path(raw_path)
        content = files[raw_path]
        if not isinstance(content, bytes):
            raise PublicationError("bundle payload values must be bytes")
        if path.endswith(".json"):
            normalized = _canonical_json_bytes(
                _load_json_bytes(content, path), strip_bundle_hash=True
            )
        elif path == "clash.yaml":
            normalized = content
        else:
            raise PublicationError(f"unsupported public payload path: {path}")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(normalized)
    return digest.hexdigest()


def _validate_runtime(raw: Any) -> dict[str, Any]:
    value = _strict_mapping(raw, RUNTIME_FIELDS, "runtime")
    for field in ("python_version", "pyyaml_version", "mihomo_version"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise PublicationError(f"runtime {field} is missing")
    value["mihomo_sha256"] = _sha256(value["mihomo_sha256"], "mihomo_sha256")
    return value


def _validate_selection_summary(raw: Any) -> dict[str, Any]:
    value = _strict_mapping(raw, SELECTION_SUMMARY_FIELDS, "selection summary")
    integer_fields = SELECTION_SUMMARY_FIELDS - {
        "desired_capacity_reached",
        "region_counts",
        "diversity_limits",
    }
    for field in integer_fields:
        value[field] = _non_negative_int(value[field], f"selection summary {field}")
    if not isinstance(value["desired_capacity_reached"], bool):
        raise PublicationError("selection summary desired capacity flag is malformed")
    regions = _strict_mapping(
        value["region_counts"], REGION_COUNT_FIELDS, "selection summary region counts"
    )
    for field in regions:
        regions[field] = _non_negative_int(regions[field], f"region count {field}")
    limits = _strict_mapping(
        value["diversity_limits"],
        DIVERSITY_LIMIT_FIELDS,
        "selection summary diversity limits",
    )
    for field in limits:
        limits[field] = _non_negative_int(limits[field], f"diversity limit {field}")
    value["region_counts"] = regions
    value["diversity_limits"] = limits
    if value["published_count"] > value["max_nodes"]:
        raise PublicationError("selection summary exceeds the publication cap")
    if value["stable_capacity_count"] > value["published_count"]:
        raise PublicationError("selection stable capacity exceeds published count")
    if value["desired_capacity_reached"] != (
        value["stable_capacity_count"] >= value["desired_capacity"]
    ):
        raise PublicationError("selection desired-capacity flag is inconsistent")
    if any(limit <= 0 for limit in limits.values()):
        raise PublicationError("selection diversity limits must be positive")
    return value


def _validate_node_status(
    raw: Any,
    *,
    expected_bundle_hash: str | None,
    accepted_region_policy_versions: frozenset[str] = frozenset(
        {REGION_POLICY_VERSION}
    ),
) -> dict[str, Any]:
    expected_fields = NODE_STATUS_FIELDS
    if expected_bundle_hash is None:
        expected_fields = NODE_STATUS_FIELDS - {"bundle_hash"}
    value = _strict_mapping(raw, expected_fields, "node-status")
    if (
        value["kind"] != NODE_STATUS_KIND
        or value["schema_version"] != NODE_STATUS_SCHEMA_VERSION
    ):
        raise PublicationError("node-status kind or schema is unsupported")
    if expected_bundle_hash is not None and value["bundle_hash"] != expected_bundle_hash:
        raise PublicationError("node-status bundle hash mismatch")
    if not isinstance(value["run_id"], str) or not RUN_ID_RE.fullmatch(value["run_id"]):
        raise PublicationError("node-status run_id is malformed")
    for field in ("source_sha256", "profile_sha256", "candidate_metadata_sha256"):
        value[field] = _sha256(value[field], f"node-status {field}")
    value["main_sha"] = _git_sha(value["main_sha"], "node-status main_sha")
    value["identity_key_version"] = validate_identity_version(
        value["identity_key_version"], "identity_key_version"
    )
    value["identity_epoch"] = validate_identity_version(
        value["identity_epoch"], "identity_epoch"
    )
    if value["selection_policy_version"] != SELECTION_POLICY_VERSION:
        raise PublicationError("node-status selection policy is unsupported")
    if value["region_policy_version"] not in accepted_region_policy_versions:
        raise PublicationError("node-status region policy is unsupported")
    value["summary"] = _validate_selection_summary(value["summary"])
    nodes = value["nodes"]
    if not isinstance(nodes, list):
        raise PublicationError("node-status nodes are malformed")
    normalized_nodes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_names: set[str] = set()
    count_fields = (
        "within_1000_count",
        "under_1000_count",
        "response_count",
        "slow_response_count",
        "over_1000_count",
        "no_result_count",
        "timeout_count",
        "first_half_within_1000_count",
        "second_half_within_1000_count",
    )
    selectable_tiers = set(TIER_COUNT_FIELDS)
    confidence_values = {"verified", "source-specific", "unknown", "conflict"}
    concentration_values = {
        "exit_concentrated",
        "server_concentrated",
        "asn_concentrated",
        "source_concentrated",
    }
    for raw_node in nodes:
        node = _strict_mapping(raw_node, NODE_STATUS_ENTRY_FIELDS, "node-status node")
        candidate = validate_public_id(node["candidate_id"], "candidate")
        name = node["output_name"]
        if not isinstance(name, str) or not name or name != name.strip():
            raise PublicationError("node-status output name is malformed")
        if candidate in seen_ids or name in seen_names:
            raise PublicationError("node-status identities or names are duplicated")
        seen_ids.add(candidate)
        seen_names.add(name)
        for field in ("selected", "priority_selected", "auto_selected", "region_stale"):
            if not isinstance(node[field], bool):
                raise PublicationError(f"node-status {field} is malformed")
        tier = node["tier"]
        eligible_tier = node["eligible_tier"]
        if tier not in selectable_tiers | {"not_selected"}:
            raise PublicationError("node-status tier is unsupported")
        if eligible_tier is not None and eligible_tier not in selectable_tiers:
            raise PublicationError("node-status eligible tier is unsupported")
        if node["selected"]:
            if eligible_tier is None or tier != eligible_tier:
                raise PublicationError("selected node-status tier is inconsistent")
        elif tier != "not_selected":
            raise PublicationError("unselected node-status tier is inconsistent")
        if (node["priority_selected"] or node["auto_selected"]) and not node["selected"]:
            raise PublicationError("node-status group membership references an unselected node")
        for field in ("reason", "history_transition"):
            if not isinstance(node[field], str) or not node[field].strip():
                raise PublicationError(f"node-status {field} is malformed")
        country = node["country_code"]
        if not isinstance(country, str) or (
            country and not re.fullmatch(r"[A-Z0-9]{2,3}", country)
        ):
            raise PublicationError("node-status country code is malformed")
        if node["region_confidence"] not in confidence_values:
            raise PublicationError("node-status region confidence is unsupported")
        for field in count_fields:
            node[field] = _non_negative_int(node[field], f"node-status {field}")
        error_counts = node["error_counts"]
        if not isinstance(error_counts, Mapping) or set(error_counts) != set(ERROR_CATEGORIES):
            raise PublicationError("node-status error categories are incomplete")
        node["error_counts"] = {
            category: _non_negative_int(
                error_counts[category], f"node-status error_counts.{category}"
            )
            for category in ERROR_CATEGORIES
        }
        if node["response_count"] != node["within_1000_count"] + node["slow_response_count"]:
            raise PublicationError("node-status response counts do not conserve")
        if node["under_1000_count"] != node["within_1000_count"]:
            raise PublicationError("node-status under-1000 count is inconsistent")
        if node["over_1000_count"] != node["slow_response_count"]:
            raise PublicationError("node-status over-1000 count is inconsistent")
        if node["response_count"] + node["no_result_count"] != TOTAL_ROUNDS:
            raise PublicationError("node-status attempts do not equal twenty rounds")
        if node["timeout_count"] > node["no_result_count"]:
            raise PublicationError("node-status timeout count exceeds no-result attempts")
        if sum(node["error_counts"].values()) != node["no_result_count"]:
            raise PublicationError("node-status error counts do not conserve")
        if node["timeout_count"] != node["error_counts"]["client_timeout"]:
            raise PublicationError("node-status timeout count disagrees with error counts")
        if (
            node["first_half_within_1000_count"]
            + node["second_half_within_1000_count"]
            != node["within_1000_count"]
        ):
            raise PublicationError("node-status half-window counts do not conserve")
        for field in ("median_delay_ms", "p90_delay_ms", "jitter_ms"):
            node[field] = _optional_non_negative_number(
                node[field], f"node-status {field}"
            )
        delay_values = [
            node["median_delay_ms"],
            node["p90_delay_ms"],
            node["jitter_ms"],
        ]
        if node["response_count"] == 0 and any(item is not None for item in delay_values):
            raise PublicationError("zero-response node-status contains delay statistics")
        if node["response_count"] > 0 and any(item is None for item in delay_values):
            raise PublicationError("responsive node-status lacks delay statistics")
        flags = node["concentration_flags"]
        if (
            not isinstance(flags, list)
            or len(flags) != len(set(flags))
            or any(item not in concentration_values for item in flags)
        ):
            raise PublicationError("node-status concentration flags are malformed")
        normalized_nodes.append(node)
    if len(normalized_nodes) != value["summary"]["source_candidate_count"]:
        raise PublicationError("node-status count disagrees with selection summary")
    if sum(bool(node["selected"]) for node in normalized_nodes) != value["summary"][
        "published_count"
    ]:
        raise PublicationError("node-status selected count disagrees with summary")
    selected_tier_counts = {
        tier: sum(node["selected"] and node["tier"] == tier for node in normalized_nodes)
        for tier in TIER_COUNT_FIELDS
    }
    expected_tier_counts = {
        "asia_core": value["summary"]["asia_core_count"],
        "asia_flexible": value["summary"]["asia_flexible_count"],
        "asia_manual_candidate": value["summary"]["asia_manual_candidate_count"],
        "history_protected": value["summary"]["history_protected_count"],
        "non_asia_stable": value["summary"]["non_asia_stable_count"],
    }
    if selected_tier_counts != expected_tier_counts:
        raise PublicationError("node-status tier counts disagree with selection summary")
    stable_count = (
        selected_tier_counts["asia_core"]
        + selected_tier_counts["asia_flexible"]
        + selected_tier_counts["non_asia_stable"]
    )
    if stable_count != value["summary"]["stable_capacity_count"]:
        raise PublicationError("node-status stable capacity disagrees with summary")
    region_counts = {
        region: sum(
            node["selected"]
            and node["country_code"] == region
            and node["region_confidence"] in {"verified", "conflict"}
            for node in normalized_nodes
        )
        for region in REGION_COUNT_FIELDS
    }
    if region_counts != value["summary"]["region_counts"]:
        raise PublicationError("node-status region counts disagree with summary")
    if sum(node["region_confidence"] == "unknown" for node in normalized_nodes) != value[
        "summary"
    ]["unknown_region_count"]:
        raise PublicationError("node-status unknown-region count disagrees with summary")
    value["nodes"] = normalized_nodes
    validate_public_json_safety(value, label="node-status")
    return value


def validate_public_diagnostics(
    raw: Any,
    *,
    accepted_validity_policy_versions: frozenset[str] = frozenset(
        {VALIDITY_POLICY_VERSION}
    ),
    accepted_region_policy_versions: frozenset[str] = frozenset(
        {REGION_POLICY_VERSION}
    ),
) -> dict[str, Any]:
    value = _strict_mapping(raw, DIAGNOSTICS_FIELDS, "run diagnostics")
    if (
        value["kind"] != RUN_DIAGNOSTICS_KIND
        or value["schema_version"] != RUN_DIAGNOSTICS_SCHEMA_VERSION
    ):
        raise PublicationError("run diagnostics kind or schema is unsupported")
    if not isinstance(value["run_id"], str) or not RUN_ID_RE.fullmatch(value["run_id"]):
        raise PublicationError("run diagnostics run_id is malformed")
    value["attempt_id"] = _attempt_id(
        value["attempt_id"], "run diagnostics attempt_id"
    )
    value["retry_of"] = _retry_of(value["retry_of"], "run diagnostics retry_of")
    if value["retry_of"] == value["attempt_id"]:
        raise PublicationError("run diagnostics retry relation is self-referential")
    value["accepted_at"] = _timestamp(value["accepted_at"], "diagnostics accepted_at")
    value["source_run_at"] = _timestamp(
        value["source_run_at"], "diagnostics source_run_at"
    )
    if _parsed_timestamp(value["source_run_at"], "diagnostics source_run_at") > _parsed_timestamp(
        value["accepted_at"], "diagnostics accepted_at"
    ):
        raise PublicationError("run diagnostics predates its source snapshot")
    for field in ("source_sha256", "profile_sha256", "candidate_metadata_sha256"):
        value[field] = _sha256(value[field], field)
    value["main_sha"] = _git_sha(value["main_sha"], "run diagnostics main_sha")
    value["identity_key_version"] = validate_identity_version(
        value["identity_key_version"], "identity_key_version"
    )
    value["identity_epoch"] = validate_identity_version(
        value["identity_epoch"], "identity_epoch"
    )
    if value["selection_policy_version"] != SELECTION_POLICY_VERSION:
        raise PublicationError("run diagnostics selection policy is unsupported")
    if value["region_policy_version"] not in accepted_region_policy_versions:
        raise PublicationError("run diagnostics region policy is unsupported")
    if value["validity_policy_version"] not in accepted_validity_policy_versions:
        raise PublicationError("run diagnostics validity policy is unsupported")
    if value["total_rounds"] != TOTAL_ROUNDS or value["shard_count"] != SHARD_COUNT:
        raise PublicationError("run diagnostics round or shard contract mismatch")
    if (
        _positive_number(
            value["minimum_observation_window_seconds"],
            "minimum_observation_window_seconds",
        )
        < MINIMUM_OBSERVATION_WINDOW_SECONDS
    ):
        raise PublicationError("run diagnostics observation window is too short")
    if value["valid_run"] is not True or value["validity_reasons"] != []:
        raise PublicationError("only an accepted valid run can be published")
    if not isinstance(value["metrics"], Mapping):
        raise PublicationError("run diagnostics metrics must be an object")
    value["metrics"] = copy.deepcopy(dict(value["metrics"]))
    if "runner_region" in value["metrics"]:
        value["metrics"]["runner_region"] = _public_region(
            value["metrics"]["runner_region"],
            "run diagnostics runner_region",
        )
    shards = value["shards"]
    if not isinstance(shards, list) or len(shards) != SHARD_COUNT:
        raise PublicationError("run diagnostics must contain four shards")
    normalized_shards: list[dict[str, Any]] = []
    for raw_shard in shards:
        shard = _strict_mapping(raw_shard, DIAGNOSTIC_SHARD_FIELDS, "diagnostic shard")
        for field in (
            "shard_index",
            "candidate_count",
            "controller_healthy_check_count",
            "controller_unhealthy_count",
            "canary_count",
        ):
            shard[field] = _non_negative_int(shard[field], field)
        if shard["controller_healthy_check_count"] != 40:
            raise PublicationError("diagnostic shard controller checks are incomplete")
        if shard["controller_unhealthy_count"] != 0:
            raise PublicationError("diagnostic shard controller is unhealthy")
        if str(shard["egress_country"]).upper() != "CN":
            raise PublicationError("diagnostic shard egress country is not CN")
        shard["egress_region"] = _public_region(
            shard["egress_region"], "diagnostic shard egress region"
        )
        normalized_shards.append(shard)
    if sorted(shard["shard_index"] for shard in normalized_shards) != list(
        range(SHARD_COUNT)
    ):
        raise PublicationError("diagnostic shard indices are incomplete")
    value["shards"] = sorted(normalized_shards, key=lambda item: item["shard_index"])
    value["bundle_hash"] = value.get("bundle_hash")
    if value["bundle_hash"] is not None:
        value["bundle_hash"] = _sha256(value["bundle_hash"], "bundle_hash")
    validate_public_json_safety(value, label="run diagnostics")
    return value


def _validate_profile(content: bytes) -> tuple[dict[str, Any], int]:
    try:
        profile = yaml.safe_load(content.decode("utf-8"))
    except Exception as exc:
        raise PublicationError("clash.yaml is invalid UTF-8 YAML") from exc
    if not isinstance(profile, Mapping):
        raise PublicationError("clash.yaml must contain a mapping")
    proxies = profile.get("proxies")
    groups = profile.get("proxy-groups")
    if not isinstance(proxies, list) or not all(isinstance(item, Mapping) for item in proxies):
        raise PublicationError("clash.yaml proxies are malformed")
    if not isinstance(groups, list) or not all(isinstance(item, Mapping) for item in groups):
        raise PublicationError("clash.yaml proxy-groups are malformed")
    proxy_names = [str(item.get("name") or "") for item in proxies]
    if any(not name for name in proxy_names) or len(proxy_names) != len(set(proxy_names)):
        raise PublicationError("clash.yaml proxy names are empty or duplicated")
    group_names = [str(item.get("name") or "") for item in groups]
    if tuple(group_names) != tuple(V2_GROUP_NAMES):
        raise PublicationError("clash.yaml does not contain the exact V2 group order")
    allowed = set(proxy_names) | set(group_names) | {
        "DIRECT",
        "REJECT",
        "GLOBAL",
        "MATCH",
        "COMPATIBLE",
    }
    for group in groups:
        references = group.get("proxies")
        if not isinstance(references, list) or any(str(item) not in allowed for item in references):
            raise PublicationError("clash.yaml contains a dangling group reference")
    return copy.deepcopy(dict(profile)), len(proxies)


def _validate_run_index(raw: Any, *, current_run_id: str) -> dict[str, Any]:
    value = _strict_mapping(raw, RUN_INDEX_FIELDS, "run index")
    if value["kind"] != RUN_INDEX_KIND or value["schema_version"] != RUN_INDEX_SCHEMA_VERSION:
        raise PublicationError("run index kind or schema is unsupported")
    if value["current_run_id"] != current_run_id:
        raise PublicationError("run index current run mismatch")
    if value["bundle_hash"] is not None:
        value["bundle_hash"] = _sha256(value["bundle_hash"], "run index bundle_hash")
    entries = value["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= RECENT_RUN_LIMIT:
        raise PublicationError("run index must contain one to five entries")
    normalized: list[dict[str, Any]] = []
    run_ids: set[str] = set()
    source_shas: set[str] = set()
    for raw_entry in entries:
        entry = _strict_mapping(raw_entry, RUN_INDEX_ENTRY_FIELDS, "run index entry")
        if not isinstance(entry["run_id"], str) or not RUN_ID_RE.fullmatch(entry["run_id"]):
            raise PublicationError("run index entry run_id is malformed")
        entry["attempt_id"] = _attempt_id(
            entry["attempt_id"], "run index attempt_id"
        )
        entry["retry_of"] = _retry_of(entry["retry_of"], "run index retry_of")
        entry["source_sha256"] = _sha256(entry["source_sha256"], "source_sha256")
        entry["diagnostics_sha256"] = _sha256(
            entry["diagnostics_sha256"], "diagnostics_sha256"
        )
        entry["output_profile_sha256"] = _sha256(
            entry["output_profile_sha256"], "output_profile_sha256"
        )
        entry["accepted_at"] = _timestamp(
            entry["accepted_at"], "run index accepted_at"
        )
        entry["source_run_at"] = _timestamp(
            entry["source_run_at"], "run index source_run_at"
        )
        if _parsed_timestamp(
            entry["source_run_at"], "run index source_run_at"
        ) > _parsed_timestamp(entry["accepted_at"], "run index accepted_at"):
            raise PublicationError("run index entry predates its source snapshot")
        if entry["run_id"] in run_ids or entry["source_sha256"] in source_shas:
            raise PublicationError("run index contains duplicate run or source identities")
        run_ids.add(entry["run_id"])
        source_shas.add(entry["source_sha256"])
        normalized.append(entry)
    if normalized[-1]["run_id"] != current_run_id:
        raise PublicationError("run index does not end with the current run")
    if normalized != sorted(normalized, key=lambda item: item["accepted_at"]):
        raise PublicationError("run index entries are not chronological")
    if normalized != sorted(normalized, key=lambda item: item["source_run_at"]):
        raise PublicationError("run index source snapshots are not chronological")
    if len({item["source_run_at"] for item in normalized}) != len(normalized):
        raise PublicationError("run index source snapshot times are duplicated")
    value["entries"] = normalized
    validate_public_json_safety(value, label="run index")
    return value


def _previous_entries(previous_run_index: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if previous_run_index is None:
        return []
    current_run = previous_run_index.get("current_run_id")
    if not isinstance(current_run, str):
        raise PublicationError("previous run index current run is malformed")
    normalized = _validate_run_index(previous_run_index, current_run_id=current_run)
    return copy.deepcopy(normalized["entries"])


def _validate_selection_result(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise PublicationError("selection result must be an object")
    value = copy.deepcopy(dict(raw))
    if (
        value.get("kind") != SELECTION_RESULT_KIND
        or value.get("schema_version") != SELECTION_RESULT_SCHEMA_VERSION
    ):
        raise PublicationError("selection result kind or schema is unsupported")
    # The owner functions perform their own complete schema and reference checks.
    render_selection_profile(value)
    public_selection_status(value)
    return value


def _require_history_region_policy(
    history: Mapping[str, Any],
    expected_policy_version: str,
) -> None:
    for node in history["nodes"].values():
        cache = node.get("region_cache")
        if cache is not None and cache.get("policy_version") != expected_policy_version:
            raise PublicationError(
                "history region cache policy disagrees with the publication"
            )


def build_publish_bundle(
    *,
    selection_result: Mapping[str, Any],
    history: Mapping[str, Any],
    diagnostics: Mapping[str, Any],
    runtime: Mapping[str, Any],
    accepted_at: str,
    source_run_at: str,
    previous_run_index: Mapping[str, Any] | None = None,
) -> PublishBundle:
    """Build the immutable, branch-neutral public tree in one operation."""

    selection = _validate_selection_result(selection_result)
    normalized_history = validate_history(history, reserved_names=V2_GROUP_NAMES)
    normalized_diagnostics = validate_public_diagnostics(diagnostics)
    normalized_runtime = _validate_runtime(runtime)
    accepted_at = _timestamp(accepted_at, "publication accepted_at")
    source_run_at = _timestamp(source_run_at, "publication source_run_at")
    if _parsed_timestamp(source_run_at, "publication source_run_at") > _parsed_timestamp(
        accepted_at, "publication accepted_at"
    ):
        raise PublicationError("publication predates its source snapshot")
    run_id = selection["run_id"]
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise PublicationError("selection run_id is malformed")
    source_sha = _sha256(selection["source_sha256"], "source_sha256")
    attempt_id = _attempt_id(
        normalized_diagnostics["attempt_id"], "diagnostics attempt_id"
    )
    retry_of = _retry_of(
        normalized_diagnostics["retry_of"], "diagnostics retry_of"
    )
    common = {
        "run_id": run_id,
        "source_sha256": source_sha,
        "main_sha": _git_sha(selection["main_sha"], "selection main_sha"),
        "profile_sha256": _sha256(
            selection["profile_sha256"], "selection profile_sha256"
        ),
        "candidate_metadata_sha256": _sha256(
            selection["candidate_metadata_sha256"],
            "selection candidate_metadata_sha256",
        ),
        "identity_key_version": validate_identity_version(
            selection["identity_key_version"], "identity_key_version"
        ),
        "identity_epoch": validate_identity_version(
            selection["identity_epoch"], "identity_epoch"
        ),
        "selection_policy_version": selection["selection_policy_version"],
        "region_policy_version": selection["region_policy_version"],
    }
    if common["selection_policy_version"] != SELECTION_POLICY_VERSION:
        raise PublicationError("selection policy is unsupported")
    if common["region_policy_version"] != REGION_POLICY_VERSION:
        raise PublicationError("selection region policy is unsupported")
    for field, expected in common.items():
        if normalized_diagnostics[field] != expected:
            raise PublicationError(f"diagnostics {field} disagrees with selection")
    if normalized_diagnostics["accepted_at"] != accepted_at:
        raise PublicationError("diagnostics accepted_at disagrees with publication")
    if normalized_diagnostics["source_run_at"] != source_run_at:
        raise PublicationError("diagnostics source_run_at disagrees with publication")
    if (
        normalized_history["last_accepted_run_id"] != run_id
        or normalized_history["last_accepted_source_sha256"] != source_sha
        or normalized_history["last_accepted_at"] != accepted_at
    ):
        raise PublicationError("history does not contain the accepted publication run")
    if (
        normalized_history["identity_key_version"] != common["identity_key_version"]
        or normalized_history["identity_epoch"] != common["identity_epoch"]
        or normalized_history["selection_policy_version"]
        != common["selection_policy_version"]
    ):
        raise PublicationError("history identity or selection policy mismatch")
    _require_history_region_policy(
        normalized_history,
        common["region_policy_version"],
    )

    profile_bytes = render_selection_profile(selection).encode("utf-8")
    profile, published_count = _validate_profile(profile_bytes)
    profile_names = {str(proxy["name"]) for proxy in profile["proxies"]}
    selection_status = public_selection_status(selection)
    summary = _validate_selection_summary(selection["summary"])
    validate_selection_publication(summary)
    if published_count != summary["published_count"]:
        raise PublicationError("selection profile count disagrees with its status")
    status_summary = {
        key: copy.deepcopy(selection_status[key]) for key in SELECTION_SUMMARY_FIELDS
    }
    if _validate_selection_summary(status_summary) != summary:
        raise PublicationError("selection status summary disagrees with selection")
    node_status = _validate_node_status(
        selection["node_status"], expected_bundle_hash=None
    )
    for field, expected in common.items():
        if node_status[field] != expected:
            raise PublicationError(f"node-status {field} disagrees with selection")
    if node_status["summary"] != summary:
        raise PublicationError("node-status summary disagrees with selection")
    selected_nodes = [node for node in node_status["nodes"] if node["selected"]]
    if {str(node["output_name"]) for node in selected_nodes} != profile_names:
        raise PublicationError("selected node-status names disagree with clash.yaml")
    history_nodes = normalized_history["nodes"]
    for node in selected_nodes:
        history_node = history_nodes.get(node["candidate_id"])
        if history_node is None or history_node["output_name"] != node["output_name"]:
            raise PublicationError("selected node-status identity disagrees with history")
    diagnostics_path = f"runs/{run_id}/diagnostics.json"
    diagnostics_without_hash = {**normalized_diagnostics, "bundle_hash": None}
    diagnostics_sha = hashlib.sha256(
        _canonical_json_bytes(diagnostics_without_hash, strip_bundle_hash=True)
    ).hexdigest()
    new_entry = {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "retry_of": retry_of,
        "source_sha256": source_sha,
        "accepted_at": accepted_at,
        "source_run_at": source_run_at,
        "diagnostics_sha256": diagnostics_sha,
        "output_profile_sha256": selection_status["output_profile_sha256"],
    }
    entries = _previous_entries(previous_run_index)
    if any(
        item["run_id"] == run_id or item["source_sha256"] == source_sha
        for item in entries
    ):
        raise PublicationError("run index already contains this accepted run or source SHA")
    entries = (entries + [new_entry])[-RECENT_RUN_LIMIT:]
    recent_history = {
        (item["run_id"], item["source_sha256"], item["accepted_at"])
        for item in normalized_history["recent_accepted_runs"]
    }
    for entry in entries:
        if (
            entry["run_id"],
            entry["source_sha256"],
            entry["accepted_at"],
        ) not in recent_history:
            raise PublicationError("run index entry is missing from accepted history")
    run_index = {
        "kind": RUN_INDEX_KIND,
        "schema_version": RUN_INDEX_SCHEMA_VERSION,
        "bundle_hash": None,
        "current_run_id": run_id,
        "entries": entries,
    }
    status = {
        "kind": PUBLISH_STATUS_KIND,
        "schema_version": PUBLISH_STATUS_SCHEMA_VERSION,
        "bundle_hash": None,
        "public_allowlist_version": PUBLIC_ALLOWLIST_VERSION,
        "publish_policy_version": PUBLISH_POLICY_VERSION,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "retry_of": retry_of,
        "accepted_at": accepted_at,
        "source_run_at": source_run_at,
        "source_sha256": source_sha,
        "main_sha": common["main_sha"],
        "source_profile_sha256": common["profile_sha256"],
        "candidate_metadata_sha256": common["candidate_metadata_sha256"],
        "output_profile_sha256": selection_status["output_profile_sha256"],
        "identity_key_version": common["identity_key_version"],
        "identity_epoch": common["identity_epoch"],
        "selection_policy_version": common["selection_policy_version"],
        "region_policy_version": common["region_policy_version"],
        "history_policy_version": HISTORY_POLICY_VERSION,
        "validity_policy_version": normalized_diagnostics[
            "validity_policy_version"
        ],
        "published_count": int(summary["published_count"]),
        "source_candidate_count": int(summary["source_candidate_count"]),
        "stable_capacity_count": int(summary["stable_capacity_count"]),
        "desired_capacity": int(summary["desired_capacity"]),
        "desired_capacity_reached": bool(summary["desired_capacity_reached"]),
        "max_nodes": int(summary["max_nodes"]),
        "tier_counts": {
            "asia_core": int(summary["asia_core_count"]),
            "asia_flexible": int(summary["asia_flexible_count"]),
            "asia_manual_candidate": int(summary["asia_manual_candidate_count"]),
            "history_protected": int(summary["history_protected_count"]),
            "non_asia_stable": int(summary["non_asia_stable_count"]),
        },
        "region_counts": copy.deepcopy(summary["region_counts"]),
        "total_rounds": normalized_diagnostics["total_rounds"],
        "shard_count": normalized_diagnostics["shard_count"],
        "minimum_observation_window_seconds": normalized_diagnostics[
            "minimum_observation_window_seconds"
        ],
        "runtime": normalized_runtime,
        "diagnostics_path": diagnostics_path,
        "history_schema_version": HISTORY_SCHEMA_VERSION,
        "node_status_schema_version": NODE_STATUS_SCHEMA_VERSION,
        "run_index_schema_version": RUN_INDEX_SCHEMA_VERSION,
        "selection_summary": copy.deepcopy(summary),
    }
    published_history = {**copy.deepcopy(normalized_history), "bundle_hash": None}
    node_status["bundle_hash"] = None
    payload_json = {
        "status.json": status,
        "history.json": published_history,
        "node-status.json": node_status,
        "runs/index.json": run_index,
        diagnostics_path: diagnostics_without_hash,
    }
    for path, payload in payload_json.items():
        validate_public_json_safety(payload, label=path)
    base_files = {
        "clash.yaml": profile_bytes,
        **{path: public_json_bytes(payload) for path, payload in payload_json.items()},
    }
    bundle_hash = compute_logical_bundle_hash(base_files)
    final_files: dict[str, bytes] = {"clash.yaml": profile_bytes}
    for path, payload in payload_json.items():
        payload["bundle_hash"] = bundle_hash
        final_files[path] = public_json_bytes(payload)
    bundle_manifest = {
        "kind": BUNDLE_KIND,
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "bundle_hash": bundle_hash,
        "public_allowlist_version": PUBLIC_ALLOWLIST_VERSION,
        "run_id": run_id,
        "attempt_id": attempt_id,
        "retry_of": retry_of,
        "accepted_at": accepted_at,
        "source_run_at": source_run_at,
        "source_sha256": source_sha,
        "main_sha": common["main_sha"],
        "identity_key_version": common["identity_key_version"],
        "identity_epoch": common["identity_epoch"],
        "files": [
            {
                "path": path,
                "sha256": hashlib.sha256(content).hexdigest(),
                "size": len(content),
                "kind": (
                    "clash-profile"
                    if path == "clash.yaml"
                    else str(_load_json_bytes(content, path)["kind"])
                ),
                "schema_version": (
                    None
                    if path == "clash.yaml"
                    else int(_load_json_bytes(content, path)["schema_version"])
                ),
            }
            for path, content in sorted(final_files.items())
        ],
    }
    validate_public_json_safety(bundle_manifest, label="bundle.json")
    final_files["bundle.json"] = public_json_bytes(bundle_manifest)
    bundle = validate_publish_bundle(final_files)
    return bundle


def _published_history(raw: Any, *, expected_bundle_hash: str) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise PublicationError("published history must be an object")
    value = copy.deepcopy(dict(raw))
    if value.pop("bundle_hash", None) != expected_bundle_hash:
        raise PublicationError("published history bundle hash mismatch")
    return validate_history(value, reserved_names=V2_GROUP_NAMES)


def validate_publish_bundle(files: Mapping[str, bytes]) -> PublishBundle:
    normalized_files = {_safe_relative_path(path): content for path, content in files.items()}
    if len(normalized_files) != len(files) or "bundle.json" not in normalized_files:
        raise PublicationError("bundle tree contains duplicate or missing paths")
    manifest = _strict_mapping(
        _load_json_bytes(normalized_files["bundle.json"], "bundle.json"),
        BUNDLE_FIELDS,
        "bundle manifest",
    )
    if manifest["kind"] != BUNDLE_KIND or manifest["schema_version"] != BUNDLE_SCHEMA_VERSION:
        raise PublicationError("bundle kind or schema is unsupported")
    bundle_hash = _sha256(manifest["bundle_hash"], "bundle_hash")
    if manifest["public_allowlist_version"] != PUBLIC_ALLOWLIST_VERSION:
        raise PublicationError("bundle public allowlist version is unsupported")
    run_id = manifest["run_id"]
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise PublicationError("bundle run_id is malformed")
    manifest["attempt_id"] = _attempt_id(
        manifest["attempt_id"], "bundle attempt_id"
    )
    manifest["retry_of"] = _retry_of(manifest["retry_of"], "bundle retry_of")
    source_sha = _sha256(manifest["source_sha256"], "source_sha256")
    manifest["accepted_at"] = _timestamp(
        manifest["accepted_at"], "bundle accepted_at"
    )
    manifest["source_run_at"] = _timestamp(
        manifest["source_run_at"], "bundle source_run_at"
    )
    if _parsed_timestamp(
        manifest["source_run_at"], "bundle source_run_at"
    ) > _parsed_timestamp(manifest["accepted_at"], "bundle accepted_at"):
        raise PublicationError("bundle predates its source snapshot")
    manifest["main_sha"] = _git_sha(manifest["main_sha"], "bundle main_sha")
    manifest["identity_key_version"] = validate_identity_version(
        manifest["identity_key_version"], "identity_key_version"
    )
    manifest["identity_epoch"] = validate_identity_version(
        manifest["identity_epoch"], "identity_epoch"
    )
    entries = manifest["files"]
    if not isinstance(entries, list) or not entries:
        raise PublicationError("bundle manifest file list is empty")
    expected_paths: set[str] = {"bundle.json"}
    for raw_entry in entries:
        entry = _strict_mapping(raw_entry, BUNDLE_FILE_FIELDS, "bundle file")
        path = _safe_relative_path(entry["path"])
        if path in expected_paths:
            raise PublicationError("bundle manifest contains duplicate paths")
        expected_paths.add(path)
        if path not in normalized_files:
            raise PublicationError("bundle manifest references a missing file")
        content = normalized_files[path]
        if _sha256(entry["sha256"], "bundle file SHA") != hashlib.sha256(content).hexdigest():
            raise PublicationError(f"bundle file hash mismatch: {path}")
        if _non_negative_int(entry["size"], "bundle file size") != len(content):
            raise PublicationError(f"bundle file size mismatch: {path}")
        if path == "clash.yaml":
            if entry["kind"] != "clash-profile" or entry["schema_version"] is not None:
                raise PublicationError("clash.yaml bundle metadata is malformed")
        else:
            payload = _load_json_bytes(content, path)
            if entry["kind"] != payload.get("kind") or entry["schema_version"] != payload.get(
                "schema_version"
            ):
                raise PublicationError(f"bundle file schema metadata mismatch: {path}")
    diagnostics_path = f"runs/{run_id}/diagnostics.json"
    exact_paths = {
        "bundle.json",
        "clash.yaml",
        "status.json",
        "history.json",
        "node-status.json",
        "runs/index.json",
        diagnostics_path,
    }
    if expected_paths != exact_paths or set(normalized_files) != exact_paths:
        raise PublicationError("bundle tree differs from the exact public allowlist")
    if compute_logical_bundle_hash(normalized_files) != bundle_hash:
        raise PublicationError("logical bundle hash mismatch")

    status = _strict_mapping(
        _load_json_bytes(normalized_files["status.json"], "status.json"),
        STATUS_FIELDS,
        "publish status",
    )
    if (
        status["kind"] != PUBLISH_STATUS_KIND
        or status["schema_version"] != PUBLISH_STATUS_SCHEMA_VERSION
        or status["publish_policy_version"] not in SUPPORTED_PUBLISH_POLICY_VERSIONS
        or status["public_allowlist_version"] != PUBLIC_ALLOWLIST_VERSION
    ):
        raise PublicationError("publish status kind, schema, or policy is unsupported")
    if status["bundle_hash"] != bundle_hash:
        raise PublicationError("publish status bundle hash mismatch")
    status["accepted_at"] = _timestamp(status["accepted_at"], "status accepted_at")
    status["source_run_at"] = _timestamp(
        status["source_run_at"], "status source_run_at"
    )
    status["source_sha256"] = _sha256(status["source_sha256"], "status source_sha256")
    status["attempt_id"] = _attempt_id(status["attempt_id"], "status attempt_id")
    status["retry_of"] = _retry_of(status["retry_of"], "status retry_of")
    status["main_sha"] = _git_sha(status["main_sha"], "status main_sha")
    for field in (
        "source_profile_sha256",
        "candidate_metadata_sha256",
        "output_profile_sha256",
    ):
        status[field] = _sha256(status[field], f"status {field}")
    status["identity_key_version"] = validate_identity_version(
        status["identity_key_version"], "identity_key_version"
    )
    status["identity_epoch"] = validate_identity_version(
        status["identity_epoch"], "identity_epoch"
    )
    manifest_bindings = {
        "run_id": run_id,
        "attempt_id": manifest["attempt_id"],
        "retry_of": manifest["retry_of"],
        "accepted_at": manifest["accepted_at"],
        "source_run_at": manifest["source_run_at"],
        "source_sha256": source_sha,
        "main_sha": manifest["main_sha"],
        "identity_key_version": manifest["identity_key_version"],
        "identity_epoch": manifest["identity_epoch"],
    }
    for field, expected in manifest_bindings.items():
        if status[field] != expected:
            raise PublicationError(f"publish status {field} disagrees with bundle manifest")
    if status["selection_policy_version"] != SELECTION_POLICY_VERSION:
        raise PublicationError("publish status selection policy is unsupported")
    if status["history_policy_version"] != HISTORY_POLICY_VERSION:
        raise PublicationError("publish status history policy is unsupported")
    policy_triple = (
        status["publish_policy_version"],
        status["validity_policy_version"],
        status["region_policy_version"],
    )
    if policy_triple not in SUPPORTED_PUBLICATION_POLICY_TRIPLES:
        raise PublicationError("publish status policy triple is unsupported")
    bundle_validity_policies = frozenset({status["validity_policy_version"]})
    bundle_region_policies = frozenset({status["region_policy_version"]})
    if status["total_rounds"] != TOTAL_ROUNDS or status["shard_count"] != SHARD_COUNT:
        raise PublicationError("publish status round/shard contract mismatch")
    if _positive_number(
        status["minimum_observation_window_seconds"], "status observation window"
    ) < MINIMUM_OBSERVATION_WINDOW_SECONDS:
        raise PublicationError("publish status observation window is too short")
    selection_summary = _validate_selection_summary(status["selection_summary"])
    for field in (
        "published_count",
        "source_candidate_count",
        "stable_capacity_count",
        "desired_capacity",
        "max_nodes",
    ):
        status[field] = _non_negative_int(status[field], f"status {field}")
        if status[field] != selection_summary[field]:
            raise PublicationError(f"publish status {field} disagrees with selection summary")
    if not isinstance(status["desired_capacity_reached"], bool):
        raise PublicationError("publish status desired-capacity flag is malformed")
    if status["desired_capacity_reached"] != selection_summary[
        "desired_capacity_reached"
    ]:
        raise PublicationError("publish status desired-capacity flag disagrees with summary")
    tier_counts = _strict_mapping(status["tier_counts"], TIER_COUNT_FIELDS, "tier counts")
    for field in tier_counts:
        tier_counts[field] = _non_negative_int(tier_counts[field], f"tier count {field}")
    expected_tier_counts = {
        "asia_core": selection_summary["asia_core_count"],
        "asia_flexible": selection_summary["asia_flexible_count"],
        "asia_manual_candidate": selection_summary["asia_manual_candidate_count"],
        "history_protected": selection_summary["history_protected_count"],
        "non_asia_stable": selection_summary["non_asia_stable_count"],
    }
    if tier_counts != expected_tier_counts:
        raise PublicationError("publish status tier counts disagree with selection summary")
    if sum(tier_counts.values()) != status["published_count"]:
        raise PublicationError("publish status tier counts do not conserve published nodes")
    region_counts = _strict_mapping(
        status["region_counts"], REGION_COUNT_FIELDS, "status region counts"
    )
    for field in region_counts:
        region_counts[field] = _non_negative_int(
            region_counts[field], f"status region count {field}"
        )
    if region_counts != selection_summary["region_counts"]:
        raise PublicationError("publish status region counts disagree with selection summary")
    runtime = _validate_runtime(status["runtime"])
    profile, proxy_count = _validate_profile(normalized_files["clash.yaml"])
    profile_names = {str(proxy["name"]) for proxy in profile["proxies"]}
    if proxy_count != _non_negative_int(status["published_count"], "published_count"):
        raise PublicationError("publish status count disagrees with clash.yaml")
    if hashlib.sha256(normalized_files["clash.yaml"]).hexdigest() != status[
        "output_profile_sha256"
    ]:
        raise PublicationError("publish status profile hash mismatch")
    if status["diagnostics_path"] != diagnostics_path:
        raise PublicationError("publish status diagnostics path mismatch")
    if (
        status["history_schema_version"] != HISTORY_SCHEMA_VERSION
        or status["node_status_schema_version"] != NODE_STATUS_SCHEMA_VERSION
        or status["run_index_schema_version"] != RUN_INDEX_SCHEMA_VERSION
    ):
        raise PublicationError("publish status child schema mismatch")

    history = _published_history(
        _load_json_bytes(normalized_files["history.json"], "history.json"),
        expected_bundle_hash=bundle_hash,
    )
    if (
        history["last_accepted_run_id"] != run_id
        or history["last_accepted_source_sha256"] != source_sha
        or history["last_accepted_at"] != status["accepted_at"]
    ):
        raise PublicationError("published history is not synchronized with status")
    if (
        history["identity_key_version"] != status["identity_key_version"]
        or history["identity_epoch"] != status["identity_epoch"]
        or history["selection_policy_version"] != status["selection_policy_version"]
        or history["history_policy_version"] != status["history_policy_version"]
    ):
        raise PublicationError("published history identity or policy disagrees with status")
    _require_history_region_policy(history, status["region_policy_version"])
    node_status = _validate_node_status(
        _load_json_bytes(normalized_files["node-status.json"], "node-status.json"),
        expected_bundle_hash=bundle_hash,
        accepted_region_policy_versions=bundle_region_policies,
    )
    node_bindings = {
        "run_id": status["run_id"],
        "source_sha256": status["source_sha256"],
        "main_sha": status["main_sha"],
        "profile_sha256": status["source_profile_sha256"],
        "candidate_metadata_sha256": status["candidate_metadata_sha256"],
        "identity_key_version": status["identity_key_version"],
        "identity_epoch": status["identity_epoch"],
        "selection_policy_version": status["selection_policy_version"],
        "region_policy_version": status["region_policy_version"],
    }
    for field, expected in node_bindings.items():
        if node_status[field] != expected:
            raise PublicationError(f"node-status {field} disagrees with status")
    if node_status["summary"] != selection_summary:
        raise PublicationError("node-status selection summary disagrees with status")
    selected_nodes = [node for node in node_status["nodes"] if node["selected"]]
    if {str(node["output_name"]) for node in selected_nodes} != profile_names:
        raise PublicationError("selected node-status names disagree with clash.yaml")
    for node in selected_nodes:
        history_node = history["nodes"].get(node["candidate_id"])
        if history_node is None or history_node["output_name"] != node["output_name"]:
            raise PublicationError("selected node-status identity disagrees with history")
    diagnostics = validate_public_diagnostics(
        _load_json_bytes(normalized_files[diagnostics_path], diagnostics_path),
        accepted_validity_policy_versions=bundle_validity_policies,
        accepted_region_policy_versions=bundle_region_policies,
    )
    if diagnostics["bundle_hash"] != bundle_hash:
        raise PublicationError("run diagnostics bundle hash mismatch")
    diagnostic_bindings = {
        "run_id": "run_id",
        "attempt_id": "attempt_id",
        "retry_of": "retry_of",
        "accepted_at": "accepted_at",
        "source_run_at": "source_run_at",
        "source_sha256": "source_sha256",
        "main_sha": "main_sha",
        "profile_sha256": "source_profile_sha256",
        "candidate_metadata_sha256": "candidate_metadata_sha256",
        "identity_key_version": "identity_key_version",
        "identity_epoch": "identity_epoch",
        "selection_policy_version": "selection_policy_version",
        "region_policy_version": "region_policy_version",
        "validity_policy_version": "validity_policy_version",
    }
    for diagnostic_field, status_field in diagnostic_bindings.items():
        if diagnostics[diagnostic_field] != status[status_field]:
            raise PublicationError(
                f"run diagnostics {diagnostic_field} disagrees with status"
            )
    run_index = _validate_run_index(
        _load_json_bytes(normalized_files["runs/index.json"], "runs/index.json"),
        current_run_id=run_id,
    )
    if run_index["bundle_hash"] != bundle_hash:
        raise PublicationError("run index bundle hash mismatch")
    current_entry = run_index["entries"][-1]
    diagnostics_logical_sha = hashlib.sha256(
        _canonical_json_bytes(diagnostics, strip_bundle_hash=True)
    ).hexdigest()
    if (
        current_entry["source_sha256"] != source_sha
        or current_entry["attempt_id"] != status["attempt_id"]
        or current_entry["retry_of"] != status["retry_of"]
        or current_entry["accepted_at"] != status["accepted_at"]
        or current_entry["source_run_at"] != status["source_run_at"]
        or current_entry["diagnostics_sha256"] != diagnostics_logical_sha
        or current_entry["output_profile_sha256"] != status["output_profile_sha256"]
    ):
        raise PublicationError("run index current entry disagrees with the bundle")
    accepted_history_entries = {
        (item["run_id"], item["source_sha256"], item["accepted_at"])
        for item in history["recent_accepted_runs"]
    }
    for entry in run_index["entries"]:
        if (
            entry["run_id"],
            entry["source_sha256"],
            entry["accepted_at"],
        ) not in accepted_history_entries:
            raise PublicationError("run index entry is missing from accepted history")
    for path in exact_paths - {"clash.yaml"}:
        validate_public_json_safety(
            _load_json_bytes(normalized_files[path], path), label=path
        )
    del runtime
    return PublishBundle(
        files=dict(normalized_files),
        bundle_hash=bundle_hash,
        run_id=run_id,
        attempt_id=manifest["attempt_id"],
        retry_of=manifest["retry_of"],
        source_sha256=source_sha,
        accepted_at=str(status["accepted_at"]),
        source_run_at=str(status["source_run_at"]),
    )


def write_publish_bundle(output_dir: str | Path, bundle: PublishBundle) -> Path:
    destination = Path(output_dir).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    for path, content in bundle.files.items():
        target = destination / PurePosixPath(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(content)
        temporary.replace(target)
    return destination


def load_publish_bundle(directory: str | Path) -> PublishBundle:
    root = Path(directory).resolve()
    if not root.is_dir():
        raise PublicationError("bundle directory does not exist")
    files: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            files[relative] = path.read_bytes()
    return validate_publish_bundle(files)


def published_count_from_bundle(bundle: PublishBundle | None) -> int:
    """Return the published proxy count from an already validated bundle."""

    if bundle is None:
        return 0
    try:
        status = json.loads(bundle.files["status.json"].decode("utf-8"))
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PreviousStateError("previous bundle status is unreadable") from exc
    if not isinstance(status, Mapping):
        raise PreviousStateError("previous bundle status is malformed")
    value = status.get("published_count")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PreviousStateError("previous bundle published count is malformed")
    return value


def classify_previous_ref(
    *, branch: str, ls_remote_output: str, command_returncode: int
) -> PreviousState:
    if command_returncode != 0:
        raise PreviousStateError("authoritative branch lookup was unreadable")
    lines = [line.strip() for line in ls_remote_output.splitlines() if line.strip()]
    expected_ref = f"refs/heads/{branch}"
    if not lines:
        return PreviousState(exists=False, observed_tip=None, bundle=None)
    matches: list[str] = []
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or parts[1] != expected_ref:
            raise PreviousStateError("authoritative branch lookup returned unexpected data")
        matches.append(_git_sha(parts[0], "authoritative branch tip"))
    if len(matches) != 1:
        raise PreviousStateError("authoritative branch lookup is ambiguous")
    return PreviousState(exists=True, observed_tip=matches[0], bundle=None)


def attach_previous_bundle(state: PreviousState, bundle: PublishBundle) -> PreviousState:
    if not state.exists or state.observed_tip is None:
        raise PreviousStateError("cannot attach a bundle to an absent previous branch")
    return PreviousState(exists=True, observed_tip=state.observed_tip, bundle=bundle)


def staging_ref_for_source(source_sha256: str) -> str:
    return f"refs/heads/{STAGING_BRANCH_PREFIX}/{_sha256(source_sha256, 'source_sha256')}"


def authoritative_ref(branch: str = AUTHORITATIVE_BRANCH) -> str:
    if branch != AUTHORITATIVE_BRANCH:
        raise PublicationError(
            f"authoritative branch must be {AUTHORITATIVE_BRANCH}"
        )
    return f"refs/heads/{branch}"


def force_with_lease_argument(ref: str, expected_tip: str | None) -> str:
    if not ref.startswith("refs/heads/") or ".." in ref or " " in ref:
        raise PublicationError("lease ref is unsafe")
    expected = "" if expected_tip is None else _git_sha(expected_tip, "lease tip")
    return f"--force-with-lease={ref}:{expected}"


def parse_expected_previous_tip(value: str) -> str | None:
    text = str(value or "")
    if text == "absent":
        return None
    return _git_sha(text, "expected previous tip")


def publication_revision(
    *, ref: str, authoritative: str, expected_commit: str
) -> str:
    """Use an exact commit for staging and the branch ref for current smoke."""

    commit = _git_sha(expected_commit, "expected commit")
    if ref == authoritative:
        return authoritative.removeprefix("refs/heads/")
    return commit


def decide_source_trigger(
    *,
    source_sha256: str,
    current_status: Mapping[str, Any] | None,
    queued_or_running: Iterable[str] = (),
    retry: bool = False,
) -> str:
    source = _sha256(source_sha256, "source_sha256")
    active = {_sha256(item, "active source SHA") for item in queued_or_running}
    if source in active:
        return "noop_active"
    if current_status is not None:
        if not isinstance(current_status, Mapping):
            raise PublicationError("current status is malformed")
        accepted_source = current_status.get("source_sha256")
        if accepted_source == source:
            return "noop_accepted"
    if retry:
        return "retry_failed_infrastructure"
    return "queue"


def execute_transaction(
    *,
    bundle: PublishBundle,
    previous: PreviousState,
    commit_bundle: Callable[[PublishBundle], str],
    read_ref: Callable[[str], str | None],
    push_with_lease: Callable[[str, str | None, str | None], None],
    smoke: Callable[[str, str, PublishBundle], None],
    branch: str = AUTHORITATIVE_BRANCH,
) -> TransactionResult:
    """Execute staging -> smoke -> CAS promote -> smoke with controlled rollback."""

    current_count = published_count_from_bundle(bundle)
    previous_count = published_count_from_bundle(previous.bundle)
    validate_publication_capacity(current_count, previous_count)
    if previous.exists != (previous.observed_tip is not None):
        raise PreviousStateError("previous branch existence and tip disagree")
    if previous.exists and previous.bundle is None:
        raise PreviousStateError("present previous branch lacks a validated bundle")
    if previous.bundle is not None:
        if previous.bundle.source_sha256 == bundle.source_sha256:
            raise PublicationTransactionError("source SHA is already authoritative")
        if _parsed_timestamp(
            previous.bundle.source_run_at, "previous source_run_at"
        ) >= _parsed_timestamp(bundle.source_run_at, "candidate source_run_at"):
            raise PublicationTransactionError(
                "candidate source snapshot is not newer than current"
            )
        if _parsed_timestamp(
            previous.bundle.accepted_at, "previous accepted_at"
        ) >= _parsed_timestamp(bundle.accepted_at, "candidate accepted_at"):
            raise PublicationTransactionError("publication run is not newer than current")
    commit = _git_sha(commit_bundle(bundle), "candidate commit")
    staging_ref = staging_ref_for_source(bundle.source_sha256)
    current_ref = authoritative_ref(branch)
    staging_tip = read_ref(staging_ref)
    if staging_tip is not None:
        staging_tip = _git_sha(staging_tip, "staging tip")
    push_with_lease(staging_ref, staging_tip, commit)
    smoke(staging_ref, commit, bundle)
    push_with_lease(current_ref, previous.observed_tip, commit)
    promoted = True
    try:
        observed = read_ref(current_ref)
        if observed != commit:
            raise PublicationTransactionError("authoritative tip changed after promotion")
        smoke(current_ref, commit, bundle)
        observed_after_smoke = read_ref(current_ref)
        if observed_after_smoke != commit:
            raise PublicationTransactionError(
                "authoritative tip changed during post-promotion smoke"
            )
    except Exception as exc:
        if promoted:
            try:
                push_with_lease(current_ref, commit, previous.observed_tip)
            except Exception as rollback_exc:
                raise PublicationTransactionError(
                    "post-promotion smoke failed and controlled rollback failed"
                ) from rollback_exc
        raise PublicationTransactionError(
            "post-promotion smoke failed; authoritative previous tip was restored"
        ) from exc
    return TransactionResult(
        commit=commit,
        staging_ref=staging_ref,
        authoritative_ref=current_ref,
        previous_tip=previous.observed_tip,
        bundle_hash=bundle.bundle_hash,
    )


def _run_git(
    args: Sequence[str],
    *,
    cwd: Path,
    check: bool = True,
    text: bool = True,
) -> subprocess.CompletedProcess[Any]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    if check and completed.returncode != 0:
        raise PublicationTransactionError("Git publication command failed")
    return completed


def _ls_remote(remote: str, ref: str, *, cwd: Path) -> tuple[int, str]:
    completed = _run_git(["ls-remote", "--refs", remote, ref], cwd=cwd, check=False)
    return completed.returncode, completed.stdout


def read_bundle_from_commit(
    *, remote: str, commit: str, work_dir: str | Path
) -> PublishBundle:
    commit = _git_sha(commit, "previous commit")
    root = Path(work_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    repo = Path(tempfile.mkdtemp(prefix="previous-", dir=root))
    try:
        _run_git(["init", "--quiet"], cwd=repo)
        _run_git(["fetch", "--quiet", "--depth=1", remote, commit], cwd=repo)
        paths_result = _run_git(
            ["ls-tree", "-r", "--name-only", commit], cwd=repo
        )
        paths = [line.strip() for line in paths_result.stdout.splitlines() if line.strip()]
        files: dict[str, bytes] = {}
        for path in paths:
            safe = _safe_relative_path(path)
            result = _run_git(
                ["show", f"{commit}:{safe}"], cwd=repo, text=False
            )
            files[safe] = bytes(result.stdout)
        return validate_publish_bundle(files)
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _commit_bundle_in_repo(bundle: PublishBundle, *, work_dir: Path) -> tuple[Path, str]:
    repo = Path(tempfile.mkdtemp(prefix="candidate-", dir=work_dir))
    _run_git(["init", "--quiet"], cwd=repo)
    _run_git(["config", "user.name", "cnb-gmgn-v2[bot]"], cwd=repo)
    _run_git(
        ["config", "user.email", "cnb-gmgn-v2@users.noreply.cnb.cool"], cwd=repo
    )
    for path, content in bundle.files.items():
        target = repo / PurePosixPath(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    _run_git(["add", "--all"], cwd=repo)
    _run_git(
        ["commit", "--quiet", "-m", f"Publish GMGN V2 run {bundle.run_id}"], cwd=repo
    )
    commit = _run_git(["rev-parse", "HEAD"], cwd=repo).stdout.strip()
    return repo, _git_sha(commit, "candidate commit")


def publish_bundle_to_remote(
    *,
    bundle_dir: str | Path,
    remote: str,
    raw_base_template: str,
    work_dir: str | Path,
    mihomo: str | Path,
    expected_previous_tip: str,
    branch: str = AUTHORITATIVE_BRANCH,
) -> TransactionResult | None:
    """Live Git transaction used by CNB's publisher-only stage."""

    from scripts.validate_public_outputs import validate_remote_bundle

    bundle = load_publish_bundle(bundle_dir)
    work_root = Path(work_dir).resolve()
    work_root.mkdir(parents=True, exist_ok=True)
    current_ref = authoritative_ref(branch)
    rc, output = _ls_remote(remote, current_ref, cwd=work_root)
    previous = classify_previous_ref(
        branch=branch, ls_remote_output=output, command_returncode=rc
    )
    if previous.exists:
        previous_bundle = read_bundle_from_commit(
            remote=remote, commit=str(previous.observed_tip), work_dir=work_root
        )
        previous = attach_previous_bundle(previous, previous_bundle)
        if previous_bundle.source_sha256 == bundle.source_sha256:
            return None
    expected_tip = parse_expected_previous_tip(expected_previous_tip)
    if previous.observed_tip != expected_tip:
        raise PreviousStateError(
            "authoritative branch tip changed after bundle finalization"
        )

    if "{revision}" not in raw_base_template:
        raise PublicationError("raw base template must contain {revision}")

    repo, commit = _commit_bundle_in_repo(bundle, work_dir=work_root)

    def commit_bundle(_bundle: PublishBundle) -> str:
        return commit

    def read_ref(ref: str) -> str | None:
        ref_rc, ref_output = _ls_remote(remote, ref, cwd=repo)
        if ref_rc != 0:
            raise PublicationTransactionError("remote ref lookup failed")
        lines = [line for line in ref_output.splitlines() if line.strip()]
        if not lines:
            return None
        if len(lines) != 1:
            raise PublicationTransactionError("remote ref lookup is ambiguous")
        return _git_sha(lines[0].split()[0], "remote ref tip")

    def push_with_lease(ref: str, expected: str | None, target: str | None) -> None:
        lease = force_with_lease_argument(ref, expected)
        refspec = f":{ref}" if target is None else f"{target}:{ref}"
        _run_git(["push", lease, remote, refspec], cwd=repo)

    def smoke(ref: str, expected_commit: str, expected_bundle: PublishBundle) -> None:
        ref_name = ref.removeprefix("refs/heads/")
        scope = "current" if ref == current_ref else "staging"
        revision = publication_revision(
            ref=ref,
            authoritative=current_ref,
            expected_commit=expected_commit,
        )
        base_url = raw_base_template.format(
            ref=ref_name,
            commit=expected_commit,
            revision=revision,
        )
        validate_remote_bundle(
            base_url=base_url,
            expected_commit=expected_commit,
            expected_revision=revision,
            scope=scope,
            expected_bundle_hash=expected_bundle.bundle_hash,
            expected_source_sha=expected_bundle.source_sha256,
            evidence_dir=work_root / "remote-smoke" / scope / expected_commit,
            mihomo=Path(mihomo),
        )

    try:
        return execute_transaction(
            bundle=bundle,
            previous=previous,
            commit_bundle=commit_bundle,
            read_ref=read_ref,
            push_with_lease=push_with_lease,
            smoke=smoke,
            branch=branch,
        )
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="validate a local bundle tree")
    validate.add_argument("--bundle-dir", required=True)
    publish = commands.add_parser(
        "publish", help="transactionally publish a validated V2 bundle"
    )
    publish.add_argument("--bundle-dir", required=True)
    publish.add_argument("--remote", required=True)
    publish.add_argument("--raw-base-template", required=True)
    publish.add_argument("--work-dir", required=True)
    publish.add_argument("--mihomo", required=True)
    publish.add_argument("--expected-previous-tip", required=True)
    publish.add_argument("--branch", default=AUTHORITATIVE_BRANCH)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "validate":
        bundle = load_publish_bundle(args.bundle_dir)
        print(bundle.bundle_hash)
        return 0
    result = publish_bundle_to_remote(
        bundle_dir=args.bundle_dir,
        remote=args.remote,
        raw_base_template=args.raw_base_template,
        work_dir=args.work_dir,
        mihomo=args.mihomo,
        expected_previous_tip=args.expected_previous_tip,
        branch=args.branch,
    )
    if result is None:
        print("Source SHA is already authoritative; no publication was performed.")
    else:
        print(
            f"Published {result.bundle_hash} to {result.authoritative_ref} "
            f"at {result.commit}."
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)


__all__ = [
    "AUTHORITATIVE_BRANCH",
    "BUNDLE_KIND",
    "BUNDLE_SCHEMA_VERSION",
    "PUBLIC_ALLOWLIST_VERSION",
    "PUBLISH_POLICY_VERSION",
    "PUBLISH_STATUS_KIND",
    "PUBLISH_STATUS_SCHEMA_VERSION",
    "PreviousState",
    "PreviousStateError",
    "PublicationError",
    "PublicationTransactionError",
    "PublishBundle",
    "RUN_DIAGNOSTICS_KIND",
    "RUN_DIAGNOSTICS_SCHEMA_VERSION",
    "RUN_INDEX_KIND",
    "RUN_INDEX_SCHEMA_VERSION",
    "TransactionResult",
    "attach_previous_bundle",
    "authoritative_ref",
    "build_publish_bundle",
    "classify_previous_ref",
    "compute_logical_bundle_hash",
    "decide_source_trigger",
    "execute_transaction",
    "force_with_lease_argument",
    "parse_expected_previous_tip",
    "publication_revision",
    "load_publish_bundle",
    "publish_bundle_to_remote",
    "published_count_from_bundle",
    "read_bundle_from_commit",
    "staging_ref_for_source",
    "validate_public_diagnostics",
    "validate_publication_capacity",
    "validate_selection_publication",
    "validate_publish_bundle",
    "write_publish_bundle",
]
