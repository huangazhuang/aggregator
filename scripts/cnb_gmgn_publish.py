#!/usr/bin/env python3
"""Publish a quality-first Clash profile from private CNB GMGN probe fragments.

This module deliberately does not read or merge the legacy gstatic output.  It
accepts the hash-pinned manifest plus all four private selection fragments,
validates that they describe one complete 20-round GMGN run, applies the
region-aware policy, and writes only the selected proxies to ``clash.yaml``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from scripts.pipeline_utils import BUILTIN_PROXY_NAMES, dump_clash_yaml
from scripts.gmgn_history import load_history, reduce_history, write_history_atomic
from scripts.gmgn_selection import (
    public_selection_status,
    render_selection_profile,
    select_candidates_v2,
    validate_selection_input,
)
from scripts.proxy_identity import (
    assert_unique_public_id_bindings,
    canonical_proxy_fingerprint,
    validate_identity_version,
    validate_proxy_fingerprint,
    validate_public_id,
)
from subscribe.asia import is_preferred_asian_proxy


SELECTION_FRAGMENT_KIND = "cnb-gmgn-selection-fragment"
SELECTION_FRAGMENT_SCHEMA_VERSION = 1
SELECTION_FRAGMENT_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "main_sha",
        "source_sha256",
        "target_url",
        "expected_status",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "shard_count",
        "shard_index",
        "shard_profile_sha256",
        "proxy_count",
        "preferred_asia_count",
        "results",
    }
)
PUBLISH_SCHEMA_VERSION = 1
HISTORY_IDENTITY_MAP_KIND = "cnb-gmgn-history-identity-map"
HISTORY_IDENTITY_MAP_SCHEMA_VERSION = 1
FORMAL_MANIFEST_KIND = "cnb-gmgn-shadow-manifest"
FORMAL_MANIFEST_SCHEMA_VERSION = 2
REQUIRED_SHARD_COUNT = 4
TOTAL_ROUNDS = 20
QUALIFIED_DELAY_MS = 1000
DESIRED_CAPACITY = 80
MAX_NODES = 150
FIRST_PUBLISH_MINIMUM = 10
MIN_RETAIN_RATIO = 0.40
NON_ASIA_BASE_LIMIT = 10
NON_ASIA_MAX = 20
REGION_CLASSIFICATION = "source-label heuristic; egress region not verified"
GROUP_MANUAL = "手动选择"
GROUP_STABLE = "GMGN稳定"
GROUP_ASIA_FLEXIBLE = "亚洲弹性"
GROUP_OBSERVATION = "GMGN观察保留"
GROUP_AUTO = "GMGN自动"
PUBLISH_GROUP_NAMES = (
    GROUP_MANUAL,
    GROUP_STABLE,
    GROUP_ASIA_FLEXIBLE,
    GROUP_OBSERVATION,
    GROUP_AUTO,
)
BLOCK_FIELD_NAMES = (
    "within_limit_count_rounds_1_5",
    "within_limit_count_rounds_6_10",
    "within_limit_count_rounds_11_15",
    "within_limit_count_rounds_16_20",
)
RUNNER_FIELDS = frozenset(
    {
        "runner_country",
        "runner_region",
        "runner_org",
        "runner_geo_provider",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    write_text_atomic(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot load JSON from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON document must be an object: {path}")
    return payload


def non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise RuntimeError(f"{label} must be a non-negative integer")
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{label} must be a non-negative integer") from exc
    if number < 0 or (isinstance(value, float) and not value.is_integer()):
        raise RuntimeError(f"{label} must be a non-negative integer")
    return number


def finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise RuntimeError(f"{label} must be a finite number")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise RuntimeError(f"{label} must be a finite number") from exc
    if not math.isfinite(number):
        raise RuntimeError(f"{label} must be a finite number")
    return number


def boolean_argument(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def proxy_fingerprint(proxy: dict[str, Any]) -> str:
    """Compatibility wrapper around the sole GMGN canonical identity owner."""

    return canonical_proxy_fingerprint(proxy)


def _normalized_block_counts(summary: dict[str, Any]) -> list[int] | None:
    raw = summary.get("five_round_block_counts")
    if raw is not None:
        if not isinstance(raw, list) or len(raw) != 4:
            raise RuntimeError("five_round_block_counts must contain four integers")
        return [
            non_negative_int(value, f"five_round_block_counts[{index}]")
            for index, value in enumerate(raw)
        ]

    present = [field in summary for field in BLOCK_FIELD_NAMES]
    if any(present) and not all(present):
        raise RuntimeError("five-round block fields are incomplete")
    if all(present):
        return [non_negative_int(summary[field], field) for field in BLOCK_FIELD_NAMES]
    return None


def normalize_summary(
    raw_summary: Any,
    proxy: dict[str, Any],
    *,
    shard_index: int,
) -> dict[str, Any]:
    if not isinstance(raw_summary, dict):
        raise RuntimeError(f"shard {shard_index} result summary must be an object")
    summary = copy.deepcopy(raw_summary)
    attempts = non_negative_int(summary.get("attempts"), "attempts")
    if attempts != TOTAL_ROUNDS:
        raise RuntimeError(f"shard {shard_index} contains an incomplete node result")

    preferred_asia = summary.get("preferred_asia")
    if not isinstance(preferred_asia, bool):
        raise RuntimeError(f"shard {shard_index} preferred_asia must be boolean")
    if preferred_asia != bool(is_preferred_asian_proxy(proxy)):
        raise RuntimeError(
            f"shard {shard_index} preferred_asia disagrees with the source-label heuristic"
        )

    response_count = non_negative_int(summary.get("response_count"), "response_count")
    within_count = non_negative_int(
        summary.get("within_limit_count"), "within_limit_count"
    )
    slow_count = non_negative_int(
        summary.get("slow_response_count"), "slow_response_count"
    )
    no_result_count = non_negative_int(
        summary.get("no_result_count"), "no_result_count"
    )
    first_half = non_negative_int(
        summary.get("first_half_within_limit_count"),
        "first_half_within_limit_count",
    )
    second_half = non_negative_int(
        summary.get("second_half_within_limit_count"),
        "second_half_within_limit_count",
    )
    if response_count + no_result_count != attempts:
        raise RuntimeError(f"shard {shard_index} response counts do not sum to attempts")
    if within_count + slow_count != response_count:
        raise RuntimeError(f"shard {shard_index} delay classes do not sum to responses")
    if first_half > 10 or second_half > 10:
        raise RuntimeError(f"shard {shard_index} half-window count exceeds ten rounds")
    if first_half + second_half != within_count:
        raise RuntimeError(f"shard {shard_index} half-window counts are inconsistent")

    block_counts = _normalized_block_counts(summary)
    if block_counts is not None:
        if any(value > 5 for value in block_counts):
            raise RuntimeError(f"shard {shard_index} five-round block count exceeds five")
        if sum(block_counts) != within_count:
            raise RuntimeError(f"shard {shard_index} five-round block counts are inconsistent")
        if sum(block_counts[:2]) != first_half or sum(block_counts[2:]) != second_half:
            raise RuntimeError(f"shard {shard_index} block and half-window counts disagree")

    if "response_rate" in summary and not math.isclose(
        finite_number(summary["response_rate"], "response_rate"),
        round(response_count / attempts, 4),
        abs_tol=0.0001,
    ):
        raise RuntimeError(f"shard {shard_index} response_rate is inconsistent")
    if "within_limit_rate" in summary and not math.isclose(
        finite_number(summary["within_limit_rate"], "within_limit_rate"),
        round(within_count / attempts, 4),
        abs_tol=0.0001,
    ):
        raise RuntimeError(f"shard {shard_index} within_limit_rate is inconsistent")

    metrics = ("min_delay_ms", "median_delay_ms", "p90_delay_ms", "max_delay_ms")
    if response_count:
        if any(summary.get(field) is None for field in (*metrics, "jitter_ms")):
            raise RuntimeError(f"shard {shard_index} response metrics are incomplete")
        minimum, median, p90, maximum = (
            finite_number(summary[field], field) for field in metrics
        )
        jitter = finite_number(summary["jitter_ms"], "jitter_ms")
        if minimum <= 0 or not minimum <= median <= p90 <= maximum or jitter < 0:
            raise RuntimeError(f"shard {shard_index} response metrics are inconsistent")
        if (within_count > 0) != (minimum <= QUALIFIED_DELAY_MS):
            raise RuntimeError(f"shard {shard_index} within-limit boundary is inconsistent")
        if (slow_count > 0) != (maximum > QUALIFIED_DELAY_MS):
            raise RuntimeError(f"shard {shard_index} slow-response boundary is inconsistent")
    elif any(summary.get(field) is not None for field in (*metrics, "jitter_ms")):
        raise RuntimeError(f"shard {shard_index} empty responses contain delay metrics")

    summary.update(
        {
            "attempts": attempts,
            "preferred_asia": preferred_asia,
            "response_count": response_count,
            "within_limit_count": within_count,
            "slow_response_count": slow_count,
            "no_result_count": no_result_count,
            "first_half_within_limit_count": first_half,
            "second_half_within_limit_count": second_half,
            "five_round_block_counts": block_counts,
        }
    )
    return summary


def validate_proxy(raw_proxy: Any, *, shard_index: int) -> dict[str, Any]:
    if not isinstance(raw_proxy, dict):
        raise RuntimeError(f"shard {shard_index} result proxy must be an object")
    proxy = copy.deepcopy(raw_proxy)
    for field in ("name", "type", "server", "port"):
        if field not in proxy or str(proxy.get(field, "")).strip() == "":
            raise RuntimeError(f"shard {shard_index} proxy is missing {field}")
    proxy["name"] = str(proxy["name"]).strip()
    return proxy


def validate_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    if manifest.get("kind") != FORMAL_MANIFEST_KIND:
        raise RuntimeError("unsupported GMGN manifest kind")
    if manifest.get("schema_version") != FORMAL_MANIFEST_SCHEMA_VERSION:
        raise RuntimeError("unsupported GMGN manifest schema")
    if non_negative_int(manifest.get("shard_count"), "shard_count") != REQUIRED_SHARD_COUNT:
        raise RuntimeError("formal GMGN publication requires exactly four shards")
    if non_negative_int(manifest.get("total_rounds"), "total_rounds") != TOTAL_ROUNDS:
        raise RuntimeError("formal GMGN publication requires exactly 20 rounds")
    if (
        non_negative_int(manifest.get("qualified_delay_ms"), "qualified_delay_ms")
        != QUALIFIED_DELAY_MS
    ):
        raise RuntimeError("formal GMGN publication requires a 1000ms qualified delay")
    target_url = str(manifest.get("target_url") or "")
    if not re.match(r"^https://gmgn\.ai(?:/|$)", target_url, flags=re.I):
        raise RuntimeError("formal GMGN publication requires a gmgn.ai target")
    if non_negative_int(manifest.get("expected_status"), "expected_status") != 200:
        raise RuntimeError("formal GMGN publication requires HTTP status 200")
    if non_negative_int(manifest.get("request_timeout_ms"), "request_timeout_ms") != 3000:
        raise RuntimeError("formal GMGN publication requires a 3000ms request timeout")
    for field in ("run_id", "main_sha", "source_sha256"):
        if not str(manifest.get(field) or "").strip():
            raise RuntimeError(f"manifest is missing {field}")

    runner = manifest.get("runner")
    if not isinstance(runner, dict) or frozenset(runner) != RUNNER_FIELDS:
        raise RuntimeError("manifest runner metadata is incomplete or unexpected")
    if not all(isinstance(runner[field], str) for field in RUNNER_FIELDS):
        raise RuntimeError("manifest runner metadata must contain strings")

    raw_shards = manifest.get("shards")
    if not isinstance(raw_shards, list) or len(raw_shards) != REQUIRED_SHARD_COUNT:
        raise RuntimeError("manifest shard metadata is incomplete")
    shards = sorted(
        (dict(item) for item in raw_shards if isinstance(item, dict)),
        key=lambda item: int(item.get("shard_index", -1)),
    )
    if len(shards) != REQUIRED_SHARD_COUNT or [
        non_negative_int(item.get("shard_index"), "shard_index") for item in shards
    ] != list(range(REQUIRED_SHARD_COUNT)):
        raise RuntimeError("manifest shard indices are incomplete or duplicated")
    for shard in shards:
        non_negative_int(shard.get("proxy_count"), "proxy_count")
        non_negative_int(shard.get("preferred_asia_count", 0), "preferred_asia_count")
        if not str(shard.get("profile_sha256") or "").strip():
            raise RuntimeError("manifest shard is missing profile_sha256")
    if "source_count" in manifest:
        source_count = non_negative_int(manifest["source_count"], "source_count")
        if sum(int(item["proxy_count"]) for item in shards) != source_count:
            raise RuntimeError("manifest shard counts do not match source_count")
    if "source_asia_count" in manifest:
        source_asia_count = non_negative_int(
            manifest["source_asia_count"], "source_asia_count"
        )
        if sum(int(item.get("preferred_asia_count", 0)) for item in shards) != source_asia_count:
            raise RuntimeError(
                "manifest shard Asia counts do not match source_asia_count"
            )
    return shards


def load_selection_candidates(
    manifest_path: Path,
    fragment_paths: Iterable[Path],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = load_json_mapping(manifest_path)
    shards = validate_manifest(manifest)
    paths = [Path(path).resolve() for path in fragment_paths]
    if len(paths) != REQUIRED_SHARD_COUNT:
        raise RuntimeError("the number of selection fragments must be four")

    fragments_by_index: dict[int, dict[str, Any]] = {}
    for path in paths:
        fragment = load_json_mapping(path)
        if frozenset(fragment) != SELECTION_FRAGMENT_FIELDS:
            raise RuntimeError(f"selection fragment fields are incomplete or unexpected: {path}")
        if fragment.get("kind") != SELECTION_FRAGMENT_KIND:
            raise RuntimeError(f"unsupported selection fragment kind: {path}")
        if fragment.get("schema_version") != SELECTION_FRAGMENT_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported selection fragment schema: {path}")
        shard_index = non_negative_int(fragment.get("shard_index"), "shard_index")
        if shard_index in fragments_by_index:
            raise RuntimeError(f"duplicate selection fragment for shard {shard_index}")
        fragments_by_index[shard_index] = fragment

    candidates: list[dict[str, Any]] = []
    for expected_shard in shards:
        shard_index = int(expected_shard["shard_index"])
        if shard_index not in fragments_by_index:
            raise RuntimeError(f"missing selection fragment for shard {shard_index}")
        fragment = fragments_by_index[shard_index]
        expected_common = {
            "run_id": manifest["run_id"],
            "main_sha": manifest["main_sha"],
            "source_sha256": manifest["source_sha256"],
            "target_url": manifest["target_url"],
            "expected_status": manifest["expected_status"],
            "request_timeout_ms": manifest["request_timeout_ms"],
            "qualified_delay_ms": manifest["qualified_delay_ms"],
            "total_rounds": manifest["total_rounds"],
            "shard_count": manifest["shard_count"],
            "shard_index": expected_shard["shard_index"],
            "shard_profile_sha256": expected_shard["profile_sha256"],
            "proxy_count": expected_shard["proxy_count"],
            "preferred_asia_count": expected_shard.get("preferred_asia_count", 0),
        }
        for field, value in expected_common.items():
            if fragment.get(field) != value:
                raise RuntimeError(
                    f"shard {shard_index} field {field} mismatch: "
                    f"expected {value!r}, got {fragment.get(field)!r}"
                )
        raw_results = fragment.get("results")
        if not isinstance(raw_results, list) or len(raw_results) != int(
            expected_shard["proxy_count"]
        ):
            raise RuntimeError(f"shard {shard_index} result count mismatch")
        shard_candidates: list[dict[str, Any]] = []
        for raw_result in raw_results:
            if not isinstance(raw_result, dict):
                raise RuntimeError(f"shard {shard_index} result must be an object")
            proxy = validate_proxy(raw_result.get("proxy"), shard_index=shard_index)
            summary = normalize_summary(
                raw_result.get("summary"), proxy, shard_index=shard_index
            )
            shard_candidates.append(
                {
                    "proxy": proxy,
                    "summary": summary,
                    "fingerprint": proxy_fingerprint(proxy),
                    "source_name": str(proxy["name"]),
                    "candidate_id": f"{shard_index}:{len(shard_candidates)}:{proxy_fingerprint(proxy)}",
                }
            )
        if sum(item["summary"]["preferred_asia"] for item in shard_candidates) != int(
            expected_shard.get("preferred_asia_count", 0)
        ):
            raise RuntimeError(f"shard {shard_index} preferred Asia count mismatch")
        candidates.extend(shard_candidates)

    if "source_count" in manifest and len(candidates) != int(manifest["source_count"]):
        raise RuntimeError("merged selection count does not match source_count")
    source_names = [str(item["source_name"]) for item in candidates]
    if len(source_names) != len(set(source_names)):
        raise RuntimeError("selection fragments contain duplicate source proxy names")
    return manifest, candidates


def _cache_busted_previous_source(source: str) -> str:
    if not source.startswith(("http://", "https://")):
        return source
    separator = "&" if "?" in source else "?"
    nonce = str(time.time_ns())
    return f"{source}{separator}previous_publication_check={nonce}"


def _read_previous_resource(
    source: str,
    *,
    label: str,
) -> bytes:
    checked_source = _cache_busted_previous_source(source)
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(
            checked_source,
            headers={
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "User-Agent": "aggregator-cnb-gmgn-publish/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise RuntimeError(
                    f"previous GMGN {label} is missing although the output branch exists; "
                    "refusing publication"
                ) from exc
            raise RuntimeError(
                f"cannot load previous GMGN {label}: HTTP {exc.code}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"cannot load previous GMGN {label}: {exc}") from exc

    path = Path(checked_source).resolve()
    if not path.is_file():
        raise RuntimeError(
            f"previous GMGN {label} is missing although the output branch exists: {path}"
        )
    try:
        return path.read_bytes()
    except Exception as exc:
        raise RuntimeError(f"cannot read previous GMGN {label}: {exc}") from exc


def empty_previous_profile() -> dict[str, Any]:
    return {
        "exists": False,
        "published_count": 0,
        "stable_fingerprints": set(),
        "observation_fingerprints": set(),
    }


def load_previous_profile(
    profile_source: str,
    status_source: str,
    *,
    previous_publication_exists: bool,
) -> dict[str, Any]:
    if not isinstance(previous_publication_exists, bool):
        raise RuntimeError("previous publication existence must be a boolean")
    if not previous_publication_exists:
        return empty_previous_profile()
    if not profile_source or not status_source:
        raise RuntimeError(
            "existing GMGN publication requires both previous profile and status sources"
        )

    status_content = _read_previous_resource(status_source, label="status")
    profile_content = _read_previous_resource(profile_source, label="profile")

    try:
        previous_status = json.loads(status_content.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise RuntimeError(f"previous GMGN status is invalid JSON: {exc}") from exc
    if not isinstance(previous_status, dict):
        raise RuntimeError("previous GMGN status must be a JSON object")
    if previous_status.get("kind") != "cnb-gmgn-publish-status":
        raise RuntimeError("previous GMGN status has an unsupported kind")
    if previous_status.get("schema_version") != PUBLISH_SCHEMA_VERSION:
        raise RuntimeError("previous GMGN status has an unsupported schema")
    expected_profile_sha256 = str(
        previous_status.get("profile_sha256") or ""
    ).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_profile_sha256):
        raise RuntimeError("previous GMGN status has a malformed profile SHA-256")
    actual_profile_sha256 = hashlib.sha256(profile_content).hexdigest()
    if actual_profile_sha256 != expected_profile_sha256:
        raise RuntimeError(
            "previous GMGN profile SHA-256 does not match its status; refusing publication"
        )
    expected_published_count = non_negative_int(
        previous_status.get("published_count"), "previous published_count"
    )
    if expected_published_count < 1:
        raise RuntimeError("previous GMGN status contains no published proxies")

    try:
        profile = yaml.safe_load(profile_content.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise RuntimeError(f"previous GMGN profile is invalid YAML: {exc}") from exc
    if not isinstance(profile, dict):
        raise RuntimeError("previous GMGN profile must be a YAML mapping")
    proxies = profile.get("proxies")
    groups = profile.get("proxy-groups")
    if not isinstance(proxies, list) or not proxies or not all(
        isinstance(proxy, dict) for proxy in proxies
    ):
        raise RuntimeError("previous GMGN profile contains no valid proxies")
    if not isinstance(groups, list):
        raise RuntimeError("previous GMGN profile contains no proxy groups")
    if len(proxies) != expected_published_count:
        raise RuntimeError(
            "previous GMGN profile proxy count does not match its status; refusing publication"
        )

    proxies_by_name: dict[str, dict[str, Any]] = {}
    for proxy in proxies:
        name = str(proxy.get("name") or "")
        if not name or name in proxies_by_name:
            raise RuntimeError("previous GMGN profile has missing or duplicate proxy names")
        proxies_by_name[name] = proxy
    groups_by_name: dict[str, dict[str, Any]] = {}
    for group in groups:
        if not isinstance(group, dict) or not group.get("name"):
            continue
        name = str(group["name"])
        if name in groups_by_name:
            raise RuntimeError("previous GMGN profile has duplicate group names")
        groups_by_name[name] = group
    for required in (GROUP_STABLE, GROUP_OBSERVATION):
        if required not in groups_by_name:
            raise RuntimeError(f"previous GMGN profile is missing group {required}")

    def member_fingerprints(group_name: str) -> set[str]:
        members = groups_by_name[group_name].get("proxies")
        if not isinstance(members, list):
            raise RuntimeError(f"previous group {group_name} has invalid members")
        fingerprints: set[str] = set()
        for raw_name in members:
            name = str(raw_name)
            if name in BUILTIN_PROXY_NAMES or name in groups_by_name:
                continue
            if name not in proxies_by_name:
                raise RuntimeError(
                    f"previous group {group_name} references a missing proxy"
                )
            fingerprints.add(proxy_fingerprint(proxies_by_name[name]))
        return fingerprints

    return {
        "exists": True,
        "published_count": expected_published_count,
        "stable_fingerprints": member_fingerprints(GROUP_STABLE),
        "observation_fingerprints": member_fingerprints(GROUP_OBSERVATION),
    }


def candidate_sort_key(candidate: dict[str, Any]) -> tuple[Any, ...]:
    summary = candidate["summary"]

    def metric(name: str) -> float:
        value = summary.get(name)
        return float("inf") if value is None else float(value)

    return (
        -int(summary["within_limit_count"]),
        -int(summary["response_count"]),
        metric("p90_delay_ms"),
        metric("median_delay_ms"),
        metric("jitter_ms"),
        metric("min_delay_ms"),
        str(candidate["fingerprint"]),
    )


def candidate_identity(candidate: dict[str, Any]) -> str:
    return str(
        candidate.get("candidate_id")
        or f"{candidate.get('source_name', '')}\0{candidate.get('fingerprint', '')}"
    )


def select_candidates(
    candidates: list[dict[str, Any]],
    previous: dict[str, Any] | None = None,
    *,
    max_nodes: int = MAX_NODES,
) -> dict[str, Any]:
    if max_nodes < 1:
        raise ValueError("max_nodes must be positive")
    previous = previous or {
        "stable_fingerprints": set(),
        "observation_fingerprints": set(),
    }
    old_stable = set(previous.get("stable_fingerprints", set()))
    old_observation = set(previous.get("observation_fingerprints", set()))
    asia_core: list[dict[str, Any]] = []
    asia_flexible: list[dict[str, Any]] = []
    observation: list[dict[str, Any]] = []
    non_asia_eligible: list[dict[str, Any]] = []

    for candidate in candidates:
        summary = candidate["summary"]
        within = int(summary["within_limit_count"])
        first = int(summary["first_half_within_limit_count"])
        second = int(summary["second_half_within_limit_count"])
        if summary["preferred_asia"]:
            if within >= 14 and first >= 5 and second >= 5:
                item = copy.deepcopy(candidate)
                item["selection_tier"] = "asia-core"
                asia_core.append(item)
            elif (
                candidate["fingerprint"] in old_stable
                and candidate["fingerprint"] not in old_observation
                and 12 <= within <= 13
            ):
                item = copy.deepcopy(candidate)
                item["selection_tier"] = "asia-observation-retained"
                observation.append(item)
            elif 10 <= within <= 13:
                item = copy.deepcopy(candidate)
                item["selection_tier"] = "asia-flexible"
                asia_flexible.append(item)
        elif within >= 16:
            item = copy.deepcopy(candidate)
            item["selection_tier"] = "non-asia-strict"
            non_asia_eligible.append(item)

    asia_core.sort(key=candidate_sort_key)
    asia_flexible.sort(key=candidate_sort_key)
    observation.sort(key=candidate_sort_key)
    non_asia_eligible.sort(key=candidate_sort_key)

    selected_non_asia = list(non_asia_eligible[:NON_ASIA_BASE_LIMIT])
    for candidate in non_asia_eligible[NON_ASIA_BASE_LIMIT:]:
        summary = candidate["summary"]
        if int(summary["within_limit_count"]) >= 18:
            selected_non_asia.append(candidate)
            if len(selected_non_asia) >= NON_ASIA_MAX:
                break

    asia_capacity = max(max_nodes - len(selected_non_asia), 0)
    selected_asia_core = asia_core[:asia_capacity]
    remaining = max_nodes - len(selected_non_asia) - len(selected_asia_core)
    selected_observation = observation[: max(remaining, 0)]
    remaining -= len(selected_observation)
    selected_flexible = asia_flexible[: max(remaining, 0)]

    stable = sorted(selected_asia_core + selected_non_asia, key=candidate_sort_key)
    selected = stable + selected_observation + selected_flexible
    return {
        "selected": selected,
        "stable": stable,
        "asia_core": selected_asia_core,
        "asia_flexible": selected_flexible,
        "observation": selected_observation,
        "non_asia": selected_non_asia,
        "qualified_asia_core_count": len(asia_core),
        "qualified_asia_flexible_count": len(asia_flexible),
        "qualified_observation_count": len(observation),
        "qualified_non_asia_count": len(non_asia_eligible),
    }


def _assign_output_names(selected: list[dict[str, Any]]) -> None:
    used = set(PUBLISH_GROUP_NAMES) | set(BUILTIN_PROXY_NAMES)
    counters: dict[str, int] = {}
    for candidate in selected:
        proxy = candidate["proxy"]
        base = str(proxy.get("name") or "unnamed").strip() or "unnamed"
        name = base
        while name in used:
            counters[base] = counters.get(base, 1) + 1
            name = f"{base}-{counters[base]}"
        proxy["name"] = name
        candidate["output_name"] = name
        used.add(name)


def build_output_profile(selection: dict[str, Any]) -> dict[str, Any]:
    selected = copy.deepcopy(selection["selected"])
    _assign_output_names(selected)
    by_identity = {candidate_identity(item): item for item in selected}
    if len(by_identity) != len(selected):
        raise RuntimeError("selected candidates contain duplicate identities")

    def selected_names(items: Iterable[dict[str, Any]]) -> list[str]:
        return [
            str(by_identity[candidate_identity(item)]["output_name"])
            for item in items
            if candidate_identity(item) in by_identity
        ]

    stable_names = selected_names(selection["stable"])
    flexible_names = selected_names(selection["asia_flexible"])
    observation_names = selected_names(selection["observation"])
    all_names = [str(item["output_name"]) for item in selected]

    def nonempty(names: list[str]) -> list[str]:
        return names or ["DIRECT"]

    profile = {
        "mode": "rule",
        "log-level": "warning",
        "proxies": [copy.deepcopy(item["proxy"]) for item in selected],
        "proxy-groups": [
            {
                "name": GROUP_MANUAL,
                "type": "select",
                "proxies": [
                    GROUP_STABLE,
                    GROUP_ASIA_FLEXIBLE,
                    GROUP_OBSERVATION,
                    GROUP_AUTO,
                    *all_names,
                    "DIRECT",
                ],
            },
            {
                "name": GROUP_STABLE,
                "type": "select",
                "proxies": nonempty(stable_names),
            },
            {
                "name": GROUP_ASIA_FLEXIBLE,
                "type": "select",
                "proxies": nonempty(flexible_names),
            },
            {
                "name": GROUP_OBSERVATION,
                "type": "select",
                "proxies": nonempty(observation_names),
            },
            {
                "name": GROUP_AUTO,
                "type": "url-test",
                "proxies": all_names,
                "url": "https://gmgn.ai/",
                "interval": 300,
                "tolerance": 50,
                "lazy": True,
            },
        ],
        "rules": [f"MATCH,{GROUP_MANUAL}"],
    }
    return profile


def build_readme(status: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# CNB GMGN 优选订阅",
            "",
            "该订阅只使用 CNB 中国 Runner 对 `https://gmgn.ai/` 的 20 轮结果，",
            "不会混入旧 gstatic 订阅。只有单轮延迟不超过 1000 ms 才记为达标。",
            "",
            f"- 本轮发布：{status['published_count']} 个",
            f"- GMGN稳定：{status['published_stable_count']} 个",
            f"- 亚洲弹性：{status['published_asia_flexible_count']} 个",
            f"- GMGN观察保留：{status['published_observation_count']} 个",
            f"- 亚洲 / 非亚洲：{status['published_asia_count']} / {status['published_non_asia_count']}",
            f"- 期望容量：{DESIRED_CAPACITY}（只作诊断，不会为了凑数放宽门槛）",
            f"- 硬上限：{MAX_NODES}",
            "",
            "选拔规则：亚洲核心至少 14/20 且前后十轮各至少 5 次；亚洲弹性",
            "为 10–13/20。非亚洲前 10 个至少 16/20，",
            "第 11–20 个必须至少 18/20。上一版稳定亚洲节点只能获得一次",
            "观察保留标记，低于 10/20 永不保留。",
            "",
            "`GMGN自动` 使用 GMGN URL 实时选择；1000 ms 硬标准来自发布前的",
            "20 轮选拔。配置中未写未经当前 Mihomo 验证的组级 timeout 字段。",
            "",
            "地区分类仅依据节点名称/标记启发式判断，尚未验证真实出口地区。",
            "",
            f"订阅：{status.get('profile_url') or 'clash.yaml'}",
            "",
        ]
    )


def validate_history_identity_map(raw: Any) -> dict[str, Any]:
    """Validate the private precomputed-ID handoff consumed by the publisher."""

    required_fields = {
        "kind",
        "schema_version",
        "identity_key_version",
        "identity_epoch",
        "candidates",
    }
    if not isinstance(raw, Mapping) or set(raw) != required_fields:
        raise RuntimeError("history identity map fields are incomplete or unexpected")
    if (
        raw["kind"] != HISTORY_IDENTITY_MAP_KIND
        or raw["schema_version"] != HISTORY_IDENTITY_MAP_SCHEMA_VERSION
    ):
        raise RuntimeError("history identity map kind or schema is unsupported")
    key_version = validate_identity_version(
        raw["identity_key_version"], "identity_key_version"
    )
    epoch = validate_identity_version(raw["identity_epoch"], "identity_epoch")
    candidates = raw["candidates"]
    if not isinstance(candidates, Mapping):
        raise RuntimeError("history identity map candidates must be an object")
    normalized: dict[str, str] = {}
    bindings: list[tuple[str, str]] = []
    for raw_fingerprint, raw_candidate_id in candidates.items():
        fingerprint = validate_proxy_fingerprint(raw_fingerprint)
        candidate = validate_public_id(raw_candidate_id, "candidate")
        if fingerprint in normalized:
            raise RuntimeError("history identity map contains duplicate fingerprints")
        normalized[fingerprint] = candidate
        bindings.append((candidate, fingerprint))
    assert_unique_public_id_bindings(bindings)
    return {
        "kind": HISTORY_IDENTITY_MAP_KIND,
        "schema_version": HISTORY_IDENTITY_MAP_SCHEMA_VERSION,
        "identity_key_version": key_version,
        "identity_epoch": epoch,
        "candidates": normalized,
    }


def stage_history_adapter(
    *,
    enabled: bool,
    previous_history_path: str,
    staged_history_path: str,
    manifest: dict[str, Any],
    candidates: list[dict[str, Any]],
    selection: dict[str, Any],
    accepted_at: str,
    identity_map: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Default-off C3 bridge; C5 remains the authority that commits a bundle."""

    if not enabled:
        return None
    if not previous_history_path or not staged_history_path:
        raise RuntimeError(
            "enabled history adapter requires previous and staged history paths"
        )
    previous_path = Path(previous_history_path).resolve()
    staged_path = Path(staged_history_path).resolve()
    if previous_path == staged_path:
        raise RuntimeError("history adapter must not overwrite previous history")
    if identity_map is None:
        raise RuntimeError("enabled history adapter requires a precomputed identity map")
    identities = validate_history_identity_map(identity_map)
    previous = load_history(previous_path)
    if (
        identities["identity_key_version"] != previous["identity_key_version"]
        or identities["identity_epoch"] != previous["identity_epoch"]
    ):
        raise RuntimeError("history identity map version disagrees with previous history")

    selected_states = {
        str(item["fingerprint"]): {
            "asia-core": "asia_core",
            "asia-flexible": "asia_flexible",
            "asia-observation-retained": "asia_flexible",
            "non-asia-strict": "non_asia_stable",
        }[str(item["selection_tier"])]
        for item in selection["selected"]
    }
    measurements: dict[str, Any] = {}
    decisions: dict[str, Any] = {}
    source_events: dict[str, str] = {}
    seen_ids: set[str] = set()
    candidate_fingerprints = {
        validate_proxy_fingerprint(candidate.get("fingerprint")) for candidate in candidates
    }
    if set(identities["candidates"]) != candidate_fingerprints:
        raise RuntimeError("history identity map does not exactly cover candidates")
    for candidate in candidates:
        fingerprint = validate_proxy_fingerprint(candidate.get("fingerprint"))
        public_id = identities["candidates"][fingerprint]
        if public_id in seen_ids:
            raise RuntimeError("history adapter received duplicate canonical identities")
        seen_ids.add(public_id)
        selected_state = selected_states.get(fingerprint)
        preferred_asia = bool(candidate["summary"]["preferred_asia"])
        if not preferred_asia and selected_state is None:
            continue
        measurements[public_id] = copy.deepcopy(candidate["summary"])
        source_events[public_id] = "present"
        decisions[public_id] = {
            "is_asia": preferred_asia,
            "proposed_state": selected_state
            or ("asia_manual_candidate" if preferred_asia else "unknown_region"),
            "source_alias": str(candidate["source_name"]),
            "selected": selected_state is not None,
            "region_cache": None,
        }
    staged = reduce_history(
        previous,
        run_context={
            "run_id": manifest["run_id"],
            "source_sha256": manifest["source_sha256"],
            "accepted_at": accepted_at,
            "valid_run": True,
            "accepted": True,
            "identity_key_version": identities["identity_key_version"],
            "identity_epoch": identities["identity_epoch"],
            "selection_policy_version": previous["selection_policy_version"],
        },
        source_events=source_events,
        measurements=measurements,
        decisions=decisions,
    )
    write_history_atomic(staged_path, staged)
    return staged


def _private_v2_path(path: Path, *, label: str) -> Path:
    resolved = path.resolve()
    lowered = {part.casefold() for part in resolved.parts}
    if ".cnb-runtime" not in lowered or ".git" in lowered or any(
        part.startswith("public-cn") for part in lowered
    ):
        raise RuntimeError(
            f"{label} must stay in a private .cnb-runtime directory"
        )
    return resolved


def stage_selection_v2_adapter(
    *,
    enabled: bool,
    selection_input_path: str,
    output_dir: str,
    private_decisions_path: str = "",
) -> dict[str, Any] | None:
    """Default-off C4 bridge; C5 remains the transaction/publish owner."""

    if not enabled:
        return None
    if not selection_input_path or not output_dir:
        raise RuntimeError(
            "enabled V2 selection adapter requires input and output paths"
        )
    input_path = _private_v2_path(
        Path(selection_input_path), label="V2 selection input"
    )
    if not input_path.is_file():
        raise RuntimeError("V2 selection input does not exist")
    payload = validate_selection_input(load_json_mapping(input_path))
    result = select_candidates_v2(payload)
    destination = Path(output_dir).resolve()
    if ".git" in {part.casefold() for part in destination.parts}:
        raise RuntimeError("V2 selection output cannot be written inside .git")
    write_text_atomic(destination / "clash.yaml", render_selection_profile(result))
    write_json_atomic(destination / "status.json", public_selection_status(result))
    write_json_atomic(destination / "node-status.json", result["node_status"])
    if private_decisions_path:
        decisions_path = _private_v2_path(
            Path(private_decisions_path), label="V2 private selection decisions"
        )
        write_json_atomic(
            decisions_path,
            {
                "kind": "cnb-gmgn-staged-selection-decisions",
                "schema_version": 1,
                "run_id": result["run_id"],
                "source_sha256": result["source_sha256"],
                "identity_key_version": result["identity_key_version"],
                "identity_epoch": result["identity_epoch"],
                "selection_policy_version": result["selection_policy_version"],
                "decisions": result["history_decisions"],
            },
        )
        decisions_path.chmod(0o600)
    return result


def publish_gmgn(args: argparse.Namespace) -> int:
    manifest, candidates = load_selection_candidates(
        Path(args.manifest).resolve(),
        [Path(path).resolve() for path in args.fragments],
    )
    previous = load_previous_profile(
        str(getattr(args, "previous_profile", "") or ""),
        str(getattr(args, "previous_status", "") or ""),
        previous_publication_exists=getattr(
            args, "previous_publication_exists", None
        ),
    )
    selection = select_candidates(candidates, previous, max_nodes=MAX_NODES)
    previous_count = int(previous["published_count"])
    required_count = max(
        FIRST_PUBLISH_MINIMUM,
        math.ceil(previous_count * MIN_RETAIN_RATIO),
    )
    published_count = len(selection["selected"])
    if published_count < required_count:
        raise RuntimeError(
            f"only {published_count} GMGN-qualified proxies are selectable; "
            f"at least {required_count} are required; refusing to replace the last good profile"
        )

    output_profile = build_output_profile(selection)
    rendered, rejected = dump_clash_yaml(output_profile)
    if rejected:
        raise RuntimeError(
            f"output profile contains {len(rejected)} malformed REALITY proxies"
        )
    parsed = yaml.safe_load(rendered)
    if not isinstance(parsed, dict) or len(parsed.get("proxies", [])) != published_count:
        raise RuntimeError("rendered Clash profile failed validation")
    profile_sha256 = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    published_asia_count = sum(
        bool(item["summary"]["preferred_asia"]) for item in selection["selected"]
    )
    profile_url = str(getattr(args, "profile_url", "") or "")
    status = {
        "kind": "cnb-gmgn-publish-status",
        "schema_version": PUBLISH_SCHEMA_VERSION,
        "run_at": utc_now(),
        "run_id": manifest["run_id"],
        "prepared_at": str(manifest.get("prepared_at") or ""),
        "main_sha": manifest["main_sha"],
        "source_run_at": str(manifest.get("source_run_at") or ""),
        "source_age_seconds": int(manifest.get("source_age_seconds") or 0),
        "source_sha256": manifest["source_sha256"],
        "target_url": manifest["target_url"],
        "expected_status": manifest["expected_status"],
        "request_timeout_ms": manifest["request_timeout_ms"],
        "qualified_delay_ms": manifest["qualified_delay_ms"],
        "total_rounds": manifest["total_rounds"],
        "shard_count": manifest["shard_count"],
        "source_count": len(candidates),
        "source_asia_count": sum(
            bool(item["summary"]["preferred_asia"]) for item in candidates
        ),
        "runner": copy.deepcopy(manifest.get("runner") or {}),
        "region_classification": REGION_CLASSIFICATION,
        "desired_capacity": DESIRED_CAPACITY,
        "desired_capacity_reached": published_count >= DESIRED_CAPACITY,
        "desired_capacity_shortfall": max(DESIRED_CAPACITY - published_count, 0),
        "max_nodes": MAX_NODES,
        "non_asia_base_limit": NON_ASIA_BASE_LIMIT,
        "non_asia_max": NON_ASIA_MAX,
        "first_publish_minimum": FIRST_PUBLISH_MINIMUM,
        "minimum_retain_ratio": MIN_RETAIN_RATIO,
        "previous_profile_found": bool(previous["exists"]),
        "previous_published_count": previous_count,
        "required_count": required_count,
        "qualified_asia_core_count": selection["qualified_asia_core_count"],
        "qualified_asia_flexible_count": selection[
            "qualified_asia_flexible_count"
        ],
        "qualified_observation_count": selection["qualified_observation_count"],
        "qualified_non_asia_count": selection["qualified_non_asia_count"],
        "published_count": published_count,
        "published_stable_count": len(selection["stable"]),
        "published_asia_core_count": len(selection["asia_core"]),
        "published_asia_flexible_count": len(selection["asia_flexible"]),
        "published_observation_count": len(selection["observation"]),
        "published_asia_count": published_asia_count,
        "published_non_asia_count": published_count - published_asia_count,
        "policy": {
            "asia_core": {"minimum_within_limit": 14, "minimum_each_half": 5},
            "asia_flexible": {
                "minimum_within_limit": 10,
                "maximum_within_limit": 13,
            },
            "asia_observation_retention": {
                "minimum_within_limit": 12,
                "maximum_within_limit": 13,
                "maximum_consecutive_runs": 1,
            },
            "non_asia_base": {
                "minimum_within_limit": 16,
                "maximum_count": 10,
            },
            "non_asia_expansion": {
                "minimum_within_limit": 18,
                "maximum_total_count": 20,
            },
        },
        "profile_sha256": profile_sha256,
        "profile_url": profile_url,
    }
    readme = build_readme(status)

    history_adapter_enabled = bool(getattr(args, "history_adapter_enabled", False))
    history_identity_map_path = str(getattr(args, "history_identity_map", "") or "")
    history_identity_map = None
    if history_adapter_enabled:
        if not history_identity_map_path:
            raise RuntimeError(
                "enabled history adapter requires --history-identity-map"
            )
        history_identity_map = load_json_mapping(
            Path(history_identity_map_path).resolve()
        )
    stage_history_adapter(
        enabled=history_adapter_enabled,
        previous_history_path=str(getattr(args, "previous_history", "") or ""),
        staged_history_path=str(getattr(args, "staged_history", "") or ""),
        manifest=manifest,
        candidates=candidates,
        selection=selection,
        accepted_at=status["run_at"],
        identity_map=history_identity_map,
    )

    output_dir = Path(args.output_dir).resolve()
    write_text_atomic(output_dir / "clash.yaml", rendered)
    write_json_atomic(output_dir / "status.json", status)
    write_text_atomic(output_dir / "README.md", readme)
    stage_selection_v2_adapter(
        enabled=bool(getattr(args, "selection_v2_adapter_enabled", False)),
        selection_input_path=str(getattr(args, "selection_v2_input", "") or ""),
        output_dir=str(getattr(args, "selection_v2_output_dir", "") or ""),
        private_decisions_path=str(
            getattr(args, "selection_v2_private_decisions", "") or ""
        ),
    )
    print(
        f"Published {published_count} GMGN candidates: stable {len(selection['stable'])}, "
        f"Asia flexible {len(selection['asia_flexible'])}, observation "
        f"{len(selection['observation'])}."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--fragments", nargs="+", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--previous-profile", default="")
    parser.add_argument("--previous-status", default="")
    parser.add_argument(
        "--previous-publication-exists",
        required=True,
        type=boolean_argument,
        metavar="true|false",
    )
    parser.add_argument("--profile-url", default="")
    parser.add_argument(
        "--history-adapter-enabled",
        default=False,
        type=boolean_argument,
        metavar="true|false",
        help="stage history.json v1 without changing current selection or groups",
    )
    parser.add_argument("--previous-history", default="")
    parser.add_argument("--staged-history", default="")
    parser.add_argument(
        "--history-identity-map",
        default="",
        help="private precomputed candidate-ID map from the controlled identity stage",
    )
    parser.add_argument(
        "--selection-v2-adapter-enabled",
        default=False,
        type=boolean_argument,
        metavar="true|false",
        help="stage the independent V2 ten-group bundle; disabled by default",
    )
    parser.add_argument("--selection-v2-input", default="")
    parser.add_argument("--selection-v2-output-dir", default="")
    parser.add_argument("--selection-v2-private-decisions", default="")
    return parser


def main(argv: list[str] | None = None) -> int:
    return publish_gmgn(build_parser().parse_args(argv))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
