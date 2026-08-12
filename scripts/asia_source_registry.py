#!/usr/bin/env python3
"""Controlled external Asia source registry, validation, and capacity limits.

The collection path and the read-only evaluator both consume this module.  It
delegates proxy syntax, endpoint safety, region hints, and identity derivation
to the existing C1/C3 owners instead of maintaining parallel implementations.
"""

from __future__ import annotations

import copy
import heapq
import json
import math
import os
import sys
import urllib.parse
import urllib.request
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scripts.candidate_sources import (
    EndpointSafetyError,
    safe_source_descriptor,
    utc_timestamp,
    validate_proxy_endpoint,
)
from scripts.gmgn_measurement import (
    DEFAULT_WORKERS,
    MINIMUM_OBSERVATION_WINDOW_SECONDS,
    REQUEST_TIMEOUT_MS,
    SHARD_COUNT,
    SHARD_STAGGER_SECONDS,
    TOTAL_ROUNDS,
)
from scripts.proxy_identity import (
    IdentityError,
    IdentitySettings,
    canonical_endpoint,
    canonical_proxy_fingerprint,
    compute_public_ids,
)
from subscribe.asia import preferred_asia_include_pattern, preferred_asia_region_hints


REGION_ORDER = ("HK", "JP", "KR", "SG", "TW")
SOURCE_MAX_CANDIDATES = 300
REGION_MAX_CANDIDATES = 100
ENDPOINT_MAX_VARIANTS = 3
TOTAL_CANDIDATE_HARD_LIMIT = 5000
SOURCE_FRESHNESS_SECONDS = 72 * 60 * 60
DELAY_REQUEST_OVERHEAD_SECONDS = 1.0
REGION_LOOKUP_TIMEOUT_SECONDS = 5.0
CONTROLLER_SELECTION_TIMEOUT_SECONDS = 1.0
DIRECT_PROBE_TIMEOUT_SECONDS = 5.0
DIRECT_PROBES_PER_ROUND = 3
CONTROLLER_HEALTH_TIMEOUT_SECONDS = 1.5
CONTROLLER_CHECKS_PER_ROUND = 2
MIHOMO_STARTUP_TIMEOUT_SECONDS = 30.0
RUNTIME_FIXED_HEADROOM_SECONDS = 60.0
MAX_ESTIMATED_RUNTIME_SECONDS = 15_000
SOURCE_POLICY_VERSION = "asia-source-expansion-v1"


class AsiaSourceError(ValueError):
    """Raised when an external source cannot be evaluated or admitted safely."""


@dataclass(frozen=True)
class AsiaSourceSpec:
    key: str
    task_name: str
    repository: str
    artifact_path: str
    feature_flag: str
    transparency_level: str
    transparency_passed: bool
    transparency_notes: tuple[str, ...]
    reservoir_only: bool = False
    production_approved: bool = False
    max_candidates: int = SOURCE_MAX_CANDIDATES
    max_per_region: int = REGION_MAX_CANDIDATES
    max_per_endpoint: int = ENDPOINT_MAX_VARIANTS
    freshness_seconds: int = SOURCE_FRESHNESS_SECONDS

    @property
    def artifact_url(self) -> str:
        return (
            f"https://raw.githubusercontent.com/{self.repository}/"
            f"{self.default_branch}/{self.artifact_path}"
        )

    @property
    def commits_api_url(self) -> str:
        encoded_path = urllib.parse.quote(self.artifact_path, safe="/")
        return (
            f"https://api.github.com/repos/{self.repository}/commits"
            f"?path={encoded_path}&per_page=1"
        )

    @property
    def default_branch(self) -> str:
        # Both approved MVP sources currently publish from master. Keeping the
        # branch in the registry makes a future upstream migration explicit.
        return "master"


SOURCE_REGISTRY: dict[str, AsiaSourceSpec] = {
    "awesome-vpn": AsiaSourceSpec(
        key="awesome-vpn",
        task_name="asia-awesome-vpn",
        repository="awesome-vpn/awesome-vpn",
        artifact_path="clash.yaml",
        feature_flag="ENABLE_ASIA_SOURCE_AWESOME_VPN",
        transparency_level="public-generation-and-validation",
        transparency_passed=True,
        transparency_notes=(
            "public generator and tests are present",
            "region labels use GeoLite data",
            "published nodes are checked through sing-box",
            "upstream discovery inputs are repository secrets",
        ),
        production_approved=True,
    ),
    "mahdibland-asia-limited": AsiaSourceSpec(
        key="mahdibland-asia-limited",
        task_name="asia-mahdibland-limited",
        repository="mahdibland/V2RayAggregator",
        artifact_path="Eternity.yml",
        feature_flag="ENABLE_ASIA_SOURCE_MAHDIBLAND",
        transparency_level="public-generation-and-speed-filter",
        transparency_passed=True,
        transparency_notes=(
            "public aggregation and filtering code is present",
            "the selected artifact is the filtered Eternity profile",
            "GitHub-runner speed does not replace CNB GMGN validation",
        ),
    ),
}


@dataclass(frozen=True)
class SourceCandidate:
    proxy: dict[str, Any]
    fingerprint: str
    endpoint: str
    candidate_id: str
    endpoint_id: str
    region: str
    protocol: str


@dataclass(frozen=True)
class SourceSelection:
    selected: tuple[dict[str, Any], ...]
    candidates: tuple[SourceCandidate, ...]
    selected_candidates: tuple[SourceCandidate, ...]
    report: dict[str, Any]


def source_spec(source_key: str) -> AsiaSourceSpec:
    try:
        return SOURCE_REGISTRY[str(source_key or "").strip()]
    except KeyError as exc:
        raise AsiaSourceError("external Asia source is not registered") from exc


def _enabled(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _candidate_v2_enabled(environment: Mapping[str, str]) -> bool:
    """Require the parent candidate contract before any external source is active."""

    return _enabled(
        environment.get(
            "ENABLE_CANDIDATE_V2",
            environment.get("ENABLE_GITHUB_CANDIDATE_V2", "false"),
        )
    )


def external_asia_domains(environment: Mapping[str, str] | None = None) -> list[dict[str, Any]]:
    """Return independently reversible crawler tasks; every flag defaults off."""

    env = os.environ if environment is None else environment
    candidate_v2_enabled = _candidate_v2_enabled(env)
    include = preferred_asia_include_pattern()
    domains: list[dict[str, Any]] = []
    for spec in SOURCE_REGISTRY.values():
        if not spec.production_approved:
            continue
        domains.append(
            {
                "name": spec.task_name,
                "sub": [spec.artifact_url],
                "enable": candidate_v2_enabled and _enabled(env.get(spec.feature_flag, "false")),
                "rename": "^#@&#@ASIA-KEEP ",
                "include": include,
                "exclude": "",
                "push_to": ["crawler"],
                "ignorede": True,
                "liveness": False,
                "publish_derivatives": True,
                "rate": 20.0,
                "secure": False,
                "candidate_source": spec.key,
            }
        )
    return domains


def _clash_module() -> Any:
    subscribe_dir = str(Path(__file__).resolve().parents[1] / "subscribe")
    if subscribe_dir not in sys.path:
        sys.path.insert(0, subscribe_dir)
    import clash  # type: ignore

    return clash


def validate_proxy_config(proxy: Mapping[str, Any]) -> dict[str, Any]:
    """Use the production Clash/Mihomo allowlist and normalization in C1."""

    if not isinstance(proxy, Mapping):
        raise AsiaSourceError("source proxy must be a mapping")
    candidate = copy.deepcopy(dict(proxy))
    try:
        valid = _clash_module().verify(candidate, mihomo=True)
    except Exception as exc:
        raise AsiaSourceError("source proxy configuration validation failed") from exc
    if not valid:
        raise AsiaSourceError("source proxy configuration validation failed")
    return candidate


def _proxy_sort_key(proxy: Mapping[str, Any]) -> str:
    return json.dumps(
        dict(proxy),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _candidate_record(
    proxy: Mapping[str, Any],
    *,
    settings: IdentitySettings | None,
) -> SourceCandidate:
    hints = preferred_asia_region_hints(proxy)
    if not hints:
        raise AsiaSourceError("source proxy has no target Asia region hint")
    region = next(region for region in REGION_ORDER if region in hints)
    fingerprint = canonical_proxy_fingerprint(proxy)
    endpoint = canonical_endpoint(proxy.get("server"), proxy.get("port"))
    public_ids = (
        compute_public_ids(
            proxy,
            key=settings.key,
            identity_key_version=settings.identity_key_version,
            identity_epoch=settings.identity_epoch,
        )
        if settings is not None
        else {"candidate_id": fingerprint, "endpoint_id": endpoint}
    )
    return SourceCandidate(
        proxy=copy.deepcopy(dict(proxy)),
        fingerprint=fingerprint,
        endpoint=endpoint,
        candidate_id=public_ids["candidate_id"],
        endpoint_id=public_ids["endpoint_id"],
        region=region,
        protocol=str(proxy.get("type", "")).strip().lower(),
    )


def _validate_endpoints(
    proxies: Sequence[dict[str, Any]],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None,
    checked_at: datetime | str | None,
    workers: int,
) -> tuple[set[str], int]:
    by_endpoint: dict[str, dict[str, Any]] = {}
    for proxy in proxies:
        try:
            endpoint = canonical_endpoint(proxy.get("server"), proxy.get("port"))
        except IdentityError:
            continue
        by_endpoint.setdefault(endpoint, proxy)

    safe: set[str] = set()
    failures = 0

    def check(item: tuple[str, dict[str, Any]]) -> tuple[str, bool]:
        endpoint, proxy = item
        try:
            validate_proxy_endpoint(proxy, resolver=resolver, checked_at=checked_at)
            return endpoint, True
        except EndpointSafetyError:
            return endpoint, False

    if resolver is not None or len(by_endpoint) <= 1:
        results = [check(item) for item in by_endpoint.items()]
    else:
        results = []
        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(by_endpoint)))) as executor:
            futures = {executor.submit(check, item): item[0] for item in by_endpoint.items()}
            for future in as_completed(futures):
                results.append(future.result())
    for endpoint, passed in results:
        if passed:
            safe.add(endpoint)
        else:
            failures += 1
    return safe, failures


def _deduplicate_candidates(candidates: Iterable[SourceCandidate]) -> list[SourceCandidate]:
    representatives: dict[str, SourceCandidate] = {}
    for candidate in candidates:
        previous = representatives.get(candidate.fingerprint)
        if previous is None or _proxy_sort_key(candidate.proxy) < _proxy_sort_key(previous.proxy):
            representatives[candidate.fingerprint] = candidate
    return [representatives[key] for key in sorted(representatives)]


def _apply_limits(
    candidates: Sequence[SourceCandidate],
    spec: AsiaSourceSpec,
    *,
    current_region_counts: Mapping[str, int] | None = None,
) -> tuple[list[SourceCandidate], Counter[str]]:
    """Balance regions deterministically while enforcing all three hard caps."""

    baseline = {region: max(int((current_region_counts or {}).get(region, 0)), 0) for region in REGION_ORDER}
    grouped: dict[str, list[SourceCandidate]] = {region: [] for region in REGION_ORDER}
    endpoint_sizes = Counter(candidate.endpoint for candidate in candidates)
    for candidate in candidates:
        grouped[candidate.region].append(candidate)
    for region in REGION_ORDER:
        grouped[region].sort(
            key=lambda item: (
                endpoint_sizes[item.endpoint],
                item.endpoint,
                item.fingerprint,
                _proxy_sort_key(item.proxy),
            )
        )

    positions = {region: 0 for region in REGION_ORDER}
    selected_by_region = Counter()
    selected_by_endpoint = Counter()
    selected: list[SourceCandidate] = []
    drops: Counter[str] = Counter()
    heap: list[tuple[int, int, str]] = []
    for index, region in enumerate(REGION_ORDER):
        if grouped[region]:
            heapq.heappush(heap, (baseline[region], index, region))

    while heap and len(selected) < spec.max_candidates:
        _, region_index, region = heapq.heappop(heap)
        items = grouped[region]
        while positions[region] < len(items):
            candidate = items[positions[region]]
            positions[region] += 1
            if selected_by_region[region] >= spec.max_per_region:
                drops["region_limit"] += 1
                continue
            if selected_by_endpoint[candidate.endpoint] >= spec.max_per_endpoint:
                drops["endpoint_limit"] += 1
                continue
            selected.append(candidate)
            selected_by_region[region] += 1
            selected_by_endpoint[candidate.endpoint] += 1
            break
        if selected_by_region[region] >= spec.max_per_region and positions[region] < len(items):
            drops["region_limit"] += len(items) - positions[region]
            positions[region] = len(items)
        elif positions[region] < len(items):
            heapq.heappush(
                heap,
                (baseline[region] + selected_by_region[region], region_index, region),
            )

    remaining = sum(len(grouped[region]) - positions[region] for region in REGION_ORDER)
    if remaining:
        drops["source_limit"] += remaining
    return selected, drops


def select_registered_source_candidates(
    source_key: str,
    proxies: Iterable[Mapping[str, Any]],
    *,
    settings: IdentitySettings | None = None,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    checked_at: datetime | str | None = None,
    current_region_counts: Mapping[str, int] | None = None,
    endpoint_workers: int = 32,
) -> SourceSelection:
    """Validate, identity-dedupe, and deterministically cap one source."""

    spec = source_spec(source_key)
    raw_items = [dict(item) for item in proxies if isinstance(item, Mapping)]
    errors: Counter[str] = Counter()
    valid_configs: list[dict[str, Any]] = []
    for raw in raw_items:
        try:
            candidate = validate_proxy_config(raw)
        except AsiaSourceError:
            errors["invalid_config"] += 1
            continue
        if not preferred_asia_region_hints(candidate):
            errors["non_target_region"] += 1
            continue
        valid_configs.append(candidate)

    safe_endpoints, endpoint_failures = _validate_endpoints(
        valid_configs,
        resolver=resolver,
        checked_at=checked_at,
        workers=endpoint_workers,
    )
    errors["unsafe_endpoint"] += endpoint_failures
    records: list[SourceCandidate] = []
    for proxy in valid_configs:
        try:
            endpoint = canonical_endpoint(proxy.get("server"), proxy.get("port"))
            if endpoint not in safe_endpoints:
                continue
            records.append(_candidate_record(proxy, settings=settings))
        except (AsiaSourceError, IdentityError):
            errors["identity_error"] += 1

    exact_unique = _deduplicate_candidates(records)
    errors["exact_duplicate"] += len(records) - len(exact_unique)
    selected, limit_drops = _apply_limits(
        exact_unique,
        spec,
        current_region_counts=current_region_counts,
    )
    errors.update(limit_drops)
    exact_regions = Counter(item.region for item in exact_unique)
    selected_regions = Counter(item.region for item in selected)
    protocols = Counter(item.protocol for item in exact_unique)
    report = {
        "source_policy_version": SOURCE_POLICY_VERSION,
        "raw_count": len(raw_items),
        "valid_count": len(valid_configs),
        "exact_unique_count": len(exact_unique),
        "unique_endpoint_count": len({item.endpoint for item in exact_unique}),
        "selected_count": len(selected),
        "region_counts": {region: exact_regions[region] for region in REGION_ORDER},
        "selected_region_counts": {region: selected_regions[region] for region in REGION_ORDER},
        "protocol_counts": dict(sorted(protocols.items())),
        "drop_reasons": {key: errors[key] for key in sorted(errors) if errors[key]},
        "limits": {
            "per_source": spec.max_candidates,
            "per_region": spec.max_per_region,
            "per_endpoint": spec.max_per_endpoint,
        },
    }
    return SourceSelection(
        selected=tuple(copy.deepcopy(item.proxy) for item in selected),
        candidates=tuple(exact_unique),
        selected_candidates=tuple(selected),
        report=report,
    )


def estimate_gmgn_capacity(
    candidate_count: int, *, workers_per_shard: int = DEFAULT_WORKERS
) -> dict[str, Any]:
    count = max(int(candidate_count), 0)
    workers = max(int(workers_per_shard), 1)
    largest_shard = math.ceil(count / SHARD_COUNT) if count else 0
    batches_per_round = math.ceil(largest_shard / workers) if largest_shard else 0
    delay_attempt_seconds = (
        REQUEST_TIMEOUT_MS / 1000.0 + DELAY_REQUEST_OVERHEAD_SECONDS
    )
    measurement_upper = batches_per_round * delay_attempt_seconds * TOTAL_ROUNDS
    direct_upper = (
        DIRECT_PROBES_PER_ROUND * DIRECT_PROBE_TIMEOUT_SECONDS * TOTAL_ROUNDS
    )
    health_upper = (
        CONTROLLER_CHECKS_PER_ROUND
        * CONTROLLER_HEALTH_TIMEOUT_SECONDS
        * TOTAL_ROUNDS
    )
    scheduled_upper = max(
        MINIMUM_OBSERVATION_WINDOW_SECONDS,
        measurement_upper + direct_upper + health_upper,
    )
    region_upper = largest_shard * (
        CONTROLLER_SELECTION_TIMEOUT_SECONDS + REGION_LOOKUP_TIMEOUT_SECONDS
    )
    egress_upper = 2 * DIRECT_PROBE_TIMEOUT_SECONDS
    estimated = (
        scheduled_upper
        + region_upper
        + egress_upper
        + MIHOMO_STARTUP_TIMEOUT_SECONDS
        + max(SHARD_STAGGER_SECONDS)
        + RUNTIME_FIXED_HEADROOM_SECONDS
    )
    return {
        "candidate_count": count,
        "shard_count": SHARD_COUNT,
        "workers_per_shard": workers,
        "rounds": TOTAL_ROUNDS,
        "request_timeout_ms": REQUEST_TIMEOUT_MS,
        "delay_attempt_upper_seconds": delay_attempt_seconds,
        "controller_selection_timeout_seconds": CONTROLLER_SELECTION_TIMEOUT_SECONDS,
        "region_lookup_timeout_seconds": REGION_LOOKUP_TIMEOUT_SECONDS,
        "minimum_observation_window_seconds": MINIMUM_OBSERVATION_WINDOW_SECONDS,
        "largest_shard_count": largest_shard,
        "worst_batches_per_round": batches_per_round,
        "measurement_upper_seconds": measurement_upper,
        "direct_probe_upper_seconds": direct_upper,
        "controller_health_upper_seconds": health_upper,
        "scheduled_upper_seconds": scheduled_upper,
        "region_lookup_upper_seconds": region_upper,
        "egress_probe_upper_seconds": egress_upper,
        "startup_upper_seconds": MIHOMO_STARTUP_TIMEOUT_SECONDS,
        "fixed_headroom_seconds": RUNTIME_FIXED_HEADROOM_SECONDS,
        "estimated_upper_seconds": estimated,
        "runtime_budget_seconds": MAX_ESTIMATED_RUNTIME_SECONDS,
        "within_runtime_budget": estimated <= MAX_ESTIMATED_RUNTIME_SECONDS,
        "below_candidate_hard_limit": count < TOTAL_CANDIDATE_HARD_LIMIT,
    }


def _parse_time(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise AsiaSourceError("source time must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AsiaSourceError("source time must include a timezone")
    return parsed.astimezone(timezone.utc)


def source_freshness(
    updated_at: datetime | str,
    *,
    evaluated_at: datetime | str | None = None,
    maximum_age_seconds: int = SOURCE_FRESHNESS_SECONDS,
) -> dict[str, Any]:
    updated = _parse_time(updated_at)
    evaluated = _parse_time(evaluated_at or datetime.now(timezone.utc))
    age_seconds = (evaluated - updated).total_seconds()
    return {
        "updated_at": utc_timestamp(updated),
        "evaluated_at": utc_timestamp(evaluated),
        "age_seconds": age_seconds,
        "maximum_age_seconds": int(maximum_age_seconds),
        "passed": -300 <= age_seconds <= int(maximum_age_seconds),
    }


def fetch_source_revision(
    spec: AsiaSourceSpec,
    *,
    token: str = "",
    timeout: float = 30.0,
) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "aggregator-source-audit"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(spec.commits_api_url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
    except Exception as exc:
        raise AsiaSourceError("source revision lookup failed") from exc
    if not isinstance(payload, list) or not payload or not isinstance(payload[0], Mapping):
        raise AsiaSourceError("source revision response is empty or malformed")
    first = payload[0]
    commit = first.get("commit") if isinstance(first.get("commit"), Mapping) else {}
    committer = commit.get("committer") if isinstance(commit.get("committer"), Mapping) else {}
    sha = str(first.get("sha", "")).strip().lower()
    updated_at = str(committer.get("date", "")).strip()
    if len(sha) != 40 or not updated_at:
        raise AsiaSourceError("source revision response lacks commit identity")
    return {"commit_sha": sha, "updated_at": utc_timestamp(updated_at)}


def evaluate_source_gain(
    source_key: str,
    source_proxies: Iterable[Mapping[str, Any]],
    current_proxies: Iterable[Mapping[str, Any]],
    *,
    source_updated_at: datetime | str,
    evaluated_at: datetime | str | None,
    settings: IdentitySettings,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
) -> dict[str, Any]:
    """Build the aggregate-only marginal-gain report used for admission."""

    spec = source_spec(source_key)
    current_records: dict[str, tuple[str, str]] = {}
    current_regions = Counter()
    for raw in current_proxies:
        if not isinstance(raw, Mapping):
            continue
        try:
            proxy = validate_proxy_config(raw)
            fingerprint = canonical_proxy_fingerprint(proxy)
            endpoint = canonical_endpoint(proxy.get("server"), proxy.get("port"))
            public_ids = compute_public_ids(
                proxy,
                key=settings.key,
                identity_key_version=settings.identity_key_version,
                identity_epoch=settings.identity_epoch,
            )
        except (AsiaSourceError, IdentityError):
            continue
        current_records[fingerprint] = (public_ids["candidate_id"], public_ids["endpoint_id"])
        hints = preferred_asia_region_hints(proxy)
        if hints:
            current_regions[next(region for region in REGION_ORDER if region in hints)] += 1

    selection = select_registered_source_candidates(
        source_key,
        source_proxies,
        settings=settings,
        resolver=resolver,
        checked_at=evaluated_at,
        current_region_counts=current_regions,
    )
    current_fingerprints = set(current_records)
    current_endpoint_ids = {value[1] for value in current_records.values()}
    source_fingerprints = {item.fingerprint for item in selection.candidates}
    source_endpoint_ids = {item.endpoint_id for item in selection.candidates}
    overlap_fingerprints = source_fingerprints & current_fingerprints
    overlap_endpoints = source_endpoint_ids & current_endpoint_ids
    selected_fingerprints = {item.fingerprint for item in selection.selected_candidates}
    new_candidates = [
        item
        for item in selection.selected_candidates
        if item.fingerprint not in current_fingerprints
    ]
    new_endpoint_items = [
        item
        for item in selection.selected_candidates
        if item.endpoint_id not in current_endpoint_ids
    ]
    new_endpoint_ids = {item.endpoint_id for item in new_endpoint_items}
    new_regions = sorted({item.region for item in new_endpoint_items}, key=REGION_ORDER.index)
    after_count = len(current_fingerprints | selected_fingerprints)
    capacity = estimate_gmgn_capacity(after_count)
    freshness = source_freshness(
        source_updated_at,
        evaluated_at=evaluated_at,
        maximum_age_seconds=spec.freshness_seconds,
    )
    overlap_rate = (
        len(overlap_endpoints) / len(source_endpoint_ids) if source_endpoint_ids else 1.0
    )
    reasons: list[str] = []
    if not freshness["passed"]:
        reasons.append("source_not_fresh")
    if len(new_endpoint_ids) < 5:
        reasons.append("fewer_than_5_new_target_endpoints")
    if len(new_regions) < 2:
        reasons.append("fewer_than_2_new_target_regions")
    if overlap_rate > 0.80:
        reasons.append("endpoint_overlap_above_80_percent")
    if not spec.transparency_passed or spec.reservoir_only:
        reasons.append("transparency_not_directly_publishable")
    if not capacity["below_candidate_hard_limit"]:
        reasons.append("candidate_hard_limit_reached")
    if not capacity["within_runtime_budget"]:
        reasons.append("gmgn_runtime_budget_exceeded")

    descriptor = safe_source_descriptor(
        spec.artifact_url,
        task_name=spec.task_name,
        publish_derivatives=True,
    )
    report = {
        "kind": "asia-source-evaluation",
        "schema_version": 1,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "source": {
            "key": spec.key,
            "source_id": descriptor["source_id"],
            "alias": descriptor["alias"],
            "repository": spec.repository,
            "artifact_path": spec.artifact_path,
            "feature_flag": spec.feature_flag,
            "feature_flag_default": False,
        },
        "evaluation_identity_key_version": settings.identity_key_version,
        "evaluation_identity_epoch": settings.identity_epoch,
        "freshness": freshness,
        "transparency": {
            "level": spec.transparency_level,
            "passed": spec.transparency_passed,
            "notes": list(spec.transparency_notes),
        },
        "counts": {
            **selection.report,
            "current_exact_unique_count": len(current_fingerprints),
            "overlap_fingerprint_count": len(overlap_fingerprints),
            "overlap_endpoint_count": len(overlap_endpoints),
            "new_exact_candidate_count": len(new_candidates),
            "new_unique_endpoint_count": len(new_endpoint_ids),
            "new_regions": new_regions,
            "endpoint_overlap_rate": overlap_rate,
            "candidate_count_after_merge": after_count,
        },
        "capacity": capacity,
        "gate": {"passed": not reasons, "reasons": reasons},
    }
    return report


def enforce_registered_source_policy(
    source_key: str,
    proxies: Iterable[Mapping[str, Any]],
    *,
    environment: Mapping[str, str] | None = None,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    now: datetime | str | None = None,
) -> SourceSelection:
    """Production collection boundary used before C1 provenance is staged."""

    env = os.environ if environment is None else environment
    spec = source_spec(source_key)
    if not spec.production_approved:
        raise AsiaSourceError("external Asia source has not passed the production admission gate")
    if not _candidate_v2_enabled(env):
        raise AsiaSourceError("candidate snapshot V2 is disabled")
    if not _enabled(env.get(spec.feature_flag, "false")):
        raise AsiaSourceError("external Asia source feature flag is disabled")
    revision = fetch_source_revision(spec, token=str(env.get("GH_TOKEN", "")))
    freshness = source_freshness(
        revision["updated_at"],
        evaluated_at=now,
        maximum_age_seconds=spec.freshness_seconds,
    )
    if not freshness["passed"]:
        raise AsiaSourceError("external Asia source artifact is stale")
    return select_registered_source_candidates(
        source_key,
        proxies,
        resolver=resolver,
        checked_at=now,
    )


__all__ = [
    "AsiaSourceError",
    "AsiaSourceSpec",
    "CONTROLLER_HEALTH_TIMEOUT_SECONDS",
    "CONTROLLER_SELECTION_TIMEOUT_SECONDS",
    "DELAY_REQUEST_OVERHEAD_SECONDS",
    "DIRECT_PROBE_TIMEOUT_SECONDS",
    "ENDPOINT_MAX_VARIANTS",
    "MAX_ESTIMATED_RUNTIME_SECONDS",
    "MIHOMO_STARTUP_TIMEOUT_SECONDS",
    "REGION_LOOKUP_TIMEOUT_SECONDS",
    "REGION_MAX_CANDIDATES",
    "REGION_ORDER",
    "SOURCE_FRESHNESS_SECONDS",
    "SOURCE_MAX_CANDIDATES",
    "SOURCE_POLICY_VERSION",
    "SOURCE_REGISTRY",
    "SourceCandidate",
    "SourceSelection",
    "TOTAL_CANDIDATE_HARD_LIMIT",
    "enforce_registered_source_policy",
    "estimate_gmgn_capacity",
    "evaluate_source_gain",
    "external_asia_domains",
    "fetch_source_revision",
    "select_registered_source_candidates",
    "source_freshness",
    "source_spec",
    "validate_proxy_config",
]
