#!/usr/bin/env python3
"""Sanitize Candidate V2 proxy endpoints before FC or Mihomo can access them."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.candidate_sources import (
    ENDPOINT_SAFETY_POLICY_VERSION,
    EndpointResolutionInfrastructureError,
    CandidateDnsResolutionSession,
    EndpointSafetyError,
    SOURCE_ID_RE,
    count_proxy_domain_hostnames,
    merge_provenance_staging,
    proxy_endpoint_safety_cache_key,
    validate_proxy_endpoint,
)
from scripts.candidate_handoff import CandidateHandoffError, write_private_bytes_atomic
from scripts.pipeline_utils import dump_clash_yaml, filtered_profile
from scripts.proxy_identity import (
    IdentityError,
    canonical_proxy_fingerprint,
)
from scripts.proxy_privacy import sanitize_public_proxy_alias, structured_proxy_name
from scripts.proxy_schema import ProxySchemaError, validate_proxy_schema


REGION_ORDER = ("HK", "JP", "KR", "SG", "TW")
ENDPOINT_SAFETY_EVIDENCE_KIND = "candidate-endpoint-safety-evidence"
ENDPOINT_SAFETY_EVIDENCE_SCHEMA_VERSION = 1
PROVENANCE_RECORD_FIELDS = frozenset(
    {
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
)
REGION_EVIDENCE_RE = re.compile(
    r"(?:name_hint|source_hint):(HK|JP|KR|SG|TW)|explicit:asia_keep"
)


class CandidateEndpointSanitizationError(ValueError):
    """Raised when the pre-network Candidate V2 staging cannot be trusted."""


def _dump_candidate_profile(profile: Mapping[str, Any]) -> tuple[str, list[str]]:
    """Serialize a private Candidate profile with a fixed redacted failure."""

    serialization_failed = False
    try:
        return dump_clash_yaml(dict(profile))
    except Exception:
        serialization_failed = True
    if serialization_failed:
        raise CandidateEndpointSanitizationError(
            "candidate profile serialization failed"
        )
    raise AssertionError("unreachable candidate serialization state")


@dataclass(frozen=True)
class SanitizedCandidateProfile:
    profile: dict[str, Any]
    raw_count: int
    safe_count: int
    quarantined_count: int
    invalid_count: int
    safe_fingerprints: tuple[str, ...]
    quarantined_fingerprints: tuple[str, ...]
    observation_bindings: tuple[tuple[str, str, tuple[str, ...], str], ...]


def _clash_module() -> Any:
    subscribe_dir = str(Path(__file__).resolve().parents[1] / "subscribe")
    if subscribe_dir not in sys.path:
        sys.path.insert(0, subscribe_dir)
    import clash  # type: ignore

    return clash


def _validated_proxy(proxy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(proxy, Mapping):
        raise CandidateEndpointSanitizationError("candidate proxy must be a mapping")
    if any(not isinstance(key, str) for key in proxy):
        raise CandidateEndpointSanitizationError(
            "candidate proxy contains a non-string field"
        )
    try:
        candidate = validate_proxy_schema(proxy)
    except ProxySchemaError as exc:
        raise CandidateEndpointSanitizationError(
            "candidate proxy schema is unsupported"
        ) from exc
    try:
        valid = _clash_module().verify(candidate, mihomo=True)
    except Exception as exc:
        raise CandidateEndpointSanitizationError(
            "candidate proxy validation failed"
        ) from exc
    if not valid:
        raise CandidateEndpointSanitizationError("candidate proxy validation failed")
    try:
        candidate = validate_proxy_schema(candidate)
        canonical_proxy_fingerprint(candidate)
    except (IdentityError, ProxySchemaError) as exc:
        raise CandidateEndpointSanitizationError(
            "candidate proxy fields cannot be canonicalized"
        ) from exc
    return candidate


def _validated_provenance_records(
    provenance: Mapping[str, Any],
) -> list[dict[str, Any]]:
    sources = provenance.get("sources") if isinstance(provenance, Mapping) else None
    records = provenance.get("records") if isinstance(provenance, Mapping) else None
    if not isinstance(sources, list) or not isinstance(records, list) or not records:
        raise CandidateEndpointSanitizationError(
            "candidate provenance contains no records"
        )

    source_ids: set[str] = set()
    for raw in sources:
        if not isinstance(raw, Mapping):
            raise CandidateEndpointSanitizationError(
                "candidate provenance source is malformed"
            )
        source_id = str(raw.get("source_id", ""))
        if not source_id or source_id in source_ids:
            raise CandidateEndpointSanitizationError(
                "candidate provenance source is malformed"
            )
        source_ids.add(source_id)

    normalized: list[dict[str, Any]] = []
    for raw in records:
        if not isinstance(raw, Mapping) or set(raw) != PROVENANCE_RECORD_FIELDS:
            raise CandidateEndpointSanitizationError(
                "candidate provenance record is malformed"
            )
        if raw.get("source_id") not in source_ids or not isinstance(
            raw.get("proxy"), Mapping
        ):
            raise CandidateEndpointSanitizationError(
                "candidate provenance record source binding is invalid"
            )
        region_hints = raw.get("region_hints")
        region_evidence = raw.get("region_evidence")
        if (
            not isinstance(region_hints, list)
            or any(region not in REGION_ORDER for region in region_hints)
            or region_hints
            != sorted(set(region_hints), key=REGION_ORDER.index)
            or not isinstance(region_evidence, list)
            or any(
                not isinstance(value, str)
                or REGION_EVIDENCE_RE.fullmatch(value) is None
                for value in region_evidence
            )
            or region_evidence != sorted(set(region_evidence))
        ):
            raise CandidateEndpointSanitizationError(
                "candidate provenance region evidence is malformed"
            )
        normalized.append(dict(raw))
    return normalized


def _safe_alias(value: Any, proxy: Mapping[str, Any]) -> str:
    return sanitize_public_proxy_alias(value, proxy, max_length=64)


def _rebuilt_name_base(
    *, proxy: Mapping[str, Any], aliases: Iterable[str], region_hints: Iterable[str], protected_asia: bool
) -> str:
    alias = next(iter(sorted({value for value in aliases if value})), "")
    if alias:
        prefix = structured_proxy_name(
            region_hints=region_hints,
            protocol="",
            protected_asia=protected_asia,
        ).removesuffix(" NODE")
        return f"{prefix} {alias}"[:96].rstrip()
    return structured_proxy_name(
        region_hints=region_hints,
        protocol=proxy.get("type", ""),
        protected_asia=protected_asia,
    )


def _choose_rebuilt_names(
    safe: Mapping[str, Mapping[str, Any]], ordered_fingerprints: list[str]
) -> dict[str, str]:
    bases = {
        fingerprint: _rebuilt_name_base(
            proxy=safe[fingerprint]["proxy"],
            aliases=safe[fingerprint]["aliases"],
            region_hints=safe[fingerprint]["region_hints"],
            protected_asia=bool(safe[fingerprint]["protected_asia"]),
        )
        for fingerprint in ordered_fingerprints
    }
    members_by_base: dict[str, list[str]] = {}
    for fingerprint in ordered_fingerprints:
        members_by_base.setdefault(bases[fingerprint], []).append(fingerprint)

    chosen: dict[str, str] = {}
    used: set[str] = set()
    for fingerprint in ordered_fingerprints:
        base = bases[fingerprint]
        members = members_by_base[base]
        name = base
        if len(members) > 1:
            name = f"{base} {members.index(fingerprint) + 1}"
        while name in used:
            name = f"{name} X"
        chosen[fingerprint] = name
        used.add(name)
    return chosen


def rebuild_candidate_profile(
    provenance: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> SanitizedCandidateProfile:
    """Build the V2 pre-network profile from exact collection provenance.

    The legacy collect/process outputs pass through another subconverter run,
    which may normalize or discard connection fields after provenance was
    recorded.  Candidate V2 therefore reconstructs the broad profile from the
    validated private records themselves instead of trying to reconcile those
    transformed outputs by name or endpoint.
    """

    records = _validated_provenance_records(provenance)
    observations: dict[str, dict[str, Any]] = {}
    observation_rows: list[tuple[str, str, tuple[str, ...]]] = []
    invalid_count = 0
    for raw in records:
        try:
            proxy = _validated_proxy(raw["proxy"])
            fingerprint = canonical_proxy_fingerprint(proxy)
        except (CandidateEndpointSanitizationError, IdentityError):
            invalid_count += 1
            continue
        observation_rows.append(
            (
                fingerprint,
                str(raw["source_id"]),
                tuple(raw["region_hints"]),
            )
        )

        entry = observations.get(fingerprint)
        if entry is None:
            observations[fingerprint] = {
                "proxy": proxy,
                "aliases": {_safe_alias(raw["alias"], proxy)} - {""},
                "region_hints": set(raw["region_hints"]),
                "protected_asia": bool(
                    raw["region_hints"]
                    or "explicit:asia_keep" in raw["region_evidence"]
                ),
            }
            continue
        entry["aliases"].add(_safe_alias(raw["alias"], proxy))
        entry["aliases"].discard("")
        entry["region_hints"].update(raw["region_hints"])
        entry["protected_asia"] = bool(
            entry["protected_asia"]
            or raw["region_hints"]
            or "explicit:asia_keep" in raw["region_evidence"]
        )

    session = CandidateDnsResolutionSession(
        expected_domain_hostnames=count_proxy_domain_hostnames(
            entry["proxy"] for entry in observations.values()
        ),
        resolver=resolver,
        sleeper=sleeper,
    )
    endpoint_cache: dict[tuple[str, int, str], dict[str, Any] | EndpointSafetyError] = {}
    safe: dict[str, dict[str, Any]] = {}
    quarantined: set[str] = set()
    for fingerprint in sorted(observations):
        entry = observations[fingerprint]
        proxy = entry["proxy"]
        try:
            endpoint = proxy_endpoint_safety_cache_key(proxy)
        except EndpointSafetyError:
            quarantined.add(fingerprint)
            continue
        if endpoint not in endpoint_cache:
            try:
                endpoint_cache[endpoint] = validate_proxy_endpoint(
                    proxy,
                    resolver=session.resolve,
                )
            except EndpointSafetyError as exc:
                endpoint_cache[endpoint] = exc
        if isinstance(endpoint_cache[endpoint], EndpointSafetyError):
            quarantined.add(fingerprint)
            continue
        safe[fingerprint] = entry

    session.finalize()

    if not safe:
        raise CandidateEndpointSanitizationError(
            "candidate provenance rebuild retained no safe proxies"
        )

    ordered_fingerprints = sorted(
        safe,
        key=lambda fingerprint: (
            min(
                (
                    REGION_ORDER.index(region)
                    for region in safe[fingerprint]["region_hints"]
                ),
                default=len(REGION_ORDER),
            ),
            str(safe[fingerprint]["proxy"].get("type", "")),
            fingerprint,
        ),
    )
    names = _choose_rebuilt_names(safe, ordered_fingerprints)
    proxies: list[dict[str, Any]] = []
    for fingerprint in ordered_fingerprints:
        entry = safe[fingerprint]
        proxy = copy.deepcopy(entry["proxy"])
        proxy["name"] = names[fingerprint]
        proxies.append(proxy)

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

    text, rejected = _dump_candidate_profile(profile)
    if rejected:
        raise CandidateEndpointSanitizationError(
            "candidate provenance rebuild contains invalid REALITY short IDs"
        )
    try:
        round_trip = yaml.safe_load(text)
        round_trip_proxies = round_trip["proxies"]
        round_trip_fingerprints = {
            canonical_proxy_fingerprint(_validated_proxy(proxy))
            for proxy in round_trip_proxies
        }
        round_trip_names = [str(proxy["name"]) for proxy in round_trip_proxies]
    except Exception:
        raise CandidateEndpointSanitizationError(
            "candidate provenance rebuild cannot be parsed"
        ) from None
    if (
        len(round_trip_proxies) != len(safe)
        or round_trip_fingerprints != set(safe)
        or len(round_trip_names) != len(set(round_trip_names))
    ):
        raise CandidateEndpointSanitizationError(
            "candidate provenance rebuild failed its round-trip contract"
        )

    return SanitizedCandidateProfile(
        profile=round_trip,
        raw_count=len(records),
        safe_count=len(safe),
        quarantined_count=len(quarantined),
        invalid_count=invalid_count,
        safe_fingerprints=tuple(sorted(safe)),
        quarantined_fingerprints=tuple(sorted(quarantined)),
        observation_bindings=tuple(
            sorted(
                (*row, "safe" if row[0] in safe else "quarantined")
                for row in observation_rows
            )
        ),
    )


def sanitize_candidate_profile(
    profile: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> SanitizedCandidateProfile:
    if not isinstance(profile, Mapping):
        raise CandidateEndpointSanitizationError("candidate profile must be a mapping")
    raw_proxies = profile.get("proxies")
    records = provenance.get("records") if isinstance(provenance, Mapping) else None
    if not isinstance(raw_proxies, list) or not raw_proxies:
        raise CandidateEndpointSanitizationError("candidate profile contains no proxies")
    if not isinstance(records, list) or not records:
        raise CandidateEndpointSanitizationError("candidate provenance contains no records")

    provenance_fingerprints: set[str] = set()
    observation_rows: list[tuple[str, str, tuple[str, ...]]] = []
    for raw in records:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("proxy"), Mapping):
            raise CandidateEndpointSanitizationError(
                "candidate provenance record is malformed"
            )
        try:
            fingerprint = canonical_proxy_fingerprint(_validated_proxy(raw["proxy"]))
            provenance_fingerprints.add(fingerprint)
            observation_rows.append(
                (
                    fingerprint,
                    str(raw.get("source_id", "")),
                    tuple(raw.get("region_hints", [])),
                )
            )
        except (CandidateEndpointSanitizationError, IdentityError):
            continue

    session = CandidateDnsResolutionSession(
        expected_domain_hostnames=count_proxy_domain_hostnames(
            proxy for proxy in raw_proxies if isinstance(proxy, Mapping)
        ),
        resolver=resolver,
        sleeper=sleeper,
    )
    safe_by_fingerprint: dict[str, dict[str, Any]] = {}
    quarantined_fingerprints: set[str] = set()
    invalid_count = 0
    quarantined_count = 0
    endpoint_cache: dict[tuple[str, int, str], dict[str, Any] | EndpointSafetyError] = {}
    for raw_proxy in raw_proxies:
        try:
            proxy = _validated_proxy(raw_proxy)
            fingerprint = canonical_proxy_fingerprint(proxy)
        except (CandidateEndpointSanitizationError, IdentityError):
            invalid_count += 1
            continue
        if fingerprint not in provenance_fingerprints:
            raise CandidateEndpointSanitizationError(
                "candidate profile is not covered by collection provenance"
            )
        try:
            endpoint = proxy_endpoint_safety_cache_key(proxy)
        except EndpointSafetyError:
            quarantined_count += 1
            quarantined_fingerprints.add(fingerprint)
            continue
        if endpoint not in endpoint_cache:
            try:
                endpoint_cache[endpoint] = validate_proxy_endpoint(
                    proxy,
                    resolver=session.resolve,
                )
            except EndpointSafetyError as exc:
                endpoint_cache[endpoint] = exc
        endpoint_result = endpoint_cache[endpoint]
        if isinstance(endpoint_result, EndpointSafetyError):
            quarantined_count += 1
            quarantined_fingerprints.add(fingerprint)
            continue
        safe_by_fingerprint.setdefault(fingerprint, proxy)

    session.finalize()

    if not safe_by_fingerprint:
        raise CandidateEndpointSanitizationError(
            "candidate endpoint sanitization retained no safe proxies"
        )
    sanitized = filtered_profile(dict(profile), safe_by_fingerprint.values())
    return SanitizedCandidateProfile(
        profile=sanitized,
        raw_count=len(raw_proxies),
        safe_count=len(safe_by_fingerprint),
        quarantined_count=quarantined_count,
        invalid_count=invalid_count,
        safe_fingerprints=tuple(sorted(safe_by_fingerprint)),
        quarantined_fingerprints=tuple(sorted(quarantined_fingerprints)),
        observation_bindings=tuple(
            sorted(
                (*row, "safe" if row[0] in safe_by_fingerprint else "quarantined")
                for row in observation_rows
            )
        ),
    )


def _json_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def build_endpoint_safety_evidence(
    result: SanitizedCandidateProfile,
    *,
    profile_bytes: bytes,
    provenance: Mapping[str, Any],
) -> dict[str, Any]:
    """Bind the sanitizer's private DNS classification to exact stage inputs."""

    evidence = {
        "kind": ENDPOINT_SAFETY_EVIDENCE_KIND,
        "schema_version": ENDPOINT_SAFETY_EVIDENCE_SCHEMA_VERSION,
        "endpoint_safety_policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
        "profile_sha256": hashlib.sha256(profile_bytes).hexdigest(),
        "provenance_sha256": hashlib.sha256(_json_bytes(dict(provenance))).hexdigest(),
        "raw_count": result.raw_count,
        "safe_fingerprints": list(result.safe_fingerprints),
        "quarantined_fingerprints": list(result.quarantined_fingerprints),
        "observation_bindings": [
            {
                "fingerprint": fingerprint,
                "source_id": source_id,
                "region_hints": list(region_hints),
                "classification": classification,
            }
            for fingerprint, source_id, region_hints, classification in result.observation_bindings
        ],
        "invalid_count": result.invalid_count,
    }
    validate_endpoint_safety_evidence(evidence)
    return evidence


def validate_endpoint_safety_evidence(value: Mapping[str, Any]) -> dict[str, Any]:
    fields = {
        "kind",
        "schema_version",
        "endpoint_safety_policy_version",
        "profile_sha256",
        "provenance_sha256",
        "raw_count",
        "safe_fingerprints",
        "quarantined_fingerprints",
        "observation_bindings",
        "invalid_count",
    }
    if not isinstance(value, Mapping) or set(value) != fields:
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence fields are invalid"
        )
    if (
        value["kind"] != ENDPOINT_SAFETY_EVIDENCE_KIND
        or value["schema_version"] != ENDPOINT_SAFETY_EVIDENCE_SCHEMA_VERSION
        or value["endpoint_safety_policy_version"] != ENDPOINT_SAFETY_POLICY_VERSION
    ):
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence version is unsupported"
        )
    for field in ("profile_sha256", "provenance_sha256"):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None:
            raise CandidateEndpointSanitizationError(
                "candidate endpoint safety evidence hash is invalid"
            )
    if any(
        not isinstance(value[field], int) or value[field] < 0
        for field in ("raw_count", "invalid_count")
    ):
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence count is invalid"
        )
    bindings: list[set[str]] = []
    for field in ("safe_fingerprints", "quarantined_fingerprints"):
        raw = value[field]
        if (
            not isinstance(raw, list)
            or raw != sorted(set(raw))
            or any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None for item in raw)
        ):
            raise CandidateEndpointSanitizationError(
                "candidate endpoint safety evidence fingerprints are invalid"
            )
        bindings.append(set(raw))
    if bindings[0] & bindings[1]:
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence classifications overlap"
        )
    raw_bindings = value["observation_bindings"]
    if not isinstance(raw_bindings, list):
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence observations are invalid"
        )
    normalized_bindings: list[tuple[str, str, tuple[str, ...], str]] = []
    for raw in raw_bindings:
        if not isinstance(raw, Mapping) or set(raw) != {
            "fingerprint",
            "source_id",
            "region_hints",
            "classification",
        }:
            raise CandidateEndpointSanitizationError(
                "candidate endpoint safety evidence observations are invalid"
            )
        fingerprint = str(raw["fingerprint"])
        source_id = str(raw["source_id"])
        region_hints = raw["region_hints"]
        classification = str(raw["classification"])
        if (
            re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
            or SOURCE_ID_RE.fullmatch(source_id) is None
            or not isinstance(region_hints, list)
            or any(
                not isinstance(region, str) or region not in REGION_ORDER
                for region in region_hints
            )
            or classification not in {"safe", "quarantined"}
            or fingerprint not in bindings[0 if classification == "safe" else 1]
        ):
            raise CandidateEndpointSanitizationError(
                "candidate endpoint safety evidence observations are invalid"
            )
        if region_hints != sorted(set(region_hints), key=REGION_ORDER.index):
            raise CandidateEndpointSanitizationError(
                "candidate endpoint safety evidence observations are invalid"
            )
        normalized_bindings.append(
            (fingerprint, source_id, tuple(region_hints), classification)
        )
    if normalized_bindings != sorted(normalized_bindings):
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence observations are invalid"
        )
    classified = {
        classification: {
            fingerprint
            for fingerprint, _source_id, _regions, current in normalized_bindings
            if current == classification
        }
        for classification in ("safe", "quarantined")
    }
    if classified["safe"] != bindings[0] or classified["quarantined"] != bindings[1]:
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence classifications are incomplete"
        )
    if value["raw_count"] != len(normalized_bindings) + value["invalid_count"]:
        raise CandidateEndpointSanitizationError(
            "candidate endpoint safety evidence count is inconsistent"
        )
    return dict(value)


def write_endpoint_safety_evidence(path: str | Path, value: Mapping[str, Any]) -> None:
    try:
        write_private_bytes_atomic(path, _json_bytes(validate_endpoint_safety_evidence(value)))
    except CandidateHandoffError as exc:
        raise CandidateEndpointSanitizationError(
            "unable to write candidate endpoint safety evidence"
        ) from exc


def sanitize_candidate_profile_files(
    profile_path: str | Path,
    provenance_paths: Iterable[str | Path],
    *,
    output_path: str | Path | None = None,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    sleeper: Callable[[float], None] | None = None,
    rebuild_from_provenance: bool = False,
    safety_evidence_path: str | Path | None = None,
) -> SanitizedCandidateProfile:
    source = Path(profile_path)
    provenance = merge_provenance_staging(provenance_paths)
    if rebuild_from_provenance:
        result = rebuild_candidate_profile(
            provenance,
            resolver=resolver,
            sleeper=sleeper,
        )
    else:
        try:
            profile = yaml.safe_load(source.read_bytes())
        except Exception as exc:
            raise CandidateEndpointSanitizationError(
                "candidate profile is invalid YAML"
            ) from exc
        result = sanitize_candidate_profile(
            profile,
            provenance,
            resolver=resolver,
            sleeper=sleeper,
        )
    text, rejected = _dump_candidate_profile(result.profile)
    if rejected:
        raise CandidateEndpointSanitizationError(
            "candidate profile contains invalid REALITY short IDs"
        )
    destination = Path(output_path) if output_path else source
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    # Write the exact bytes bound into endpoint-safety evidence. Text-mode
    # newline translation on Windows would otherwise make the persisted
    # profile SHA differ from the evidence generated below.
    temporary.write_bytes(text.encode("utf-8"))
    temporary.replace(destination)
    if safety_evidence_path is not None:
        write_endpoint_safety_evidence(
            safety_evidence_path,
            build_endpoint_safety_evidence(
                result,
                profile_bytes=text.encode("utf-8"),
                provenance=provenance,
            ),
        )
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--provenance", action="append", required=True)
    parser.add_argument("--output", default="")
    parser.add_argument("--safety-evidence", default="")
    parser.add_argument("--rebuild-from-provenance", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = sanitize_candidate_profile_files(
        args.profile,
        args.provenance,
        output_path=args.output or None,
        rebuild_from_provenance=args.rebuild_from_provenance,
        safety_evidence_path=args.safety_evidence or None,
    )
    print(
        "candidate endpoint sanitization: "
        f"kept {result.safe_count}/{result.raw_count}, "
        f"quarantined {result.quarantined_count}, invalid {result.invalid_count}"
    )
    return 0


def _run_cli(argv: list[str] | None = None) -> int:
    try:
        return main(argv)
    except (
        CandidateEndpointSanitizationError,
        EndpointResolutionInfrastructureError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_run_cli())


__all__ = [
    "CandidateEndpointSanitizationError",
    "ENDPOINT_SAFETY_EVIDENCE_KIND",
    "ENDPOINT_SAFETY_EVIDENCE_SCHEMA_VERSION",
    "SanitizedCandidateProfile",
    "build_endpoint_safety_evidence",
    "rebuild_candidate_profile",
    "sanitize_candidate_profile",
    "sanitize_candidate_profile_files",
    "validate_endpoint_safety_evidence",
    "write_endpoint_safety_evidence",
]
