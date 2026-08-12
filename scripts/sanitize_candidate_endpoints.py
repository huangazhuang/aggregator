#!/usr/bin/env python3
"""Sanitize Candidate V2 proxy endpoints before FC or Mihomo can access them."""

from __future__ import annotations

import argparse
import copy
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from scripts.candidate_sources import (
    EndpointResolutionInfrastructureError,
    EndpointSafetyError,
    merge_provenance_staging,
    validate_proxy_endpoint,
)
from scripts.pipeline_utils import dump_clash_yaml, filtered_profile
from scripts.proxy_identity import (
    IdentityError,
    canonical_endpoint,
    canonical_proxy_fingerprint,
)


class CandidateEndpointSanitizationError(ValueError):
    """Raised when the pre-network Candidate V2 staging cannot be trusted."""


@dataclass(frozen=True)
class SanitizedCandidateProfile:
    profile: dict[str, Any]
    raw_count: int
    safe_count: int
    quarantined_count: int
    invalid_count: int


def _clash_module() -> Any:
    subscribe_dir = str(Path(__file__).resolve().parents[1] / "subscribe")
    if subscribe_dir not in sys.path:
        sys.path.insert(0, subscribe_dir)
    import clash  # type: ignore

    return clash


def _validated_proxy(proxy: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(proxy, Mapping):
        raise CandidateEndpointSanitizationError("candidate proxy must be a mapping")
    candidate = copy.deepcopy(dict(proxy))
    try:
        valid = _clash_module().verify(candidate, mihomo=True)
    except Exception as exc:
        raise CandidateEndpointSanitizationError(
            "candidate proxy validation failed"
        ) from exc
    if not valid:
        raise CandidateEndpointSanitizationError("candidate proxy validation failed")
    return candidate


def sanitize_candidate_profile(
    profile: Mapping[str, Any],
    provenance: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
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
    for raw in records:
        if not isinstance(raw, Mapping) or not isinstance(raw.get("proxy"), Mapping):
            raise CandidateEndpointSanitizationError(
                "candidate provenance record is malformed"
            )
        try:
            provenance_fingerprints.add(
                canonical_proxy_fingerprint(_validated_proxy(raw["proxy"]))
            )
        except (CandidateEndpointSanitizationError, IdentityError):
            continue

    safe_by_fingerprint: dict[str, dict[str, Any]] = {}
    invalid_count = 0
    quarantined_count = 0
    endpoint_cache: dict[str, dict[str, Any] | EndpointSafetyError] = {}
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
        endpoint = canonical_endpoint(proxy["server"], proxy["port"])
        if endpoint not in endpoint_cache:
            try:
                endpoint_cache[endpoint] = validate_proxy_endpoint(
                    proxy,
                    resolver=resolver,
                )
            except EndpointSafetyError as exc:
                endpoint_cache[endpoint] = exc
        endpoint_result = endpoint_cache[endpoint]
        if isinstance(endpoint_result, EndpointSafetyError):
            quarantined_count += 1
            continue
        safe_by_fingerprint.setdefault(fingerprint, proxy)

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
    )


def sanitize_candidate_profile_files(
    profile_path: str | Path,
    provenance_paths: Iterable[str | Path],
    *,
    output_path: str | Path | None = None,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
) -> SanitizedCandidateProfile:
    source = Path(profile_path)
    try:
        profile = yaml.safe_load(source.read_bytes())
    except Exception as exc:
        raise CandidateEndpointSanitizationError(
            "candidate profile is invalid YAML"
        ) from exc
    provenance = merge_provenance_staging(provenance_paths)
    result = sanitize_candidate_profile(profile, provenance, resolver=resolver)
    text, rejected = dump_clash_yaml(result.profile)
    if rejected:
        raise CandidateEndpointSanitizationError(
            "candidate profile contains invalid REALITY short IDs"
        )
    destination = Path(output_path) if output_path else source
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(destination)
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--provenance", action="append", required=True)
    parser.add_argument("--output", default="")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    result = sanitize_candidate_profile_files(
        args.profile,
        args.provenance,
        output_path=args.output or None,
    )
    print(
        "candidate endpoint sanitization: "
        f"kept {result.safe_count}/{result.raw_count}, "
        f"quarantined {result.quarantined_count}, invalid {result.invalid_count}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        CandidateEndpointSanitizationError,
        EndpointResolutionInfrastructureError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)


__all__ = [
    "CandidateEndpointSanitizationError",
    "SanitizedCandidateProfile",
    "sanitize_candidate_profile",
    "sanitize_candidate_profile_files",
]
