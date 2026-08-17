#!/usr/bin/env python3
"""Probe-time DNS pinning and fail-closed network-guard contract for GMGN V2."""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
import socket
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any

from scripts.gmgn_measurement import (
    NETWORK_GUARD_POLICY_VERSION,
    RESOLVER_POLICY_VERSION,
    MeasurementError,
    candidate_ids_sha256,
    normalize_candidate,
)
from scripts.proxy_identity import canonical_port, canonical_server


SUPPORTED_BACKENDS = frozenset({"container-deny-v1", "netns-deny-v1"})
_DNS_RETRY_DELAYS = (0.25, 1.0, 2.0)
_TRANSIENT_DNS_ERRORS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_AGAIN", None),
        getattr(socket, "EAI_FAIL", None),
    )
    if isinstance(code, int)
)
_DEFINITIVE_DNS_ERRORS = frozenset(
    code
    for code in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
        getattr(socket, "EAI_ADDRFAMILY", None),
    )
    if isinstance(code, int)
)
GUARD_EVIDENCE_FIELDS = frozenset(
    {
        "backend",
        "backend_version",
        "policy_version",
        "resolver_policy_version",
        "available",
        "deny_self_test_passed",
        "controller_isolated",
        "fixed_resolution_enforced",
        "candidate_ids_sha256",
    }
)


def _public_address(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise MeasurementError("resolver returned an invalid IP address") from exc
    if (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise MeasurementError("resolver returned a forbidden non-global address")
    return address.compressed.lower()


def default_resolver(
    host: str,
    port: int,
    *,
    getaddrinfo: Callable[..., Iterable[tuple[Any, ...]]] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> Sequence[str]:
    resolve = getaddrinfo or socket.getaddrinfo
    for attempt in range(len(_DNS_RETRY_DELAYS) + 1):
        try:
            values = {
                str(sockaddr[0])
                for _family, _type, _proto, _canonname, sockaddr in resolve(
                    host, port, type=socket.SOCK_STREAM
                )
            }
            return sorted(values)
        except socket.gaierror as exc:
            code = int(exc.errno or 0)
            if code not in _TRANSIENT_DNS_ERRORS or attempt >= len(_DNS_RETRY_DELAYS):
                raise socket.gaierror(code, "DNS resolution failed") from None
            sleeper(_DNS_RETRY_DELAYS[attempt])
        except Exception:
            raise MeasurementError("resolver infrastructure failed") from None
    raise MeasurementError("resolver retry state is invalid")


def _resolve_candidate_set(
    candidates: Iterable[Any],
    *,
    resolver: Callable[[str, int], Sequence[str]],
    allow_definitive_failures: bool,
) -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    normalized = [normalize_candidate(candidate) for candidate in candidates]
    if not normalized:
        raise MeasurementError("network guard candidate set is empty")
    ids = [candidate["candidate_id"] for candidate in normalized]
    if len(ids) != len(set(ids)):
        raise MeasurementError("network guard candidate set contains duplicate IDs")

    pinned: dict[str, dict[str, Any]] = {}
    unresolved: list[str] = []
    for candidate in normalized:
        proxy = candidate["proxy"]
        if "server" not in proxy or "port" not in proxy:
            raise MeasurementError("candidate proxy is missing server or port")
        host = canonical_server(proxy["server"])
        port = canonical_port(proxy["port"])
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            try:
                raw_addresses = resolver(host, port)
            except socket.gaierror as exc:
                code = int(exc.errno or 0)
                if allow_definitive_failures and code in _DEFINITIVE_DNS_ERRORS:
                    unresolved.append(candidate["candidate_id"])
                    continue
                label = (
                    "candidate DNS resolution failed"
                    if code in _DEFINITIVE_DNS_ERRORS
                    else "candidate DNS infrastructure failed"
                )
                raise MeasurementError(label) from None
            except MeasurementError:
                raise
            except Exception:
                raise MeasurementError("candidate DNS infrastructure failed") from None
        else:
            raw_addresses = [literal.compressed]
        addresses = sorted({_public_address(value) for value in raw_addresses})
        if not addresses:
            if allow_definitive_failures:
                unresolved.append(candidate["candidate_id"])
                continue
            raise MeasurementError("resolver returned no public addresses")
        pinned[candidate["candidate_id"]] = {
            "server": host,
            "port": port,
            "addresses": addresses,
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        }
    if not pinned:
        raise MeasurementError("network guard candidate set has no resolvable endpoints")
    return pinned, tuple(sorted(unresolved))


def resolve_and_pin_candidates(
    candidates: Iterable[Any],
    *,
    resolver: Callable[[str, int], Sequence[str]] = default_resolver,
) -> dict[str, dict[str, Any]]:
    """Resolve every candidate endpoint and reject any unsafe A/AAAA answer."""
    pinned, unresolved = _resolve_candidate_set(
        candidates,
        resolver=resolver,
        allow_definitive_failures=False,
    )
    if unresolved:
        raise MeasurementError("network guard resolver partition is invalid")
    return pinned


def resolve_and_pin_candidates_with_failures(
    candidates: Iterable[Any],
    *,
    resolver: Callable[[str, int], Sequence[str]] = default_resolver,
) -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    """Pin resolvable candidates and return definitive DNS failures separately."""

    return _resolve_candidate_set(
        candidates,
        resolver=resolver,
        allow_definitive_failures=True,
    )


def verify_pinned_resolution(
    pinned: Mapping[str, Mapping[str, Any]],
    *,
    resolver: Callable[[str, int], Sequence[str]] = default_resolver,
) -> None:
    """Fail if a hostname drifts, including public-to-private DNS rebinding."""

    for candidate_id, record in pinned.items():
        host = str(record["server"])
        port = int(record["port"])
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            current = sorted({_public_address(value) for value in resolver(host, port)})
        else:
            current = [_public_address(literal.compressed)]
        if current != list(record["addresses"]):
            raise MeasurementError(f"fixed resolution drift for {candidate_id}")


def validate_guard_evidence(
    evidence: Mapping[str, Any], *, candidate_ids: Iterable[str]
) -> dict[str, Any]:
    if not isinstance(evidence, Mapping) or frozenset(evidence) != GUARD_EVIDENCE_FIELDS:
        raise MeasurementError("network guard evidence fields are incomplete or unexpected")
    value = dict(evidence)
    if value["backend"] not in SUPPORTED_BACKENDS:
        raise MeasurementError("network guard backend is unavailable or unsupported")
    if value["policy_version"] != NETWORK_GUARD_POLICY_VERSION:
        raise MeasurementError("network guard policy version mismatch")
    if value["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
        raise MeasurementError("network guard resolver policy version mismatch")
    if not isinstance(value["backend_version"], str) or not value["backend_version"].strip():
        raise MeasurementError("network guard backend version is missing")
    for field in (
        "available",
        "deny_self_test_passed",
        "controller_isolated",
        "fixed_resolution_enforced",
    ):
        if value[field] is not True:
            raise MeasurementError(f"network guard {field} check failed")
    normalized_ids = [str(value) for value in candidate_ids]
    if not normalized_ids or len(normalized_ids) != len(set(normalized_ids)):
        raise MeasurementError("network guard candidate IDs are empty or duplicated")
    expected = candidate_ids_sha256(sorted(normalized_ids))
    if value["candidate_ids_sha256"] != expected:
        raise MeasurementError("network guard candidate binding mismatch")
    return value


def guard_preflight(
    candidates: Iterable[Any],
    *,
    backend: Callable[[dict[str, dict[str, Any]]], Mapping[str, Any]],
    resolver: Callable[[str, int], Sequence[str]] = default_resolver,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Resolve, invoke a C5-provided isolation backend, self-test, then recheck DNS."""

    if not callable(backend):
        raise MeasurementError("network guard backend is required")
    materialized = [normalize_candidate(candidate) for candidate in candidates]
    pinned = resolve_and_pin_candidates(materialized, resolver=resolver)
    evidence = validate_guard_evidence(
        backend(copy.deepcopy(pinned)), candidate_ids=pinned.keys()
    )
    verify_pinned_resolution(pinned, resolver=resolver)
    return pinned, evidence


def build_guarded_launch(
    command: Sequence[str], *, evidence: Mapping[str, Any], candidate_ids: Iterable[str]
) -> list[str]:
    """Validate evidence before returning the exact Mihomo launch command."""

    if not command or any(not isinstance(item, str) or not item for item in command):
        raise MeasurementError("guarded launch command is invalid")
    validate_guard_evidence(evidence, candidate_ids=candidate_ids)
    return list(command)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate GMGN V2 network guard evidence")
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--candidate-ids", required=True)
    args = parser.parse_args(argv)
    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    candidate_ids = json.loads(Path(args.candidate_ids).read_text(encoding="utf-8"))
    validate_guard_evidence(evidence, candidate_ids=candidate_ids)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())


__all__ = [
    "GUARD_EVIDENCE_FIELDS",
    "NETWORK_GUARD_POLICY_VERSION",
    "RESOLVER_POLICY_VERSION",
    "SUPPORTED_BACKENDS",
    "build_guarded_launch",
    "default_resolver",
    "guard_preflight",
    "resolve_and_pin_candidates",
    "resolve_and_pin_candidates_with_failures",
    "validate_guard_evidence",
    "verify_pinned_resolution",
]
