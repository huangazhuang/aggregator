#!/usr/bin/env python3
"""Safe C1 source/provenance staging and endpoint validation helpers."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from scripts.proxy_identity import IdentityError, canonical_port, canonical_server
from subscribe.asia import (
    PREFERRED_ASIA_MARKER_PATTERN,
    preferred_asia_region_hints,
)


PROVENANCE_STAGING_KIND = "github-candidate-provenance-staging"
PROVENANCE_STAGING_SCHEMA_VERSION = 1
SOURCE_POLICY_VERSION = "candidate-source-v1"
ENDPOINT_SAFETY_POLICY_VERSION = "endpoint-safety-v1"

SOURCE_OUTCOMES = frozenset(
    {"success", "empty", "timeout", "rate_limited", "parse_error", "network_error"}
)
SOURCE_VISIBILITIES = frozenset({"public", "opaque"})
SOURCE_ID_RE = re.compile(r"^(?:public|opaque)_[0-9a-f]{24}$")
SAFE_PUBLIC_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", flags=re.I)
BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data.ec2.internal",
    }
)
BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")
BLOCKED_PLATFORM_IPS = frozenset(
    {
        # Azure's virtual platform/wire-server address is globally classified
        # by generic IP libraries but must never be reachable through a proxy.
        "168.63.129.16",
    }
)
PRIVATE_PROXY_FIELDS = frozenset(
    {
        "sub",
        "source",
        "source_id",
        "source_ids",
        "provenance",
        "liveness",
        "chatgpt",
        "country",
        "region",
        "location",
        "region_hints",
        "region_evidence",
        "protected_asia",
        "github_check_state",
        "github_tested",
        "github_test_result",
        "candidate_id",
        "server_id",
        "endpoint_id",
        "exit_id",
        "fingerprint",
    }
)


class CandidateSourceError(ValueError):
    """Raised when source/provenance staging is malformed or unsafe."""


class EndpointSafetyError(CandidateSourceError):
    """Raised when a proxy endpoint is not safe to hand to the identity stage."""


class EndpointResolutionInfrastructureError(CandidateSourceError):
    """Raised when DNS infrastructure is too uncertain to classify a candidate."""


def utc_timestamp(value: datetime | str | None = None) -> str:
    """Return a strict second-resolution UTC timestamp."""

    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    else:
        text = str(value or "").strip()
        if not text:
            raise CandidateSourceError("timestamp is required")
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CandidateSourceError("timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise CandidateSourceError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _source_digest(raw_source: str, visibility: str) -> str:
    material = f"{SOURCE_POLICY_VERSION}\0{visibility}\0{raw_source}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:24]


def _github_public_alias(raw_source: str) -> str:
    try:
        parsed = urlsplit(raw_source)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    parts = [part for part in parsed.path.split("/") if part]
    if host == "raw.githubusercontent.com" and len(parts) >= 2:
        alias = f"github:{parts[0]}/{parts[1]}"
    elif host in {"github.com", "www.github.com"} and len(parts) >= 2:
        alias = f"github:{parts[0]}/{parts[1].removesuffix('.git')}"
    else:
        return ""
    return alias if SAFE_PUBLIC_ALIAS_RE.fullmatch(alias) else ""


def safe_source_descriptor(
    raw_source: Any,
    *,
    task_name: Any = "",
    publish_derivatives: bool = False,
) -> dict[str, Any]:
    """Create a persistent public-safe source descriptor without retaining a URL."""

    raw = str(raw_source or "").strip()
    task_alias = str(task_name or "").strip()
    public_alias = _github_public_alias(raw)
    if not raw:
        raw = f"task:{task_alias}" if task_alias else "task:unknown"
    visibility = "public" if public_alias else "opaque"
    alias = public_alias
    if visibility == "public" and not alias and SAFE_PUBLIC_ALIAS_RE.fullmatch(task_alias):
        alias = task_alias
    return {
        "source_id": f"{visibility}_{_source_digest(raw, visibility)}",
        "alias": alias,
        "visibility": visibility,
        "publish_derivatives": bool(publish_derivatives),
    }


def _safe_proxy_copy(proxy: Mapping[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(dict(proxy))
    for field in PRIVATE_PROXY_FIELDS:
        output.pop(field, None)
    return output


def _region_evidence(proxy: Mapping[str, Any], task_name: str) -> tuple[list[str], list[str]]:
    hints = set(preferred_asia_region_hints(proxy))
    source_hints = set(preferred_asia_region_hints({"name": task_name}))
    hints.update(source_hints)
    evidence = {f"name_hint:{region}" for region in preferred_asia_region_hints(proxy)}
    evidence.update(f"source_hint:{region}" for region in source_hints)
    name = str(proxy.get("name", "") or "")
    if PREFERRED_ASIA_MARKER_PATTERN.search(name) or PREFERRED_ASIA_MARKER_PATTERN.search(task_name):
        evidence.add("explicit:asia_keep")
    return sorted(hints), sorted(evidence)


def provenance_for_task(
    task: Any,
    proxies: Iterable[Mapping[str, Any]] | None,
    *,
    observed_at: datetime | str | None = None,
    outcome: str | None = None,
    default_publish_derivatives: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build safe source events and private proxy records for one collection task."""

    timestamp = utc_timestamp(observed_at)
    task_name = str(getattr(task, "name", "") or "").strip()
    task_source = (
        str(getattr(task, "sub", "") or "").strip()
        or str(getattr(task, "domain", "") or "").strip()
        or task_name
    )
    explicit_publish = getattr(task, "publish_derivatives", None)
    publish_derivatives = (
        bool(explicit_publish) if explicit_publish is not None else bool(default_publish_derivatives)
    )
    items = [dict(proxy) for proxy in (proxies or []) if isinstance(proxy, Mapping)]
    normalized_outcome = str(outcome or ("success" if items else "empty")).strip().lower()
    if normalized_outcome not in SOURCE_OUTCOMES:
        raise CandidateSourceError("source outcome is unsupported")

    descriptor = safe_source_descriptor(
        task_source,
        task_name=task_name,
        publish_derivatives=publish_derivatives,
    )
    sources: dict[str, dict[str, Any]] = {
        descriptor["source_id"]: {
            **descriptor,
            "outcome": normalized_outcome,
            "observed_at": timestamp,
            "last_success_at": timestamp if normalized_outcome == "success" else "",
        }
    }
    records: list[dict[str, Any]] = []
    for proxy in items:
        if not descriptor["publish_derivatives"]:
            continue
        alias = str(proxy.get("name", "") or "").strip()
        hints, evidence = _region_evidence(proxy, task_name)
        records.append(
            {
                "proxy": _safe_proxy_copy(proxy),
                "alias": alias,
                "source_id": descriptor["source_id"],
                "source_alias": descriptor["alias"],
                "source_visibility": descriptor["visibility"],
                "source_last_success_at": timestamp,
                "observed_at": timestamp,
                "region_hints": hints,
                "region_evidence": evidence,
            }
        )
    return sorted(sources.values(), key=lambda item: item["source_id"]), records


def write_provenance_staging(
    path: str | Path,
    *,
    sources: Iterable[Mapping[str, Any]],
    records: Iterable[Mapping[str, Any]],
    generated_at: datetime | str | None = None,
) -> None:
    """Write a private identity handoff atomically; it must never be published."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": PROVENANCE_STAGING_KIND,
        "schema_version": PROVENANCE_STAGING_SCHEMA_VERSION,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "generated_at": utc_timestamp(generated_at),
        "sources": sorted((dict(item) for item in sources), key=lambda item: item["source_id"]),
        "records": [dict(item) for item in records],
    }
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def load_provenance_staging(path: str | Path) -> dict[str, Any]:
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        raise CandidateSourceError("provenance staging is invalid JSON") from exc
    required = {
        "kind",
        "schema_version",
        "source_policy_version",
        "generated_at",
        "sources",
        "records",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise CandidateSourceError("provenance staging fields are incomplete or unexpected")
    if payload["kind"] != PROVENANCE_STAGING_KIND:
        raise CandidateSourceError("provenance staging kind is unsupported")
    if payload["schema_version"] != PROVENANCE_STAGING_SCHEMA_VERSION:
        raise CandidateSourceError("provenance staging schema is unsupported")
    if payload["source_policy_version"] != SOURCE_POLICY_VERSION:
        raise CandidateSourceError("provenance source policy is unsupported")
    utc_timestamp(payload["generated_at"])
    if not isinstance(payload["sources"], list) or not isinstance(payload["records"], list):
        raise CandidateSourceError("provenance staging collections are malformed")
    source_ids: set[str] = set()
    sources_by_id: dict[str, dict[str, Any]] = {}
    for item in payload["sources"]:
        required_source = {
            "source_id",
            "alias",
            "visibility",
            "publish_derivatives",
            "outcome",
            "observed_at",
            "last_success_at",
        }
        if not isinstance(item, dict) or set(item) != required_source:
            raise CandidateSourceError("provenance source fields are incomplete or unexpected")
        source_id = str(item["source_id"])
        if not SOURCE_ID_RE.fullmatch(source_id) or source_id in source_ids:
            raise CandidateSourceError("provenance source ID is invalid or duplicated")
        source_ids.add(source_id)
        sources_by_id[source_id] = item
        if item["visibility"] not in SOURCE_VISIBILITIES or item["outcome"] not in SOURCE_OUTCOMES:
            raise CandidateSourceError("provenance source state is unsupported")
        if not isinstance(item["publish_derivatives"], bool):
            raise CandidateSourceError("provenance publish_derivatives must be boolean")
        alias = str(item["alias"] or "")
        if alias and not SAFE_PUBLIC_ALIAS_RE.fullmatch(alias):
            raise CandidateSourceError("provenance source alias is unsafe")
        utc_timestamp(item["observed_at"])
        if item["last_success_at"]:
            utc_timestamp(item["last_success_at"])
    for item in payload["records"]:
        required_record = {
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
        if not isinstance(item, dict) or set(item) != required_record:
            raise CandidateSourceError("provenance record fields are incomplete or unexpected")
        if item["source_id"] not in source_ids or not isinstance(item["proxy"], dict):
            raise CandidateSourceError("provenance record source binding is invalid")
        if item["source_visibility"] not in SOURCE_VISIBILITIES:
            raise CandidateSourceError("provenance record source visibility is unsupported")
        source = sources_by_id[item["source_id"]]
        if (
            item["source_visibility"] != source["visibility"]
            or item["source_alias"] != source["alias"]
            or source["publish_derivatives"] is not True
        ):
            raise CandidateSourceError("provenance record source descriptor is inconsistent")
        alias = str(item["alias"] or "")
        if len(alias) > 512 or any(ord(char) < 32 or ord(char) == 127 for char in alias):
            raise CandidateSourceError("provenance record alias is unsafe")
        if not isinstance(item["region_hints"], list) or not isinstance(item["region_evidence"], list):
            raise CandidateSourceError("provenance region evidence is malformed")
        if any(region not in {"HK", "JP", "KR", "SG", "TW"} for region in item["region_hints"]):
            raise CandidateSourceError("provenance region hint is unsupported")
        if any(
            not re.fullmatch(r"(?:name_hint|source_hint):(HK|JP|KR|SG|TW)|explicit:asia_keep", str(value))
            for value in item["region_evidence"]
        ):
            raise CandidateSourceError("provenance region evidence is unsafe")
        utc_timestamp(item["source_last_success_at"])
        utc_timestamp(item["observed_at"])
    return payload


def merge_provenance_staging(paths: Iterable[str | Path]) -> dict[str, Any]:
    sources: dict[str, dict[str, Any]] = {}
    records: list[dict[str, Any]] = []
    generated_at = ""
    for path in paths:
        payload = load_provenance_staging(path)
        generated_at = max(generated_at, str(payload["generated_at"]))
        for item in payload["sources"]:
            source_id = item["source_id"]
            previous = sources.get(source_id)
            if previous is None:
                sources[source_id] = dict(item)
            elif previous.get("outcome") != "success" and item.get("outcome") == "success":
                sources[source_id] = dict(item)
            elif previous.get("outcome") == item.get("outcome") and str(item["observed_at"]) >= str(previous["observed_at"]):
                sources[source_id] = dict(item)
        records.extend(dict(item) for item in payload["records"])
    return {
        "kind": PROVENANCE_STAGING_KIND,
        "schema_version": PROVENANCE_STAGING_SCHEMA_VERSION,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "generated_at": generated_at or utc_timestamp(),
        "sources": sorted(sources.values(), key=lambda item: item["source_id"]),
        "records": records,
    }


def _default_resolver(host: str, port: int) -> list[str]:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if item and item[0] in {socket.AF_INET, socket.AF_INET6}
    }
    return sorted(addresses)


def is_acceptable_public_ip(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return address.compressed not in BLOCKED_PLATFORM_IPS and address.is_global


def validate_proxy_endpoint(
    proxy: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    checked_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Resolve every A/AAAA result and reject any non-public endpoint."""

    if not isinstance(proxy, Mapping):
        raise EndpointSafetyError("proxy endpoint input must be a mapping")
    try:
        server = canonical_server(proxy.get("server"))
        port = canonical_port(proxy.get("port"))
    except IdentityError as exc:
        raise EndpointSafetyError("proxy endpoint is malformed") from exc
    try:
        literal = ipaddress.ip_address(server)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [literal.compressed]
    else:
        if server in BLOCKED_HOSTS or server.endswith(BLOCKED_HOST_SUFFIXES):
            raise EndpointSafetyError("proxy endpoint host is not publicly routable")
        labels = server.split(".")
        if len(labels) < 2 or any(not HOST_LABEL_RE.fullmatch(label) for label in labels):
            raise EndpointSafetyError("proxy endpoint hostname is malformed")
        try:
            addresses = list((resolver or _default_resolver)(server, port))
        except socket.gaierror as exc:
            definitive_codes = {
                value
                for value in (
                    getattr(socket, "EAI_NONAME", None),
                    getattr(socket, "EAI_NODATA", None),
                    getattr(socket, "EAI_ADDRFAMILY", None),
                )
                if value is not None
            }
            if exc.errno in definitive_codes:
                raise EndpointSafetyError("proxy endpoint DNS resolution failed") from exc
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            ) from exc
        except Exception as exc:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            ) from exc
    if not addresses or any(not is_acceptable_public_ip(value) for value in addresses):
        raise EndpointSafetyError("proxy endpoint resolved outside the public Internet")
    return {
        "policy_version": ENDPOINT_SAFETY_POLICY_VERSION,
        "checked_at": utc_timestamp(checked_at),
        "resolved_address_count": len(set(addresses)),
    }


__all__ = [
    "CandidateSourceError",
    "ENDPOINT_SAFETY_POLICY_VERSION",
    "EndpointResolutionInfrastructureError",
    "EndpointSafetyError",
    "PROVENANCE_STAGING_KIND",
    "PROVENANCE_STAGING_SCHEMA_VERSION",
    "SOURCE_POLICY_VERSION",
    "is_acceptable_public_ip",
    "load_provenance_staging",
    "merge_provenance_staging",
    "provenance_for_task",
    "safe_source_descriptor",
    "utc_timestamp",
    "validate_proxy_endpoint",
    "write_provenance_staging",
]
