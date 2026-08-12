#!/usr/bin/env python3
"""Safe C1 source/provenance staging and endpoint validation helpers."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import socket
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from scripts.candidate_handoff import CandidateHandoffError, write_private_bytes_atomic
from scripts.proxy_identity import IdentityError, canonical_port, canonical_server
from scripts.proxy_privacy import contains_sensitive_scalar_material
from scripts.proxy_schema import ProxySchemaError, validate_proxy_schema
from subscribe.asia import (
    PREFERRED_ASIA_MARKER_PATTERN,
    preferred_asia_region_hints,
)


PROVENANCE_STAGING_KIND = "github-candidate-provenance-staging"
PROVENANCE_STAGING_SCHEMA_VERSION = 2
# Source identity is a persistent namespace, independent of later policy and
# schema upgrades. Keep this value fixed so existing public source IDs do not
# rotate when SOURCE_POLICY_VERSION changes.
SOURCE_ID_VERSION = "candidate-source-v2"
SOURCE_POLICY_VERSION = "candidate-source-v3"
ENDPOINT_SAFETY_POLICY_VERSION = "endpoint-safety-v2"
_TRANSIENT_DNS_RETRY_DELAYS = (0.25, 1.0, 2.0)
_TARGET_DNS_REOBSERVATION_DELAY_SECONDS = 5.0
_DNS_CANARY_HOSTS = ("example.com", "one.one.one.one", "dns.google")
_DNS_CANARY_PORT = 443
_CANDIDATE_DNS_FAILURE_MINIMUM = 3
_CANDIDATE_DNS_FAILURE_RATIO = 0.02

SOURCE_OUTCOMES = frozenset(
    {"success", "empty", "timeout", "rate_limited", "parse_error", "network_error"}
)
SOURCE_VISIBILITIES = frozenset({"public", "opaque"})
SOURCE_KINDS = frozenset({"fixed", "dynamic"})
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
COLLECTOR_PROXY_METADATA_FIELDS = frozenset(
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
    }
)


class CandidateSourceError(ValueError):
    """Raised when source/provenance staging is malformed or unsafe."""


class EndpointSafetyError(CandidateSourceError):
    """Raised when a proxy endpoint is not safe to hand to the identity stage."""


class EndpointResolutionCandidateError(EndpointSafetyError):
    """Raised when healthy DNS infrastructure cannot resolve one candidate."""


class EndpointResolutionInfrastructureError(CandidateSourceError):
    """Raised when DNS infrastructure is too uncertain to classify a candidate."""


@dataclass(frozen=True)
class _ResolutionObservation:
    addresses: tuple[str, ...] = ()
    failure_kind: str = ""
    failure_code: int | None = None


@dataclass(frozen=True)
class _CachedResolution:
    addresses: tuple[str, ...] = ()
    failure_kind: str = ""
    failure_code: int | None = None


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
    material = f"{SOURCE_ID_VERSION}\0{visibility}\0{raw_source}".encode("utf-8")
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


def _source_credential_values(
    raw_source: str,
    *,
    include_opaque_components: bool,
) -> tuple[str, ...]:
    """Return URL credential values while the private source URL is in scope."""

    try:
        parsed = urlsplit(raw_source)
    except ValueError:
        return ()
    if not parsed.scheme or not parsed.netloc:
        return ()

    values: set[str] = set()

    def add(value: Any) -> None:
        current = str(value or "").strip()
        # Compare the exact URL spelling as well as a bounded decode chain.
        # This catches aliases echoing ``ABC%2FDEF`` or a double-encoded token
        # without letting adversarial percent input consume unbounded work.
        for _ in range(4):
            if not current or current in values:
                break
            values.add(current)
            decoded = unquote(current).strip()
            if decoded == current:
                break
            current = decoded

    for value in (parsed.username, parsed.password):
        add(value)

    # Every subscription URL can carry credentials in userinfo or query
    # fields, including an otherwise public GitHub-hosted URL.  Opaque sources
    # additionally use path segments and fragments as bearer material.  Parse
    # without ``unquote_plus`` semantics: ``+`` is valid token material and
    # must not silently turn into a space before comparison.
    for component in re.split(r"[&;]", parsed.query):
        if not component:
            continue
        key, separator, value = component.partition("=")
        add(key)
        if separator:
            add(value)
    if include_opaque_components:
        for segment in parsed.path.split("/"):
            add(segment)
        add(parsed.fragment)
        for component in re.split(r"[/?:#&;=]", parsed.fragment):
            add(component)
    return tuple(sorted(values, key=lambda item: (item.casefold(), item)))


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
    output = _collector_proxy_copy(proxy)
    try:
        return validate_proxy_schema(output)
    except ProxySchemaError as exc:
        raise CandidateSourceError("candidate proxy schema is unsupported") from exc


def _collector_proxy_copy(proxy: Mapping[str, Any]) -> dict[str, Any]:
    output = copy.deepcopy(dict(proxy))
    for field in COLLECTOR_PROXY_METADATA_FIELDS:
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
    source_kind = str(
        getattr(task, "candidate_source_role", "dynamic") or ""
    ).strip().lower()
    if source_kind not in SOURCE_KINDS:
        raise CandidateSourceError("candidate source kind is unsupported")
    normalized_outcome = str(outcome or ("success" if items else "empty")).strip().lower()
    if normalized_outcome not in SOURCE_OUTCOMES:
        raise CandidateSourceError("source outcome is unsupported")

    descriptor = safe_source_descriptor(
        task_source,
        task_name=task_name,
        publish_derivatives=publish_derivatives,
    )
    source_credentials = _source_credential_values(
        task_source,
        include_opaque_components=descriptor["visibility"] == "opaque",
    )
    sources: dict[str, dict[str, Any]] = {
        descriptor["source_id"]: {
            **descriptor,
            "source_kind": source_kind,
            "configured_this_run": True,
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
        if contains_sensitive_scalar_material(alias, source_credentials):
            alias = ""
        hints, evidence = _region_evidence(proxy, task_name)
        try:
            safe_proxy = _safe_proxy_copy(proxy)
        except CandidateSourceError:
            # Preserve the exact invalid candidate only in the private staging
            # boundary so the downstream sanitizer can count and quarantine it.
            # It is never handed to identity, Mihomo, or public serialization.
            safe_proxy = _collector_proxy_copy(proxy)
        records.append(
            {
                "proxy": safe_proxy,
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

    payload = {
        "kind": PROVENANCE_STAGING_KIND,
        "schema_version": PROVENANCE_STAGING_SCHEMA_VERSION,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "generated_at": utc_timestamp(generated_at),
        "sources": sorted((dict(item) for item in sources), key=lambda item: item["source_id"]),
        "records": [dict(item) for item in records],
    }
    content = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    try:
        write_private_bytes_atomic(path, content)
    except CandidateHandoffError as exc:
        raise CandidateSourceError("unable to write private provenance staging") from exc


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
            "source_kind",
            "configured_this_run",
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
        if item["source_kind"] not in SOURCE_KINDS:
            raise CandidateSourceError("provenance source kind is unsupported")
        if item["configured_this_run"] is not True:
            raise CandidateSourceError("provenance source must be configured this run")
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
        try:
            item["proxy"] = validate_proxy_schema(item["proxy"])
        except ProxySchemaError:
            # Invalid untrusted candidates are allowed only inside this private
            # staging file. Every consumer must validate before identity or
            # network access and count the rejected record explicitly.
            item["proxy"] = copy.deepcopy(item["proxy"])
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
                continue
            preferred = previous
            if previous.get("outcome") != "success" and item.get("outcome") == "success":
                preferred = item
            elif previous.get("outcome") == item.get("outcome") and str(item["observed_at"]) >= str(previous["observed_at"]):
                preferred = item
            merged = dict(preferred)
            if previous.get("source_kind") == "fixed" or item.get("source_kind") == "fixed":
                merged["source_kind"] = "fixed"
            merged["configured_this_run"] = True
            sources[source_id] = merged
        records.extend(dict(item) for item in payload["records"])
    return {
        "kind": PROVENANCE_STAGING_KIND,
        "schema_version": PROVENANCE_STAGING_SCHEMA_VERSION,
        "source_policy_version": SOURCE_POLICY_VERSION,
        "generated_at": generated_at or utc_timestamp(),
        "sources": sorted(sources.values(), key=lambda item: item["source_id"]),
        "records": records,
    }


def _default_resolver(
    host: str,
    port: int,
    *,
    getaddrinfo: Callable[..., Iterable[tuple[Any, ...]]] | None = None,
    sleeper: Callable[[float], None] | None = None,
) -> list[str]:
    resolve = getaddrinfo or socket.getaddrinfo
    pause = sleeper if sleeper is not None else time.sleep
    transient_codes = {
        value
        for value in (
            getattr(socket, "EAI_AGAIN", None),
            getattr(socket, "EAI_FAIL", None),
        )
        if value is not None
    }
    for attempt in range(len(_TRANSIENT_DNS_RETRY_DELAYS) + 1):
        try:
            results = resolve(host, port, type=socket.SOCK_STREAM)
            break
        except socket.gaierror as exc:
            if (
                exc.errno not in transient_codes
                or attempt >= len(_TRANSIENT_DNS_RETRY_DELAYS)
            ):
                raise
            pause(_TRANSIENT_DNS_RETRY_DELAYS[attempt])

    addresses = {
        item[4][0]
        for item in results
        if item and item[0] in {socket.AF_INET, socket.AF_INET6}
    }
    return sorted(addresses)


def is_acceptable_public_ip(value: Any) -> bool:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return bool(
        address.compressed not in BLOCKED_PLATFORM_IPS
        and address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not getattr(address, "is_site_local", False)
        and getattr(address, "scope_id", None) is None
    )


def _resolution_observation(
    resolver: Callable[[str, int], Iterable[str]],
    host: str,
    port: int,
) -> _ResolutionObservation:
    """Observe one DNS result without retaining untrusted exception text."""

    try:
        addresses = tuple(sorted({str(value) for value in resolver(host, port)}))
    except socket.gaierror as exc:
        return _ResolutionObservation(
            failure_kind="gaierror",
            failure_code=exc.errno,
        )
    except Exception:
        return _ResolutionObservation(failure_kind="exception")
    return _ResolutionObservation(addresses=addresses)


class CandidateDnsResolutionSession:
    """Classify endpoint DNS failures at run scope with hostname caching."""

    def __init__(
        self,
        *,
        expected_domain_hostnames: int,
        resolver: Callable[[str, int], Iterable[str]] | None = None,
        sleeper: Callable[[float], None] | None = None,
    ) -> None:
        if not isinstance(expected_domain_hostnames, int) or expected_domain_hostnames < 0:
            raise ValueError("expected domain hostname count must be non-negative")
        self._sleeper = sleeper if sleeper is not None else time.sleep
        if resolver is None:
            self._resolver = lambda host, port: _default_resolver(
                host,
                port,
                sleeper=self._sleeper,
            )
        else:
            self._resolver = resolver
        self._expected_domain_hostnames = expected_domain_hostnames
        self._cache: dict[str, _CachedResolution] = {}
        self._candidate_failure_hosts: set[str] = set()
        self._candidate_scope_canaries_healthy: bool | None = None

    def _canaries_are_healthy(self) -> bool:
        healthy = 0
        ordinary_failure = False
        for hostname in _DNS_CANARY_HOSTS:
            observation = _resolution_observation(
                self._resolver,
                hostname,
                _DNS_CANARY_PORT,
            )
            if observation.failure_kind == "exception":
                ordinary_failure = True
                break
            if (
                not observation.failure_kind
                and observation.addresses
                and all(
                    is_acceptable_public_ip(address)
                    for address in observation.addresses
                )
            ):
                healthy += 1
        if ordinary_failure:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        return healthy >= 2

    def _cache_candidate_failure(self, hostname: str) -> None:
        self._candidate_failure_hosts.add(hostname)
        failure_count = len(self._candidate_failure_hosts)
        if (
            failure_count >= _CANDIDATE_DNS_FAILURE_MINIMUM
            and failure_count / max(self._expected_domain_hostnames, 1)
            > _CANDIDATE_DNS_FAILURE_RATIO
        ):
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        self._cache[hostname] = _CachedResolution(failure_kind="candidate")

    @staticmethod
    def _raise_cached_failure(value: _CachedResolution) -> None:
        if value.failure_kind == "candidate":
            raise EndpointResolutionCandidateError(
                "proxy endpoint DNS resolution failed"
            )
        if value.failure_kind == "definitive":
            raise socket.gaierror(value.failure_code or 0, "DNS resolution failed")
        if value.failure_kind:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )

    def resolve(self, host: str, port: int) -> list[str]:
        """Resolve one hostname once per run, classifying isolated transients."""

        hostname = str(host or "").strip().lower()
        cached = self._cache.get(hostname)
        if cached is not None:
            self._raise_cached_failure(cached)
            return list(cached.addresses)

        observation = _resolution_observation(self._resolver, hostname, port)
        transient_codes = {
            value
            for value in (
                getattr(socket, "EAI_AGAIN", None),
                getattr(socket, "EAI_FAIL", None),
            )
            if value is not None
        }
        definitive_codes = {
            value
            for value in (
                getattr(socket, "EAI_NONAME", None),
                getattr(socket, "EAI_NODATA", None),
                getattr(socket, "EAI_ADDRFAMILY", None),
            )
            if value is not None
        }
        if not observation.failure_kind:
            self._cache[hostname] = _CachedResolution(addresses=observation.addresses)
            return list(observation.addresses)
        if observation.failure_kind == "exception":
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        if observation.failure_code in definitive_codes:
            self._cache[hostname] = _CachedResolution(
                failure_kind="definitive",
                failure_code=observation.failure_code,
            )
            self._raise_cached_failure(self._cache[hostname])
        if observation.failure_code not in transient_codes:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )

        if self._candidate_scope_canaries_healthy is None:
            self._candidate_scope_canaries_healthy = self._canaries_are_healthy()
        if not self._candidate_scope_canaries_healthy:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        self._sleeper(_TARGET_DNS_REOBSERVATION_DELAY_SECONDS)
        reobserved = _resolution_observation(self._resolver, hostname, port)
        if not reobserved.failure_kind:
            self._cache[hostname] = _CachedResolution(addresses=reobserved.addresses)
            return list(reobserved.addresses)
        if reobserved.failure_kind == "exception":
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        if reobserved.failure_code in definitive_codes:
            self._cache[hostname] = _CachedResolution(
                failure_kind="definitive",
                failure_code=reobserved.failure_code,
            )
            self._raise_cached_failure(self._cache[hostname])
        if reobserved.failure_code not in transient_codes:
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        self._cache_candidate_failure(hostname)
        self._raise_cached_failure(self._cache[hostname])
        raise AssertionError("unreachable")

    def finalize(self) -> None:
        """Fail closed if DNS health degraded after isolated quarantines."""

        if self._candidate_failure_hosts and not self._canaries_are_healthy():
            raise EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )


def count_proxy_domain_hostnames(proxies: Iterable[Mapping[str, Any]]) -> int:
    """Count unique non-literal proxy servers expected to require DNS."""

    hostnames: set[str] = set()
    for proxy in proxies:
        try:
            server, _port, _override = proxy_endpoint_safety_cache_key(proxy)
        except EndpointSafetyError:
            continue
        try:
            ipaddress.ip_address(server)
        except ValueError:
            hostnames.add(server)
    return len(hostnames)


def _canonical_tuic_override_ip(proxy: Mapping[str, Any]) -> str:
    value = proxy.get("ip")
    if proxy.get("type") != "tuic" or value is None or value == "":
        return ""
    if not isinstance(value, str) or value != value.strip():
        raise EndpointSafetyError("proxy TUIC IP override is malformed")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EndpointSafetyError("proxy TUIC IP override is malformed") from exc
    if getattr(address, "scope_id", None) is not None:
        raise EndpointSafetyError("proxy TUIC IP override is malformed")
    return address.compressed


def proxy_endpoint_safety_cache_key(proxy: Mapping[str, Any]) -> tuple[str, int, str]:
    """Return endpoint material whose safety result may be reused.

    TUIC can connect to its optional ``ip`` override instead of the address
    resolved from ``server``.  The override therefore belongs in the cache
    boundary even though the public endpoint identity remains server/port.
    """

    if not isinstance(proxy, Mapping):
        raise EndpointSafetyError("proxy endpoint input must be a mapping")
    try:
        server = canonical_server(proxy.get("server"))
        port = canonical_port(proxy.get("port"))
    except IdentityError as exc:
        raise EndpointSafetyError("proxy endpoint is malformed") from exc
    return server, port, _canonical_tuic_override_ip(proxy)


def validate_proxy_endpoint(
    proxy: Mapping[str, Any],
    *,
    resolver: Callable[[str, int], Iterable[str]] | None = None,
    checked_at: datetime | str | None = None,
) -> dict[str, Any]:
    """Resolve every A/AAAA result and reject any non-public endpoint."""

    if not isinstance(proxy, Mapping):
        raise EndpointSafetyError("proxy endpoint input must be a mapping")
    server, port, tuic_override_ip = proxy_endpoint_safety_cache_key(proxy)
    if tuic_override_ip and not is_acceptable_public_ip(tuic_override_ip):
        raise EndpointSafetyError("proxy TUIC IP override is not publicly routable")
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
        resolution_failure: CandidateSourceError | None = None
        try:
            addresses = list((resolver or _default_resolver)(server, port))
        except EndpointResolutionCandidateError:
            raise
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
                resolution_failure = EndpointSafetyError(
                    "proxy endpoint DNS resolution failed"
                )
            else:
                resolution_failure = EndpointResolutionInfrastructureError(
                    "proxy endpoint DNS infrastructure failed"
                )
        except Exception:
            resolution_failure = EndpointResolutionInfrastructureError(
                "proxy endpoint DNS infrastructure failed"
            )
        if resolution_failure is not None:
            # Raise outside the handler so neither explicit nor implicit
            # exception chaining can expose an untrusted resolver message.
            raise resolution_failure
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
    "EndpointResolutionCandidateError",
    "EndpointResolutionInfrastructureError",
    "CandidateDnsResolutionSession",
    "EndpointSafetyError",
    "PROVENANCE_STAGING_KIND",
    "PROVENANCE_STAGING_SCHEMA_VERSION",
    "SOURCE_POLICY_VERSION",
    "SOURCE_ID_VERSION",
    "SOURCE_KINDS",
    "count_proxy_domain_hostnames",
    "is_acceptable_public_ip",
    "load_provenance_staging",
    "merge_provenance_staging",
    "proxy_endpoint_safety_cache_key",
    "provenance_for_task",
    "safe_source_descriptor",
    "utc_timestamp",
    "validate_proxy_endpoint",
    "write_provenance_staging",
]
