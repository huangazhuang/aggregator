"""Shared validation and filtering helpers for publishing pipelines."""

from __future__ import annotations

import copy
import math
import re
from typing import Any, Iterable

import yaml

from scripts.proxy_identity import (
    canonical_proxy_fingerprint,
)
from scripts.proxy_schema import ProxySchemaError, validate_proxy_schema


BUILTIN_PROXY_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
REALITY_SHORT_ID = re.compile(r"[0-9a-fA-F]{0,16}")
PROXY_NAME_MAX_LENGTH = 96


class QuotedString(str):
    """String scalar that must retain explicit quotes in generated YAML."""


class ClashSafeDumper(yaml.SafeDumper):
    """Safe YAML dumper with Clash-specific scalar handling."""


def _quoted_string(dumper: yaml.Dumper, value: QuotedString) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style='"')


ClashSafeDumper.add_representer(QuotedString, _quoted_string)


def valid_reality_short_id(value: Any) -> bool:
    """Return whether a REALITY short ID satisfies Mihomo's hex requirements."""

    if not isinstance(value, str):
        return False
    return len(value) % 2 == 0 and REALITY_SHORT_ID.fullmatch(value) is not None


def normalize_reality_short_ids(
    proxies: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Copy proxies, quote valid short IDs, and reject malformed REALITY entries."""

    normalized: list[dict[str, Any]] = []
    rejected: list[str] = []
    for original in proxies:
        proxy = copy.deepcopy(original)
        reality = proxy.get("reality-opts")
        if not isinstance(reality, dict):
            normalized.append(proxy)
            continue

        short_id = reality.get("short-id")
        if not valid_reality_short_id(short_id):
            rejected.append(str(proxy.get("name", "unnamed")))
            continue

        # PyYAML otherwise emits values such as "08" and "54462e21"
        # without quotes. Go YAML then resolves them as numbers and Mihomo
        # aborts the whole configuration with "invalid REALITY short ID".
        reality["short-id"] = QuotedString(short_id)
        normalized.append(proxy)
    return normalized, rejected


def prepare_clash_profile(profile: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Return a copy safe for Mihomo serialization and rejected proxy names."""

    prepared = copy.deepcopy(profile)
    proxies = [item for item in prepared.get("proxies", []) if isinstance(item, dict)]
    prepared["proxies"], rejected = normalize_reality_short_ids(proxies)
    return prepared, rejected


def dump_clash_yaml(profile: dict[str, Any]) -> tuple[str, list[str]]:
    """Serialize a profile while preserving REALITY short IDs as strings."""

    prepared, rejected = prepare_clash_profile(profile)
    return (
        yaml.dump(
            prepared,
            Dumper=ClashSafeDumper,
            allow_unicode=True,
            sort_keys=False,
        ),
        rejected,
    )


def calculate_publish_floor(minimum: int, previous_count: int, retain_ratio: float) -> int:
    """Calculate the fail-closed floor for replacing a previous publication."""

    if minimum < 1:
        raise ValueError("minimum must be at least 1")
    if previous_count < 0:
        raise ValueError("previous_count cannot be negative")
    if not 0.0 <= retain_ratio <= 1.0:
        raise ValueError("retain_ratio must be between 0 and 1")
    return max(minimum, math.ceil(previous_count * retain_ratio))


def filter_profile_groups(profile: dict[str, Any], selected_names: Iterable[str]) -> None:
    """Remove stale proxy references while keeping groups and built-in targets."""

    groups = profile.get("proxy-groups", [])
    if not isinstance(groups, list):
        return

    selected = list(dict.fromkeys(str(name) for name in selected_names))
    selected_set = set(selected)
    group_names = {
        str(group.get("name"))
        for group in groups
        if isinstance(group, dict) and group.get("name")
    }
    allowed_refs = selected_set | group_names | BUILTIN_PROXY_NAMES

    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("proxies"), list):
            continue
        references = [str(item) for item in group["proxies"] if str(item) in allowed_refs]
        fixed = [item for item in references if item in group_names or item in BUILTIN_PROXY_NAMES]
        members = [item for item in selected if item in references]
        group["proxies"] = list(dict.fromkeys(fixed + members))


def filtered_profile(
    profile: dict[str, Any], selected_proxies: Iterable[dict[str, Any]]
) -> dict[str, Any]:
    """Build a profile containing only the selected proxies and valid group references."""

    output = copy.deepcopy(profile)
    selected = [copy.deepcopy(proxy) for proxy in selected_proxies]
    output["proxies"] = selected
    filter_profile_groups(output, [str(proxy.get("name", "")) for proxy in selected])
    return output


def _safe_proxy_name(value: Any) -> str:
    name = "".join(
        character
        for character in str(value or "")
        if ord(character) >= 32 and ord(character) != 127
    )
    return re.sub(r"\s+", " ", name).strip()[:PROXY_NAME_MAX_LENGTH].rstrip()


def _preferred_exact_duplicate_name(names: Iterable[str]) -> str:
    aliases = {_safe_proxy_name(name) for name in names}
    aliases.discard("")
    if not aliases:
        return "Node"
    return min(
        aliases,
        key=lambda name: (
            "ASIA-KEEP" not in name.upper(),
            name.casefold(),
            name,
        ),
    )


def _numbered_conflict_name(base: str, start: int, used: set[str]) -> str:
    index = max(start, 2)
    while index < 1_000_000:
        suffix = f"-{index}"
        root = base[: max(PROXY_NAME_MAX_LENGTH - len(suffix), 1)].rstrip() or "N"
        candidate = f"{root}{suffix}"
        if candidate not in used:
            return candidate
        index += 1
    raise ValueError("unable to allocate a unique proxy name")


def exact_unique_proxy_variants(
    proxies: Iterable[dict[str, Any]],
    *,
    reserved_names: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Keep one copy per canonical connection fingerprint with stable names.

    Candidate V2 must not use the legacy endpoint/credential heuristics in
    ``subscribe.clash.filter_proxies``.  Those heuristics intentionally fold
    HTTP proxies by endpoint and several protocols by only one credential,
    which discards valid transport, TLS, plugin, or cross-protocol variants.
    """

    grouped: dict[str, list[dict[str, Any]]] = {}
    for original in proxies:
        try:
            raw_proxy = validate_proxy_schema(copy.deepcopy(original))
        except ProxySchemaError as exc:
            raise ValueError("Candidate V2 proxy schema is unsupported") from exc
        fingerprint = canonical_proxy_fingerprint(raw_proxy)
        proxy = copy.deepcopy(raw_proxy)
        proxy["name"] = _safe_proxy_name(raw_proxy.get("name", "")) or "Node"
        grouped.setdefault(fingerprint, []).append(proxy)

    preferred_names = {
        fingerprint: _preferred_exact_duplicate_name(
            str(proxy.get("name", "")) for proxy in candidates
        )
        for fingerprint, candidates in grouped.items()
    }
    name_members: dict[str, list[str]] = {}
    for fingerprint, name in preferred_names.items():
        name_members.setdefault(name, []).append(fingerprint)
    for members in name_members.values():
        members.sort(
            key=lambda fingerprint: (
                -len(
                    {
                        _safe_proxy_name(proxy.get("name", ""))
                        for proxy in grouped[fingerprint]
                        if _safe_proxy_name(proxy.get("name", ""))
                    }
                ),
                fingerprint,
            )
        )
    used = set(BUILTIN_PROXY_NAMES) | {
        _safe_proxy_name(name) for name in reserved_names if _safe_proxy_name(name)
    }
    result: list[dict[str, Any]] = []
    for fingerprint in sorted(grouped):
        candidates = grouped[fingerprint]
        base = preferred_names[fingerprint]
        name = base
        base_ordinal = name_members[base].index(fingerprint) + 1
        if base_ordinal > 1 or name in used:
            name = _numbered_conflict_name(base, base_ordinal, used)

        representative = min(
            candidates,
            key=lambda proxy: (
                _safe_proxy_name(proxy.get("name", "")) != base,
                _safe_proxy_name(proxy.get("name", "")).casefold(),
                _safe_proxy_name(proxy.get("name", "")),
            ),
        )
        representative["name"] = name
        used.add(name)
        result.append(representative)
    return result


def build_candidate_v2_clash_profile(
    proxies: Iterable[dict[str, Any]],
    *,
    external_controller: str,
    test_url: str,
) -> dict[str, Any]:
    """Build a deterministic basic Clash profile without coarse proxy folding."""

    group_names = ("automatic", "🌐 Proxy")
    selected = exact_unique_proxy_variants(proxies, reserved_names=group_names)
    names = [str(proxy["name"]) for proxy in selected]
    return {
        "mixed-port": 7890,
        "external-controller": external_controller,
        "mode": "Rule",
        "log-level": "silent",
        "proxies": selected,
        "proxy-groups": [
            {
                "name": group_names[0],
                "type": "url-test",
                "proxies": names,
                "url": test_url,
                "interval": 300,
            },
            {
                "name": group_names[1],
                "type": "select",
                "proxies": [group_names[0], *names],
            },
        ],
        "rules": [f"MATCH,{group_names[1]}"],
    }
