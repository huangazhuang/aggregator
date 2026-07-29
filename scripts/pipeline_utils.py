"""Shared validation and filtering helpers for publishing pipelines."""

from __future__ import annotations

import copy
import math
import re
from typing import Any, Iterable

import yaml


BUILTIN_PROXY_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}
REALITY_SHORT_ID = re.compile(r"[0-9a-fA-F]{0,16}")


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
