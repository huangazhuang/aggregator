#!/usr/bin/env python3
"""Apply the optional mainland-China TCP probe to a generated Clash profile."""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, os.path.abspath("subscribe"))

import clash  # noqa: E402


CACHE_FILE = Path("data/cn-fc-check.json")
CACHE_DAYS = 7
TCP_PROBE_SKIP_TYPES = {"tuic", "hysteria", "hysteria2"}


def should_probe_proxy(proxy: dict[str, Any]) -> bool:
    """TCP-check every protocol except transports that require UDP."""

    return str(proxy.get("type", "")).lower() not in TCP_PROBE_SKIP_TYPES


def endpoint_key(proxy: dict[str, Any]) -> str:
    server = str(proxy.get("server", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return ""
    return f"{server}:{port}" if server and 0 < port <= 65535 else ""


def load_cache(now: float) -> dict[str, dict[str, Any]]:
    try:
        cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        cache = {}
    if not isinstance(cache, dict):
        return {}
    return {
        str(key): value
        for key, value in cache.items()
        if isinstance(value, dict) and now - float(value.get("ts", 0)) < CACHE_DAYS * 86400
    }


def main() -> int:
    profile = Path("data") / os.environ.get("PROFILE_FILE", "clash.yaml")
    data = yaml.load(profile.read_text(encoding="utf-8", errors="ignore"), Loader=yaml.SafeLoader) or {}
    proxies = [proxy for proxy in data.get("proxies", []) if isinstance(proxy, dict)]
    if not proxies:
        print("No proxies found; skip China-side probe.")
        return 0

    now = time.time()
    cache = load_cache(now)
    endpoints: dict[str, tuple[str, int]] = {}
    for proxy in proxies:
        if not should_probe_proxy(proxy):
            continue
        key = endpoint_key(proxy)
        if key:
            server, _, port = key.rpartition(":")
            endpoints.setdefault(key, (server, int(port)))

    probe_url = os.environ.get("PROBE_URL", "")
    probe_token = os.environ.get("PROBE_TOKEN", "")
    todo = [key for key in endpoints if key not in cache]
    print(f"cn-check(FC): {len(endpoints)} endpoints, {len(todo)} new to probe, cache {len(cache)}")
    chunk_size = 500
    classification_totals: Counter[str] = Counter()
    for index in range(0, len(todo), chunk_size):
        batch = todo[index : index + chunk_size]
        request = urllib.request.Request(
            probe_url,
            data=json.dumps({"endpoints": batch, "timeout": 3.0}).encode(),
            headers={"Content-Type": "application/json", "X-Probe-Token": probe_token},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                result = json.loads(response.read().decode())
        except Exception as exc:
            print(f"::warning::FC probe failed ({exc}); keeping unprobed endpoints this round")
            break
        classification_totals.update(
            {
                str(name): int(count)
                for name, count in (result.get("classifications") or {}).items()
            }
        )
        for endpoint, ok in (result.get("ok") or {}).items():
            cache[str(endpoint)] = {"ok": bool(ok), "ts": now}

    if classification_totals:
        print(f"cn-check classifications: {dict(sorted(classification_totals.items()))}")

    CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    CACHE_FILE.write_text(json.dumps(cache, indent=1, sort_keys=True) + "\n", encoding="utf-8")

    blocked = {key for key, value in cache.items() if not value.get("ok")}
    kept: list[dict[str, Any]] = []
    dropped = 0
    for proxy in proxies:
        key = endpoint_key(proxy)
        if should_probe_proxy(proxy) and key and key in blocked:
            dropped += 1
            continue
        kept.append(proxy)

    line = (
        f"cn-check: dropped {dropped} TCP-unreachable, kept {len(kept)}/{len(proxies)} "
        f"(blocked cache {len(blocked)})"
    )
    print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(f"### China-side TCP probe\n- {line}\n")

    if not dropped or not kept:
        return 0

    config = {
        "mixed-port": 7890,
        "external-controller": clash.EXTERNAL_CONTROLLER,
        "mode": "Rule",
        "log-level": "silent",
    }
    config.update(clash.filter_proxies(kept))
    for group in config.get("proxy-groups", []):
        if group.get("type") == "url-test":
            group["url"] = os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/")

    with profile.open("w", encoding="utf-8") as handle:
        yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
        yaml.dump(config, handle, allow_unicode=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
