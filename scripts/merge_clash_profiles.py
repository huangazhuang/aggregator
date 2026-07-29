#!/usr/bin/env python3
"""Merge collected and crawled Clash profiles for the publishing workflow."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import yaml

sys.path.insert(0, os.path.abspath("subscribe"))

import clash  # noqa: E402


def main() -> int:
    output = Path("data") / os.environ.get("PROFILE_FILE", "clash.yaml")
    sources = [Path("data/collect-clash.yaml"), Path("data/crawler-clash.yaml")]
    proxies: list[dict] = []

    for source in sources:
        if not source.is_file() or source.stat().st_size <= 0:
            continue
        try:
            data = yaml.load(source.read_text(encoding="utf-8", errors="ignore"), Loader=yaml.SafeLoader) or {}
        except Exception:
            data = {}
        items = data.get("proxies", [])
        if isinstance(items, list):
            proxies.extend(item for item in items if isinstance(item, dict))
            print(f"{source}: {len(items)} proxies")

    if not proxies:
        print("No proxies found to merge.")
        return 1

    config = {
        "mixed-port": 7890,
        "external-controller": clash.EXTERNAL_CONTROLLER,
        "mode": "Rule",
        "log-level": "silent",
    }
    config.update(clash.filter_proxies(proxies))
    for group in config.get("proxy-groups", []):
        if group.get("type") == "url-test":
            group["url"] = os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/")

    with output.open("w", encoding="utf-8") as handle:
        yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
        yaml.dump(config, handle, allow_unicode=True)
    print(f"merged {len(proxies)} source proxies into {len(config.get('proxies', []))} unique proxies")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
