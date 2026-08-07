#!/usr/bin/env python3
"""Generate GitHub output-branch status and README files."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import yaml

from subscribe.asia import is_preferred_asian_proxy


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True)
    parser.add_argument("--public-dir", required=True)
    parser.add_argument("--profile-url", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--alive-check", required=True)
    parser.add_argument("--main-sha", default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profile = Path(args.profile)
    public = Path(args.public_dir)
    public.mkdir(parents=True, exist_ok=True)
    content = profile.read_bytes()
    try:
        data = yaml.safe_load(content) or {}
        proxies = [proxy for proxy in data.get("proxies", []) if isinstance(proxy, dict)]
        proxy_count = len(proxies)
        protected_asia_count = sum(is_preferred_asian_proxy(proxy) for proxy in proxies)
    except Exception:
        proxy_count = 0
        protected_asia_count = 0

    run_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    status = {
        "run_at": run_at,
        "mode": args.mode,
        "alive_check": args.alive_check,
        "proxy_count": proxy_count,
        "protected_asia_count": protected_asia_count,
        "profile_url": args.profile_url,
        "profile_sha256": hashlib.sha256(content).hexdigest(),
        "main_sha": args.main_sha or os.environ.get("GITHUB_SHA", ""),
    }
    (public / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (public / "last-run.txt").write_text(run_at + "\n", encoding="utf-8")
    (public / "README.md").write_text(
        "# Clash Verge Auto Profile\n\n"
        "Subscription URL:\n\n"
        f"{args.profile_url}\n\n"
        f"Last run: {run_at}\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
