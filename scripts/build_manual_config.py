#!/usr/bin/env python3
"""Build the workflow configuration for user-supplied subscription URLs."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path


class ManualCandidateV2Error(ValueError):
    """Raised when private manual subscriptions cannot satisfy V2 provenance."""


def extract_urls(raw: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    for line in raw.replace("\r", "\n").split("\n"):
        for part in re.split(r"[\s,]+", line):
            url = part.strip().strip("'\"<>").rstrip(",;)]")
            if not url.startswith(("http://", "https://")) or url in seen:
                continue
            urls.append(url)
            seen.add(url)
    return urls


def main() -> int:
    raw = os.environ.get("CLASH_SUBSCRIPTIONS_SECRET", "")
    remote = os.environ.get("CLASH_SUBSCRIPTION_URL_SECRET", "")
    candidate_v2 = os.environ.get("ENABLE_CANDIDATE_V2", "").strip().lower() == "true"
    if candidate_v2 and (extract_urls(raw) or remote.strip()):
        raise ManualCandidateV2Error(
            "Candidate V2 does not support manual subscription mode; "
            "disable Candidate V2 or remove the manual subscription secrets"
        )
    if remote:
        request = urllib.request.Request(remote, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(request, timeout=60) as response:
            raw += "\n" + response.read().decode("utf-8", errors="ignore")

    urls = extract_urls(raw)
    if not urls:
        print("manual=false")
        return 0

    config = {
        "domains": [
            {
                "name": "manual-subscriptions",
                "sub": urls,
                "enable": True,
                "rename": "",
                "include": "",
                "exclude": "",
                "push_to": ["clash-verge"],
                "ignorede": True,
                "liveness": True,
                "rate": 20.0,
                "secure": False,
            }
        ],
        "crawl": {"enable": False},
        "groups": {
            "clash-verge": {
                "emoji": True,
                "list": False,
                "targets": {"clash": "clash-local"},
            }
        },
        "storage": {
            "engine": "local",
            "items": {"clash-local": {"folderid": "", "fileid": "clash.yaml"}},
        },
        "delay": 10000,
    }

    config_path = Path("subscribe/config/clash-verge.generated.json")
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    data_path = Path("data/subscribes.txt")
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_text("\n".join(urls) + "\n", encoding="utf-8")
    print(f"manual=true count={len(urls)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
