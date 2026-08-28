#!/usr/bin/env python3
"""Build the generated crawler configuration used by Clash Verge Auto."""

from __future__ import annotations

import json
import os
import re
import urllib.request
from pathlib import Path

from scripts.asia_source_registry import external_asia_domains
from subscribe.asia import preferred_asia_include_pattern


COMMUNITY_SUBS = [
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/clash.yml",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/mfuu/v2ray/master/v2ray",
    "https://raw.githubusercontent.com/peasoft/NoMoreWalls/master/list.txt",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://raw.githubusercontent.com/anaer/Sub/main/clash.yaml",
    "https://raw.githubusercontent.com/Jsnzkpg/Jsnzkpg/Jsnzkpg/Jsnzkpg",
    "https://raw.githubusercontent.com/free18/v2ray/main/v.txt",
    "https://raw.githubusercontent.com/Ruk1ng001/freeSub/main/v2ray",
    "https://raw.githubusercontent.com/shaoyouvip/free/main/base64.txt",
    "https://raw.githubusercontent.com/go4sharing/sub/main/sub.yaml",
    "https://raw.githubusercontent.com/Barabama/FreeNodes/refs/heads/feat/ai-crawler-v2/nodes/merged.yaml",
    "https://raw.githubusercontent.com/Leon406/SubCrawler/master/sub/share/v2",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/clash-meta-2.yaml",
]
# Public node-pool URLs curated by hwanz/SSR-V2ray-Trojan-vpn. Trial-airport
# referral pages and client-app links from that README are intentionally omitted.
HWANZ_NODE_POOLS = [
    "https://links.bocchi2b.top/clash",
    "https://raw.githubusercontent.com/Misaka-blog/chromego_merge/main/sub/merged_proxies_new.yaml",
]
LINK_PATTERN = (
    r"|(?:vmess|trojan|ss|ssr|snell|hysteria2|vless|hysteria|tuic|anytls)://"
    r"[a-zA-Z0-9:.?+=@%&#_\-/]{10,}"
)
BASE_CRAWL_CONFIG = {
    "push_to": ["crawler"],
    "ignorede": True,
    "liveness": True,
    "publish_derivatives": True,
    "candidate_source_role": "dynamic",
    "rate": 20.0,
}
PREFERRED_ASIA_INCLUDE = preferred_asia_include_pattern()
ASIA_SOURCE_SPECS = [
    {
        "name": "asia-au1rxx-hk",
        "sub": [
            "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-HK.yaml"
        ],
        "rename": "^#@&#@香港 ",
        "include": "",
    },
    {
        "name": "asia-au1rxx-tw",
        "sub": [
            "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-TW.yaml"
        ],
        "rename": "^#@&#@台湾 ",
        "include": "",
    },
    {
        "name": "asia-au1rxx-sg",
        "sub": [
            "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-SG.yaml"
        ],
        "rename": "^#@&#@新加坡 ",
        "include": "",
    },
    {
        "name": "asia-au1rxx-jp",
        "sub": [
            "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-JP.yaml"
        ],
        "rename": "^#@&#@日本 ",
        "include": "",
    },
    {
        "name": "asia-au1rxx-kr",
        "sub": [
            "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/by-country/clash-KR.yaml"
        ],
        "rename": "^#@&#@韩国 ",
        "include": "",
    },
    {
        "name": "asia-multi-proxy-tested",
        "sub": [
            "https://raw.githubusercontent.com/4n0nymou3/multi-proxy-config-fetcher/main/configs/clash_configs_tested.yaml"
        ],
        "rename": "^#@&#@ASIA-KEEP ",
        "include": PREFERRED_ASIA_INCLUDE,
    },
    {
        "name": "asia-ovmvo-freesub",
        "sub": ["https://raw.githubusercontent.com/ovmvo/FreeSub/main/sub/permanent/mihomo.yaml"],
        "rename": "^#@&#@ASIA-KEEP ",
        "include": PREFERRED_ASIA_INCLUDE,
    },
    {
        "name": "asia-daily-free-vpn",
        "sub": [
            "https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/main/sub/ClashMeta.yml"
        ],
        "rename": "^#@&#@ASIA-KEEP ",
        "include": PREFERRED_ASIA_INCLUDE,
    },
    {
        "name": "asia-kooker-free-subs",
        "sub": ["https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/all.yaml"],
        "rename": "^#@&#@ASIA-KEEP ",
        "include": PREFERRED_ASIA_INCLUDE,
    },
]


def add_rotating_clashfree_feed(subscriptions: list[str]) -> None:
    """Resolve aiboboxx/clashfree's date-stamped file without failing the build."""

    try:
        headers = {"User-Agent": "aggregator"}
        token = os.environ.get("GH_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            "https://api.github.com/repos/aiboboxx/clashfree/contents/",
            headers=headers,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            entries = json.load(response)
        names = sorted(
            entry["name"]
            for entry in entries
            if re.match(r"^clash\d{8}\.ya?ml$", entry.get("name", ""))
        )
        if names:
            subscriptions.append(
                f"https://raw.githubusercontent.com/aiboboxx/clashfree/main/{names[-1]}"
            )
            print(f"aiboboxx/clashfree latest file: {names[-1]}")
    except Exception as exc:
        print(f"skip aiboboxx/clashfree: {exc}")


def telegram_user() -> dict:
    return {
        "enable": True,
        "include": LINK_PATTERN,
        "exclude": "",
        "config": dict(BASE_CRAWL_CONFIG),
        "push_to": ["crawler"],
    }


def twitter_user() -> dict:
    return {
        "enable": True,
        "num": 200,
        "include": "",
        "exclude": "",
        "config": dict(BASE_CRAWL_CONFIG),
        "push_to": ["crawler"],
    }


def asia_domains() -> list[dict]:
    """Build Asia-only source tasks whose nodes bypass later liveness filters."""

    return [
        {
            **source,
            "enable": True,
            "exclude": "",
            "push_to": ["crawler"],
            "ignorede": True,
            "liveness": False,
            "publish_derivatives": True,
            "candidate_source_role": "fixed",
            "rate": 20.0,
            "secure": False,
        }
        for source in ASIA_SOURCE_SPECS
    ]


def build_config() -> dict:
    subscriptions = list(COMMUNITY_SUBS)
    rotating_subscriptions: list[str] = []
    add_rotating_clashfree_feed(rotating_subscriptions)
    telegram_users = {
        name: telegram_user()
        for name in (
            "v2raydailyupdate",
            "vmessorg",
            "PrivateVPNs",
            "freev2rayssr",
            "proxy_mtm",
            "proxystore11",
            "yangmaoshare",
        )
    }
    twitter_users = {
        name: twitter_user()
        for name in (
            "v2raydailyupdate",
            "vpnfail",
            "freevpn724",
            "V2rayCollector",
            "freev2raydaily",
        )
    }
    return {
        "domains": [
            {
                "name": "community-aggregators",
                "sub": subscriptions,
                "enable": True,
                "rename": "",
                "include": "",
                "exclude": "",
                "push_to": ["crawler"],
                "ignorede": True,
                "liveness": True,
                "publish_derivatives": True,
                "candidate_source_role": "fixed",
                "rate": 20.0,
                "secure": False,
            }
        ]
        + (
            [
                {
                    "name": "community-rotating-clashfree",
                    "sub": rotating_subscriptions,
                    "enable": True,
                    "rename": "",
                    "include": "",
                    "exclude": "",
                    "push_to": ["crawler"],
                    "ignorede": True,
                    "liveness": True,
                    "publish_derivatives": True,
                    "candidate_source_role": "dynamic",
                    "rate": 20.0,
                    "secure": False,
                }
            ]
            if rotating_subscriptions
            else []
        )
        + [
            {
                "name": "community-hwanz-pools",
                "sub": list(HWANZ_NODE_POOLS),
                "enable": True,
                "rename": "",
                "include": "",
                "exclude": "",
                "push_to": ["crawler"],
                "ignorede": True,
                "liveness": True,
                "publish_derivatives": True,
                "candidate_source_role": "fixed",
                "rate": 20.0,
                "secure": False,
            }
        ]
        + asia_domains()
        + external_asia_domains(),
        "crawl": {
            "enable": True,
            "threshold": 10,
            "singlelink": True,
            "persist": {
                "subs": "crawler-subs-store",
                "proxies": "crawler-proxies-store",
            },
            "config": {
                "rename": "",
                "include": "",
                "exclude": "",
                **BASE_CRAWL_CONFIG,
                "secure": False,
            },
            "github": {
                "enable": True,
                "pages": 6,
                "push_to": ["crawler"],
                "exclude": "",
                "spams": [],
            },
            "duckduckgo": {
                "enable": True,
                "limits": 30,
                "push_to": ["crawler"],
                "exclude": "",
                "notinurl": ["github.com", "githubusercontent.com"],
            },
            "yahoo": {
                "enable": True,
                "limits": 30,
                "push_to": ["crawler"],
                "exclude": "",
                "notinurl": ["github.com", "githubusercontent.com"],
            },
            "google": {
                "enable": True,
                "limits": 100,
                "qdr": 30,
                "push_to": ["crawler"],
                "exclude": "",
                "notinurl": ["github.com", "githubusercontent.com"],
            },
            "yandex": {
                "enable": True,
                "pages": 1,
                "within": 30,
                "push_to": ["crawler"],
                "exclude": "",
                "notinurl": ["github.com", "githubusercontent.com"],
            },
            "telegram": {"enable": True, "pages": 12, "limits": 50, "users": telegram_users},
            "twitter": {"enable": True, "users": twitter_users},
            "repositories": [],
            "pages": [],
            "scripts": [
                {
                    "enable": True,
                    "script": "gitforks#collect_subs",
                    "params": {
                        "username": "wzdnzd",
                        "repository": "aggregator",
                        "sort": "newest",
                        "max_pages": int(os.environ.get("FORK_SCAN_PAGES", "2")),
                        "full_scan": os.environ.get("FULL_FORK_SCAN", "false").lower() == "true",
                        "persist": {"folderid": "", "fileid": "crawler-gitfork-subs.txt"},
                        "config": dict(BASE_CRAWL_CONFIG),
                        "remain": 0,
                        "life": 0,
                    },
                },
                {
                    "enable": True,
                    "script": "v2rayse#fetch",
                    "params": {
                        "url": "https://s3.v2rayse.com",
                        "nodebuf_url": "https://nodebuf.com/api/public/proxy-cache",
                        "nodebuf_max_nodes": 100,
                        "nopublic": True,
                        "types": [
                            "ss",
                            "ssr",
                            "vmess",
                            "trojan",
                            "tuic",
                            "snell",
                            "vless",
                            "hysteria2",
                            "hysteria",
                            "http",
                            "socks5",
                            "anytls",
                        ],
                        "persist": {
                            "proxies": {"folderid": "", "fileid": "crawler-v2rayse.txt"},
                            "modified": {
                                "folderid": "",
                                "fileid": "crawler-v2rayse-modified.json",
                            },
                        },
                        "config": dict(BASE_CRAWL_CONFIG),
                    },
                },
            ],
        },
        "groups": {
            "crawler": {
                "emoji": True,
                "list": False,
                "targets": {"clash": "crawler-clash-local"},
            }
        },
        "storage": {
            "engine": "local",
            "items": {
                "crawler-clash-local": {"folderid": "", "fileid": "crawler-clash.yaml"},
                "crawler-subs-store": {"folderid": "", "fileid": "crawler-subs.json"},
                "crawler-proxies-store": {"folderid": "", "fileid": "crawler-proxies.txt"},
            },
        },
        "delay": 10000,
    }


def main() -> int:
    path = Path("subscribe/config/clash-verge-crawler.generated.json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_config(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
