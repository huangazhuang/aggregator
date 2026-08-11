"""Recognition helpers for Asia nodes that must survive connectivity filters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


PREFERRED_ASIA_FLAGS = frozenset({"🇭🇰", "🇹🇼", "🇸🇬", "🇯🇵", "🇰🇷"})
PREFERRED_ASIA_MARKER_PATTERN = re.compile(r"\bASIA-KEEP\b|亚洲保留|亞洲保留", flags=re.I)
PREFERRED_ASIA_REGION_CODE_PATTERNS = {
    "HK": re.compile(r"(?<![a-z])(?:hk|hkg)(?=$|[^a-z])", flags=re.I),
    "TW": re.compile(r"(?<![a-z])(?:tw|twn|tpe|khh)(?=$|[^a-z])", flags=re.I),
    "SG": re.compile(r"(?<![a-z])(?:sg|sgp|sin)(?=$|[^a-z])", flags=re.I),
    "JP": re.compile(r"(?<![a-z])(?:jp|jpn|nrt|kix|hnd)(?=$|[^a-z])", flags=re.I),
    "KR": re.compile(r"(?<![a-z])(?:kr|kor|icn|pus)(?=$|[^a-z])", flags=re.I),
}
PREFERRED_ASIA_CODE_PATTERN = re.compile(
    "|".join(f"(?:{pattern.pattern})" for pattern in PREFERRED_ASIA_REGION_CODE_PATTERNS.values()),
    flags=re.I,
)
PREFERRED_ASIA_NAME_PATTERN = re.compile(
    r"Hong[\s._-]*Kong|Kowloon|Singapore|Japan|Tokyo|Osaka|Saitama|Yokohama|Nagoya|Fukuoka|Hokkaido|"
    r"(?:South[\s._-]*)?Korea|Seoul|Busan|Jeju|Taiwan|Taipei|New[\s._-]*Taipei|"
    r"Taichung|Tainan|Kaohsiung|Taoyuan|Changhua|"
    r"香港|九龙|九龍|台湾|台灣|新加坡|狮城|獅城|日本|日韩|日韓|韩国|韓國|南韩|南韓|"
    r"东京|東京|大阪|埼玉|横滨|橫濱|名古屋|福冈|福岡|北海道|"
    r"首尔|首爾|釜山|济州|濟州|"
    r"台北|臺北|新北|台中|臺中|台南|臺南|高雄|桃园|桃園|彰化",
    flags=re.I,
)
PREFERRED_ASIA_SHORT_PATTERNS = {
    "HK": re.compile(r"(?:^|[\s|/_()\[\]【】-])港[\s/_-]*\d{1,4}(?=$|\D)", flags=re.I),
    "TW": re.compile(r"(?:^|[\s|/_()\[\]【】-])(?:台|臺)[\s/_-]*\d{1,4}(?=$|\D)", flags=re.I),
    "JP": re.compile(r"(?:^|[\s|/_()\[\]【】-])日[\s/_-]*\d{1,4}(?=$|\D)", flags=re.I),
    "KR": re.compile(r"(?:^|[\s|/_()\[\]【】-])(?:韩|韓)[\s/_-]*\d{1,4}(?=$|\D)", flags=re.I),
}
PREFERRED_ASIA_SHORT_PATTERN = re.compile(
    "|".join(f"(?:{pattern.pattern})" for pattern in PREFERRED_ASIA_SHORT_PATTERNS.values()),
    flags=re.I,
)
STATUS_NODE_PATTERN = re.compile(
    r"流量|到期|过期|過期|剩余|剩餘|重置|更新|官网|官網|套餐|时间|時間|"
    r"traffic|expire|bandwidth|reset|subscription",
    flags=re.I,
)


def preferred_asia_include_pattern() -> str:
    """Return a regex suitable for selecting HK/TW/SG/JP/KR names in mixed feeds."""

    flags = "|".join(re.escape(flag) for flag in sorted(PREFERRED_ASIA_FLAGS))
    return "|".join(
        (
            flags,
            f"(?:{PREFERRED_ASIA_CODE_PATTERN.pattern})",
            f"(?:{PREFERRED_ASIA_NAME_PATTERN.pattern})",
            f"(?:{PREFERRED_ASIA_SHORT_PATTERN.pattern})",
        )
    )


def preferred_asia_region_hints(proxy: Mapping[str, Any] | Any) -> tuple[str, ...]:
    """Return deterministic HK/TW/SG/JP/KR hints without claiming verified egress."""

    if not isinstance(proxy, Mapping):
        return ()

    hints: set[str] = set()
    labels = [proxy.get(key, "") for key in ("name", "country", "region", "location")]
    for value in labels:
        label = str(value or "").strip()
        if not label or STATUS_NODE_PATTERN.search(label):
            continue

        for region, pattern in PREFERRED_ASIA_REGION_CODE_PATTERNS.items():
            if pattern.search(label):
                hints.add(region)
        for region, pattern in PREFERRED_ASIA_SHORT_PATTERNS.items():
            if pattern.search(label):
                hints.add(region)

        if "🇭🇰" in label or re.search(r"Hong[\s._-]*Kong|Kowloon|香港|九龙|九龍", label, flags=re.I):
            hints.add("HK")
        if "🇹🇼" in label or re.search(
            r"Taiwan|Taipei|New[\s._-]*Taipei|Taichung|Tainan|Kaohsiung|Taoyuan|Changhua|"
            r"台湾|台灣|台北|臺北|新北|台中|臺中|台南|臺南|高雄|桃园|桃園|彰化",
            label,
            flags=re.I,
        ):
            hints.add("TW")
        if "🇸🇬" in label or re.search(r"Singapore|新加坡|狮城|獅城", label, flags=re.I):
            hints.add("SG")
        if "🇯🇵" in label or re.search(
            r"Japan|Tokyo|Osaka|Saitama|Yokohama|Nagoya|Fukuoka|Hokkaido|"
            r"日本|东京|東京|大阪|埼玉|横滨|橫濱|名古屋|福冈|福岡|北海道",
            label,
            flags=re.I,
        ):
            hints.add("JP")
        if "🇰🇷" in label or re.search(
            r"(?:South[\s._-]*)?Korea|Seoul|Busan|Jeju|韩国|韓國|南韩|南韓|首尔|首爾|釜山|济州|濟州",
            label,
            flags=re.I,
        ):
            hints.add("KR")

    return tuple(region for region in ("HK", "JP", "KR", "SG", "TW") if region in hints)


def is_preferred_asian_proxy(proxy: Mapping[str, Any] | Any) -> bool:
    """Whether a proxy is in HK/TW/SG/JP/KR and must bypass connectivity filters."""

    if not isinstance(proxy, Mapping):
        return False

    labels = [proxy.get(key, "") for key in ("name", "country", "region", "location")]
    for value in labels:
        label = str(value or "").strip()
        if not label:
            continue

        if PREFERRED_ASIA_MARKER_PATTERN.search(label):
            return True
        if any(flag in label for flag in PREFERRED_ASIA_FLAGS):
            return True
        if preferred_asia_region_hints({"name": label}):
            return True

        # Short names such as "港 01" and "日-02" are common. Exclude
        # subscription-status pseudo nodes such as "下次更新时间".
        if not STATUS_NODE_PATTERN.search(label) and PREFERRED_ASIA_SHORT_PATTERN.search(label):
            return True

    return False
