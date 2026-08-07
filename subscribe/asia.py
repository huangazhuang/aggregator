"""Recognition helpers for Asia nodes that must survive connectivity filters."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any


PREFERRED_ASIA_FLAGS = frozenset({"🇭🇰", "🇹🇼", "🇸🇬", "🇯🇵", "🇰🇷"})
PREFERRED_ASIA_MARKER_PATTERN = re.compile(r"\bASIA-KEEP\b|亚洲保留|亞洲保留", flags=re.I)
PREFERRED_ASIA_CODE_PATTERN = re.compile(
    r"(?<![a-z])(?:hkg?|twn?|sgp?|jpn?|kr|kor)(?=$|[^a-z])",
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
PREFERRED_ASIA_SHORT_PATTERN = re.compile(
    r"(?:^|[\s|/_()\[\]【】-])"
    r"(?:港|台|臺|新|日|韩|韓)"
    r"(?=$|[\s\d|/_()\[\]【】-])",
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
        if PREFERRED_ASIA_CODE_PATTERN.search(label) or PREFERRED_ASIA_NAME_PATTERN.search(label):
            return True

        # Short names such as "港 01" and "日-02" are common. Exclude
        # subscription-status pseudo nodes such as "下次更新时间".
        if not STATUS_NODE_PATTERN.search(label) and PREFERRED_ASIA_SHORT_PATTERN.search(label):
            return True

    return False
