from __future__ import annotations

import unittest

from scripts.gmgn_history import allocate_stable_output_names, sanitize_output_alias
from scripts.proxy_identity import candidate_id


KEY = b"stable-name-test-key"
KEY_VERSION = "stable-name-key-v1"
EPOCH = "identity-v1"


def identity(index: int) -> str:
    return candidate_id(
        {
            "name": f"Source {index}",
            "type": "ss",
            "server": f"node-{index}.example",
            "port": 10_000 + index,
            "cipher": "aes-128-gcm",
            "password": f"fixture-{index}",
        },
        key=KEY,
        identity_key_version=KEY_VERSION,
        identity_epoch=EPOCH,
    )


class StableOutputNameTests(unittest.TestCase):
    def test_input_reordering_and_alias_collision_are_deterministic(self) -> None:
        first, second = identity(1), identity(2)
        forward = allocate_stable_output_names(
            {}, {first: "Korea", second: "Korea"}
        )
        reversed_order = allocate_stable_output_names(
            {}, {second: "Korea", first: "Korea"}
        )
        self.assertEqual(forward, reversed_order)
        winner = min(first, second)
        loser = max(first, second)
        self.assertEqual(forward[winner], "Korea")
        self.assertEqual(forward[loser], f"Korea [{loser[-6:]}]")

    def test_existing_name_survives_source_rename_tier_change_and_recovery(self) -> None:
        existing, newcomer = identity(1), identity(2)
        previous = {
            existing: {
                "candidate_id": existing,
                "output_name": "Korea Stable",
                "current_state": "removed_bad_streak",
            }
        }
        allocated = allocate_stable_output_names(
            previous,
            {existing: "Completely Renamed", newcomer: "Korea Stable"},
        )
        self.assertEqual(allocated[existing], "Korea Stable")
        self.assertEqual(
            allocated[newcomer], f"Korea Stable [{newcomer[-6:]}]"
        )

    def test_reserved_empty_private_and_dynamic_aliases_use_safe_stable_names(self) -> None:
        aliases = {
            identity(1): "DIRECT",
            identity(2): "  ",
            identity(3): "8.8.8.8",
            identity(4): "https://secret.example/token",
            identity(5): "Japan Fast | 80ms",
            identity(6): "Korea Timeout",
        }
        allocated = allocate_stable_output_names({}, aliases)
        self.assertEqual(allocated[identity(5)], "Japan Fast")
        self.assertEqual(allocated[identity(6)], "Korea")
        for candidate in (identity(1), identity(2), identity(3), identity(4)):
            self.assertRegex(allocated[candidate], rf"^Node \[{candidate[-6:]}\]$")
        self.assertNotIn("DIRECT", allocated.values())
        serialized = "\n".join(allocated.values())
        self.assertNotIn("8.8.8.8", serialized)
        self.assertNotIn("https://", serialized)
        self.assertNotRegex(serialized.lower(), r"\b(?:80ms|timeout)\b")

    def test_long_unicode_alias_is_bounded_and_stable(self) -> None:
        candidate = identity(1)
        alias = "韩国稳定线路" * 30
        first = allocate_stable_output_names({}, {candidate: alias})[candidate]
        second = allocate_stable_output_names({}, {candidate: alias})[candidate]
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 80)

    def test_sanitizer_removes_only_dynamic_tail(self) -> None:
        self.assertEqual(sanitize_output_alias("KR 012 | 87ms"), "KR 012")
        self.assertEqual(sanitize_output_alias("Japan 02 - 95%"), "Japan 02")
        self.assertEqual(sanitize_output_alias("Korea Timeout"), "Korea")


if __name__ == "__main__":
    unittest.main()
