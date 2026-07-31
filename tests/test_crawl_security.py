from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

SUBSCRIBE_DIR = Path(__file__).resolve().parents[1] / "subscribe"
sys.path.insert(0, str(SUBSCRIBE_DIR))
try:
    from crawl import is_expired
finally:
    sys.path.remove(str(SUBSCRIBE_DIR))


class SubscriptionUserinfoTests(unittest.TestCase):
    def test_accepts_integer_usage_values(self) -> None:
        header = "upload=10; download=20; total=100; expire=2000"

        with patch("crawl.time.time", return_value=1000):
            self.assertEqual(is_expired(header), (True, False))

    def test_rejects_expired_integer_usage_values(self) -> None:
        header = "upload=10; download=20; total=30; expire=900"

        with patch("crawl.time.time", return_value=1000):
            self.assertEqual(is_expired(header), (False, True))

    def test_does_not_execute_subscription_header_expressions(self) -> None:
        marker = "AGGREGATOR_EVAL_EXECUTED"
        header = (
            "upload=__import__('os').environ.__setitem__"
            f"('{marker}', '1') or 0; download=0; total=100; expire="
        )

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(marker, None)
            self.assertEqual(is_expired(header), (True, False))
            self.assertNotIn(marker, os.environ)

    def test_malformed_values_preserve_fail_open_behavior(self) -> None:
        self.assertEqual(is_expired("upload=1.5; download=0; total=100"), (True, False))


if __name__ == "__main__":
    unittest.main()
