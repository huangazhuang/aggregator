from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import build_manual_config


class ManualConfigContractTests(unittest.TestCase):
    def test_candidate_v2_rejects_inline_manual_subscriptions_without_writes(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            with (
                patch.dict(
                    os.environ,
                    {
                        "ENABLE_CANDIDATE_V2": "true",
                        "CLASH_SUBSCRIPTIONS_SECRET": "https://manual.invalid/sub?token=secret",
                        "CLASH_SUBSCRIPTION_URL_SECRET": "",
                    },
                    clear=False,
                ),
                patch(
                    "scripts.build_manual_config.Path",
                    side_effect=lambda value: root / value,
                ),
                self.assertRaisesRegex(
                    build_manual_config.ManualCandidateV2Error,
                    "does not support manual subscription mode",
                ),
            ):
                build_manual_config.main()

            self.assertFalse(
                (root / "subscribe/config/clash-verge.generated.json").exists()
            )
            self.assertFalse((root / "data/subscribes.txt").exists())

    def test_candidate_v2_rejects_remote_manual_source_before_fetch(self) -> None:
        with (
            patch.dict(
                os.environ,
                {
                    "ENABLE_CANDIDATE_V2": "true",
                    "CLASH_SUBSCRIPTIONS_SECRET": "",
                    "CLASH_SUBSCRIPTION_URL_SECRET": "https://private.invalid/list?token=secret",
                },
                clear=False,
            ),
            patch.object(build_manual_config.urllib.request, "urlopen") as urlopen,
            self.assertRaisesRegex(
                build_manual_config.ManualCandidateV2Error,
                "does not support manual subscription mode",
            ),
        ):
            build_manual_config.main()

        urlopen.assert_not_called()

    def test_legacy_manual_mode_still_writes_the_same_config(self) -> None:
        with tempfile.TemporaryDirectory(
            dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
        ) as directory:
            root = Path(directory)
            with (
                patch.dict(
                    os.environ,
                    {
                        "ENABLE_CANDIDATE_V2": "false",
                        "CLASH_SUBSCRIPTIONS_SECRET": "https://manual.invalid/sub?token=secret",
                        "CLASH_SUBSCRIPTION_URL_SECRET": "",
                    },
                    clear=False,
                ),
                patch(
                    "scripts.build_manual_config.Path",
                    side_effect=lambda value: root / value,
                ),
            ):
                self.assertEqual(build_manual_config.main(), 0)

            config = json.loads(
                (root / "subscribe/config/clash-verge.generated.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                config["domains"][0]["sub"],
                ["https://manual.invalid/sub?token=secret"],
            )
            self.assertEqual(
                (root / "data/subscribes.txt").read_text(encoding="utf-8"),
                "https://manual.invalid/sub?token=secret\n",
            )


if __name__ == "__main__":
    unittest.main()
