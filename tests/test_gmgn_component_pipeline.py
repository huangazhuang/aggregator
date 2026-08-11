from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.cnb_gmgn_publish import stage_selection_v2_adapter
from scripts.gmgn_selection import GROUP_AUTO, GROUP_MANUAL_PRIORITY, V2_GROUP_NAMES
from tests.test_gmgn_selection import (
    candidate_record,
    measurement,
    region,
    selection_input,
)


class SelectionV2PublisherAdapterTests(unittest.TestCase):
    def temporary_directory(self):
        preferred = os.environ.get("AGGREGATOR_TEST_TMPDIR")
        if preferred:
            Path(preferred).mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=preferred or None)

    def test_adapter_is_default_off(self):
        self.assertIsNone(
            stage_selection_v2_adapter(
                enabled=False,
                selection_input_path="missing-private-input.json",
                output_dir="missing-output",
            )
        )

    def test_enabled_adapter_writes_ten_group_bundle_and_private_decisions(self):
        records = [candidate_record(index) for index in range(600, 604)]
        measurements = [
            measurement(600, within=14, response=14, first=7, second=7),
            measurement(601, within=10, response=10, first=5, second=5),
            measurement(602, within=0, response=1, first=0, second=0),
            measurement(603, within=18, response=18, first=9, second=9),
        ]
        regions = [
            region(600, country="HK"),
            region(601, country="JP"),
            region(602, country="KR"),
            region(603, country="US"),
        ]
        payload = selection_input(records, measurements, regions)
        with self.temporary_directory() as directory:
            root = Path(directory)
            private = root / ".cnb-runtime"
            private.mkdir()
            input_path = private / "selection-input.json"
            decisions_path = private / "selection-decisions.json"
            output = root / "public-cn-gmgn-v2"
            input_path.write_text(
                json.dumps(payload, ensure_ascii=False), encoding="utf-8"
            )

            result = stage_selection_v2_adapter(
                enabled=True,
                selection_input_path=str(input_path),
                output_dir=str(output),
                private_decisions_path=str(decisions_path),
            )

            self.assertIsNotNone(result)
            profile = yaml.safe_load((output / "clash.yaml").read_text(encoding="utf-8"))
            status = json.loads((output / "status.json").read_text(encoding="utf-8"))
            node_status = json.loads(
                (output / "node-status.json").read_text(encoding="utf-8")
            )
            decisions = json.loads(decisions_path.read_text(encoding="utf-8"))
            groups = {item["name"]: item for item in profile["proxy-groups"]}
            self.assertEqual(tuple(groups), V2_GROUP_NAMES)
            self.assertNotIn("Node 602", groups[GROUP_MANUAL_PRIORITY]["proxies"])
            self.assertNotIn("Node 601", groups[GROUP_AUTO]["proxies"])
            self.assertEqual(status["published_count"], 4)
            self.assertEqual(node_status["run_id"], status["run_id"])
            self.assertEqual(decisions["run_id"], status["run_id"])
            public_text = (output / "node-status.json").read_text(encoding="utf-8")
            self.assertNotIn("secret-", public_text)
            self.assertNotIn("node-600.example", public_text)

    def test_private_input_outside_runtime_is_rejected(self):
        with self.temporary_directory() as directory:
            root = Path(directory)
            input_path = root / "selection-input.json"
            input_path.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "private .cnb-runtime"):
                stage_selection_v2_adapter(
                    enabled=True,
                    selection_input_path=str(input_path),
                    output_dir=str(root / "output"),
                )


if __name__ == "__main__":
    unittest.main()
