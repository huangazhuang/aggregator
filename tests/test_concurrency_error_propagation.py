from __future__ import annotations

import traceback
import unittest
from unittest.mock import patch

from scripts.candidate_sources import (
    EndpointResolutionInfrastructureError,
    EndpointSafetyError,
)
from subscribe import utils, workflow
from subscribe.workflow import TaskConfig


class MultiThreadRunErrorPropagationTests(unittest.TestCase):
    def test_ordinary_worker_errors_are_logged_and_keep_none_results(self) -> None:
        def worker(value: str) -> str:
            if value == "unsafe":
                raise EndpointSafetyError("unsafe candidate")
            if value == "invalid":
                raise ValueError("invalid source")
            return value.upper()

        with patch.object(utils.logger, "error") as log_error:
            results = utils.multi_thread_run(
                worker,
                ["first", "unsafe", "invalid", "last"],
                num_threads=2,
            )

        self.assertEqual(results, ["FIRST", None, None, "LAST"])
        self.assertEqual(log_error.call_count, 2)

    def test_dns_infrastructure_error_is_re_raised_without_logging_it(self) -> None:
        def worker(_value: str) -> str:
            try:
                raise OSError("resolver-secret")
            except OSError as cause:
                raise EndpointResolutionInfrastructureError(
                    "proxy endpoint DNS infrastructure failed"
                ) from cause

        with (
            patch.object(utils.logger, "error") as log_error,
            self.assertRaises(EndpointResolutionInfrastructureError) as raised,
        ):
            utils.multi_thread_run(worker, ["candidate"], num_threads=1)

        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn(
            "resolver-secret",
            "".join(traceback.format_exception(raised.exception)),
        )
        log_error.assert_not_called()

    def test_workflow_wrapper_does_not_hide_dns_infrastructure_error(self) -> None:
        task = TaskConfig(
            name="registered-source",
            bin_name="subconverter",
            candidate_source="test-source",
        )
        failure = EndpointResolutionInfrastructureError(
            "proxy endpoint DNS infrastructure failed"
        )

        with (
            patch.object(workflow.AirPort, "get_subscribe", return_value=("", "")),
            patch.object(workflow.AirPort, "parse", return_value=[{"name": "candidate"}]),
            patch(
                "scripts.asia_source_registry.enforce_registered_source_policy",
                side_effect=failure,
            ),
            self.assertRaises(EndpointResolutionInfrastructureError) as raised,
        ):
            utils.multi_thread_run(workflow.executewrapper, [task], num_threads=1)

        self.assertIs(raised.exception, failure)


if __name__ == "__main__":
    unittest.main()
