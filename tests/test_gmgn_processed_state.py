from __future__ import annotations

import copy
import unittest

from scripts.gmgn_processed_state import (
    ProcessedStateError,
    build_attempt,
    decide_attempt,
    processed_ref,
    transition,
    validate_record,
)


SOURCE = "1" * 64
T0 = "2026-08-11T00:00:00Z"
T1 = "2026-08-11T00:01:00Z"
T2 = "2026-08-11T00:02:00Z"
T3 = "2026-08-11T00:03:00Z"
T4 = "2026-08-11T00:04:00Z"
T5 = "2026-08-11T00:05:00Z"


class ProcessedStateTests(unittest.TestCase):
    def primary_running(self):
        primary = build_attempt(SOURCE)
        return primary, transition(None, attempt=primary, state="running", at=T0)

    def test_primary_records_queue_then_running_and_active_is_noop(self) -> None:
        primary, record = self.primary_running()
        self.assertEqual([item["state"] for item in record["events"]], ["queued", "running"])
        decision, repeated = decide_attempt(
            SOURCE, retry_token=None, accepted=False, record=record
        )
        self.assertEqual(decision, "noop_active")
        self.assertEqual(repeated.attempt_id, primary.attempt_id)
        self.assertEqual(
            processed_ref(SOURCE),
            f"refs/heads/clash-cn-gmgn-v2-processed/{SOURCE}",
        )

    def test_primary_queue_can_finish_failed_or_rejected(self) -> None:
        decision, primary = decide_attempt(
            SOURCE, retry_token=None, accepted=False, record=None
        )
        self.assertEqual(decision, "queue")
        running = transition(None, attempt=primary, state="running", at=T0)

        failed = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        self.assertEqual(failed["state"], "failed_infrastructure")
        self.assertEqual(
            [item["state"] for item in failed["events"]],
            ["queued", "running", "failed_infrastructure"],
        )

        rejected = transition(running, attempt=primary, state="rejected", at=T1)
        self.assertEqual(rejected["state"], "rejected")
        self.assertEqual(
            [item["state"] for item in rejected["events"]],
            ["queued", "running", "rejected"],
        )

    def test_failed_attempt_requires_a_new_retry_token_and_binds_retry_of(self) -> None:
        primary, running = self.primary_running()
        failed = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        decision, retry = decide_attempt(
            SOURCE, retry_token="infra-1", accepted=False, record=failed
        )
        self.assertEqual(decision, "retry_failed_infrastructure")
        self.assertEqual(retry.retry_of, primary.attempt_id)
        retried = transition(failed, attempt=retry, state="running", at=T2)
        self.assertEqual(
            [item["state"] for item in retried["events"][-2:]],
            ["queued", "running"],
        )
        failed_retry = transition(
            retried, attempt=retry, state="failed_infrastructure", at="2026-08-11T00:03:00Z"
        )
        with self.assertRaisesRegex(ProcessedStateError, "already been used"):
            decide_attempt(
                SOURCE, retry_token="infra-1", accepted=False, record=failed_retry
            )

    def test_retry_chain_binds_each_attempt_to_the_immediately_prior_failure(self) -> None:
        primary, running = self.primary_running()
        failed_primary = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        _decision, retry_one = decide_attempt(
            SOURCE, retry_token="infra-chain-1", accepted=False, record=failed_primary
        )
        running_one = transition(
            failed_primary, attempt=retry_one, state="running", at=T2
        )
        failed_one = transition(
            running_one, attempt=retry_one, state="failed_infrastructure", at=T3
        )

        _decision, retry_two = decide_attempt(
            SOURCE, retry_token="infra-chain-2", accepted=False, record=failed_one
        )
        self.assertEqual(retry_one.retry_of, primary.attempt_id)
        self.assertEqual(retry_two.retry_of, retry_one.attempt_id)
        self.assertNotEqual(retry_two.attempt_id, retry_one.attempt_id)
        running_two = transition(
            failed_one, attempt=retry_two, state="running", at=T4
        )
        self.assertEqual(
            [
                event["attempt_id"]
                for event in running_two["events"]
                if event["state"] == "queued"
            ],
            [primary.attempt_id, retry_one.attempt_id, retry_two.attempt_id],
        )

    def test_retry_token_cannot_be_reused_after_a_later_retry(self) -> None:
        primary, running = self.primary_running()
        failed_primary = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        _decision, retry_one = decide_attempt(
            SOURCE, retry_token="infra-reuse-1", accepted=False, record=failed_primary
        )
        running_one = transition(
            failed_primary, attempt=retry_one, state="running", at=T2
        )
        failed_one = transition(
            running_one, attempt=retry_one, state="failed_infrastructure", at=T3
        )
        _decision, retry_two = decide_attempt(
            SOURCE, retry_token="infra-reuse-2", accepted=False, record=failed_one
        )
        running_two = transition(
            failed_one, attempt=retry_two, state="running", at=T4
        )
        failed_two = transition(
            running_two, attempt=retry_two, state="failed_infrastructure", at=T5
        )

        with self.assertRaisesRegex(ProcessedStateError, "already been used"):
            decide_attempt(
                SOURCE,
                retry_token="infra-reuse-1",
                accepted=False,
                record=failed_two,
            )

    def test_record_rejects_a_historical_retry_attempt_replayed_later(self) -> None:
        primary, running = self.primary_running()
        failed_primary = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        _decision, retry_one = decide_attempt(
            SOURCE, retry_token="infra-replay-1", accepted=False, record=failed_primary
        )
        running_one = transition(
            failed_primary, attempt=retry_one, state="running", at=T2
        )
        failed_one = transition(
            running_one, attempt=retry_one, state="failed_infrastructure", at=T3
        )
        _decision, retry_two = decide_attempt(
            SOURCE, retry_token="infra-replay-2", accepted=False, record=failed_one
        )
        running_two = transition(
            failed_one, attempt=retry_two, state="running", at=T4
        )
        failed_two = transition(
            running_two, attempt=retry_two, state="failed_infrastructure", at=T5
        )
        _decision, retry_three = decide_attempt(
            SOURCE, retry_token="infra-replay-3", accepted=False, record=failed_two
        )
        running_three = transition(
            failed_two,
            attempt=retry_three,
            state="running",
            at="2026-08-11T00:06:00Z",
        )

        replayed = copy.deepcopy(running_three)
        replayed["attempt_id"] = retry_one.attempt_id
        replayed["retry_token_sha256"] = retry_one.retry_token_sha256
        for event in replayed["events"][-2:]:
            event["attempt_id"] = retry_one.attempt_id
        with self.assertRaisesRegex(ProcessedStateError, "retry history is invalid"):
            validate_record(replayed)

    def test_retry_self_loop_is_rejected(self) -> None:
        primary, running = self.primary_running()
        failed = transition(
            running, attempt=primary, state="failed_infrastructure", at=T1
        )
        _decision, retry = decide_attempt(
            SOURCE, retry_token="infra-loop", accepted=False, record=failed
        )
        retried = transition(failed, attempt=retry, state="running", at=T2)
        self_loop = copy.deepcopy(retried)
        self_loop["retry_of"] = self_loop["attempt_id"]
        with self.assertRaisesRegex(ProcessedStateError, "retry processed.*binding"):
            validate_record(self_loop)

    def test_rejected_cannot_be_retried_but_authoritative_acceptance_wins(self) -> None:
        primary, running = self.primary_running()
        rejected = transition(running, attempt=primary, state="rejected", at=T1)
        with self.assertRaisesRegex(ProcessedStateError, "recorded failed"):
            decide_attempt(
                SOURCE, retry_token="infra-2", accepted=False, record=rejected
            )
        decision, _attempt = decide_attempt(
            SOURCE, retry_token="infra-2", accepted=True, record=rejected
        )
        self.assertEqual(decision, "noop_accepted")

    def test_external_authoritative_acceptance_needs_no_processed_state(self) -> None:
        decision, primary = decide_attempt(
            SOURCE, retry_token=None, accepted=True, record=None
        )
        self.assertEqual(decision, "noop_accepted")
        self.assertIsNone(primary.retry_of)

        retry_decision, retry = decide_attempt(
            SOURCE,
            retry_token="infra-authoritative",
            accepted=True,
            record=None,
        )
        self.assertEqual(retry_decision, "noop_accepted")
        self.assertIsNone(retry.retry_of)

    def test_missing_primary_and_orphan_running_have_controlled_recovery(self) -> None:
        decision, retry = decide_attempt(
            SOURCE,
            retry_token="infra-missing",
            accepted=False,
            record=None,
            queued_primary=True,
        )
        self.assertEqual(decision, "retry_failed_infrastructure")
        with self.assertRaisesRegex(ProcessedStateError, "first processed"):
            transition(None, attempt=retry, state="running", at=T1)
        recovered = transition(
            None,
            attempt=retry,
            state="running",
            at=T1,
            allow_missing_primary=True,
        )
        self.assertEqual(
            [item["state"] for item in recovered["events"]],
            ["queued", "failed_infrastructure", "queued", "running"],
        )

        _primary, orphan = self.primary_running()
        _decision, retry2 = decide_attempt(
            SOURCE, retry_token="infra-orphan", accepted=False, record=orphan
        )
        recovered2 = transition(orphan, attempt=retry2, state="running", at=T1)
        self.assertEqual(
            [item["state"] for item in recovered2["events"][-3:]],
            ["failed_infrastructure", "queued", "running"],
        )

    def test_noncanonical_time_attempt_binding_and_bad_event_replay_fail_closed(self) -> None:
        _primary, record = self.primary_running()
        self.assertEqual(validate_record(record)["updated_at"], T0)
        bad_time = copy.deepcopy(record)
        bad_time["updated_at"] = "2026-08-11T08:00:00+08:00"
        bad_time["events"][-1]["at"] = bad_time["updated_at"]
        with self.assertRaisesRegex(ProcessedStateError, "canonical UTC"):
            validate_record(bad_time)

        bad_attempt = copy.deepcopy(record)
        bad_attempt["attempt_id"] = "f" * 24
        bad_attempt["events"][-1]["attempt_id"] = "f" * 24
        with self.assertRaisesRegex(ProcessedStateError, "primary.*binding"):
            validate_record(bad_attempt)

        bad_events = copy.deepcopy(record)
        bad_events["events"] = [bad_events["events"][1]]
        with self.assertRaisesRegex(ProcessedStateError, "start queued"):
            validate_record(bad_events)

    def test_schema_and_event_chronology_are_strict(self) -> None:
        _primary, record = self.primary_running()

        missing_field = copy.deepcopy(record)
        del missing_field["retry_token_sha256"]
        with self.assertRaisesRegex(ProcessedStateError, "fields.*unexpected"):
            validate_record(missing_field)

        extra_field = copy.deepcopy(record)
        extra_field["accepted"] = False
        with self.assertRaisesRegex(ProcessedStateError, "fields.*unexpected"):
            validate_record(extra_field)

        unsupported_schema = copy.deepcopy(record)
        unsupported_schema["schema_version"] = 2
        with self.assertRaisesRegex(ProcessedStateError, "schema is unsupported"):
            validate_record(unsupported_schema)

        out_of_order = copy.deepcopy(record)
        out_of_order["events"][0]["at"] = T1
        with self.assertRaisesRegex(ProcessedStateError, "not chronological"):
            validate_record(out_of_order)


if __name__ == "__main__":
    unittest.main()
