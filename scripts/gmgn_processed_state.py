#!/usr/bin/env python3
"""Strict processed-source state machine for the GMGN V2 controlled ref."""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping


KIND = "cnb-gmgn-v2-processed-source"
SCHEMA_VERSION = 1
PROCESSED_REF_PREFIX = "clash-cn-gmgn-v2-processed"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ATTEMPT_RE = re.compile(r"^[0-9a-f]{24}$")
RETRY_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STATES = frozenset({"running", "failed_infrastructure", "rejected"})
EVENT_STATES = frozenset({"queued", *STATES})
FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "source_sha256",
        "state",
        "attempt_id",
        "retry_of",
        "retry_token_sha256",
        "updated_at",
        "events",
    }
)
EVENT_FIELDS = frozenset({"state", "attempt_id", "retry_of", "at"})


class ProcessedStateError(ValueError):
    """A processed-source record or transition is invalid."""


@dataclass(frozen=True)
class Attempt:
    source_sha256: str
    attempt_id: str
    retry_of: str | None
    retry_token_sha256: str | None


def _source(value: Any) -> str:
    text = str(value or "").lower()
    if not SHA256_RE.fullmatch(text):
        raise ProcessedStateError("processed source SHA is malformed")
    return text


def _attempt(value: Any) -> str:
    text = str(value or "").lower()
    if not ATTEMPT_RE.fullmatch(text):
        raise ProcessedStateError("attempt ID is malformed")
    return text


def _timestamp(value: Any) -> str:
    text = str(value or "")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProcessedStateError("processed timestamp is malformed") from exc
    if parsed.tzinfo is None:
        raise ProcessedStateError("processed timestamp lacks a timezone")
    canonical = parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )
    if text != canonical:
        raise ProcessedStateError("processed timestamp is not canonical UTC")
    return canonical


def processed_ref(source_sha256: str) -> str:
    return f"refs/heads/{PROCESSED_REF_PREFIX}/{_source(source_sha256)}"


def primary_attempt_id(source_sha256: str) -> str:
    source = _source(source_sha256)
    return hashlib.sha256(f"gmgn-v2-primary\0{source}".encode("ascii")).hexdigest()[:24]


def build_attempt(source_sha256: str, retry_token: str | None = None) -> Attempt:
    source = _source(source_sha256)
    if retry_token is None:
        return Attempt(source, primary_attempt_id(source), None, None)
    token = str(retry_token)
    if not RETRY_TOKEN_RE.fullmatch(token):
        raise ProcessedStateError("retry token is malformed")
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    attempt_id = hashlib.sha256(
        f"gmgn-v2-retry\0{source}\0{token_hash}".encode("ascii")
    ).hexdigest()[:24]
    return Attempt(source, attempt_id, None, token_hash)


def _retry_attempt_id(source: str, token_hash: str) -> str:
    return hashlib.sha256(
        f"gmgn-v2-retry\0{source}\0{token_hash}".encode("ascii")
    ).hexdigest()[:24]


def validate_record(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping) or frozenset(raw) != FIELDS:
        raise ProcessedStateError("processed-source fields are incomplete or unexpected")
    value = copy.deepcopy(dict(raw))
    if value["kind"] != KIND or value["schema_version"] != SCHEMA_VERSION:
        raise ProcessedStateError("processed-source schema is unsupported")
    value["source_sha256"] = _source(value["source_sha256"])
    if value["state"] not in STATES:
        raise ProcessedStateError("processed-source state is unsupported")
    value["attempt_id"] = _attempt(value["attempt_id"])
    value["retry_of"] = None if value["retry_of"] is None else _attempt(value["retry_of"])
    token_hash = value["retry_token_sha256"]
    if token_hash is not None and (
        not isinstance(token_hash, str) or not SHA256_RE.fullmatch(token_hash)
    ):
        raise ProcessedStateError("processed retry token hash is malformed")
    if value["retry_of"] is None:
        if token_hash is not None or value["attempt_id"] != primary_attempt_id(
            value["source_sha256"]
        ):
            raise ProcessedStateError("primary processed attempt binding is invalid")
    elif (
        token_hash is None
        or value["retry_of"] == value["attempt_id"]
        or value["attempt_id"]
        != _retry_attempt_id(value["source_sha256"], token_hash)
    ):
        raise ProcessedStateError("retry processed attempt binding is invalid")
    value["updated_at"] = _timestamp(value["updated_at"])
    if not isinstance(value["events"], list) or not value["events"]:
        raise ProcessedStateError("processed-source events are missing")
    events: list[dict[str, Any]] = []
    for raw_event in value["events"]:
        if not isinstance(raw_event, Mapping) or frozenset(raw_event) != EVENT_FIELDS:
            raise ProcessedStateError("processed-source event is malformed")
        event = dict(raw_event)
        if event["state"] not in EVENT_STATES:
            raise ProcessedStateError("processed-source event state is unsupported")
        event["attempt_id"] = _attempt(event["attempt_id"])
        event["retry_of"] = None if event["retry_of"] is None else _attempt(event["retry_of"])
        event["at"] = _timestamp(event["at"])
        events.append(event)
    if events != sorted(events, key=lambda item: item["at"]):
        raise ProcessedStateError("processed-source events are not chronological")
    queued_attempt_ids: set[str] = set()
    for index, event in enumerate(events):
        if index == 0:
            if (
                event["state"] != "queued"
                or event["attempt_id"] != primary_attempt_id(value["source_sha256"])
                or event["retry_of"] is not None
            ):
                raise ProcessedStateError(
                    "processed-source history must start queued with the primary attempt"
                )
            queued_attempt_ids.add(event["attempt_id"])
            continue
        prior = events[index - 1]
        if event["state"] == "queued":
            if (
                prior["state"] not in {"failed_infrastructure", "running"}
                or event["retry_of"] != prior["attempt_id"]
                or event["attempt_id"] == prior["attempt_id"]
                or event["attempt_id"] in queued_attempt_ids
            ):
                raise ProcessedStateError("processed retry history is invalid")
            queued_attempt_ids.add(event["attempt_id"])
        elif event["state"] == "running":
            if (
                prior["state"] != "queued"
                or event["attempt_id"] != prior["attempt_id"]
                or event["retry_of"] != prior["retry_of"]
            ):
                raise ProcessedStateError("processed running history is invalid")
        else:
            allowed_prior = (
                {"queued", "running"}
                if event["state"] == "failed_infrastructure"
                else {"running"}
            )
            if (
                prior["state"] not in allowed_prior
                or event["attempt_id"] != prior["attempt_id"]
                or event["retry_of"] != prior["retry_of"]
            ):
                raise ProcessedStateError("processed terminal history is invalid")
    latest = events[-1]
    if (
        latest["state"] != value["state"]
        or latest["attempt_id"] != value["attempt_id"]
        or latest["retry_of"] != value["retry_of"]
        or latest["at"] != value["updated_at"]
    ):
        raise ProcessedStateError("processed-source latest event binding mismatch")
    value["events"] = events
    return value


def decide_attempt(
    source_sha256: str,
    *,
    retry_token: str | None,
    accepted: bool,
    record: Mapping[str, Any] | None,
    queued_primary: bool = False,
) -> tuple[str, Attempt]:
    source = _source(source_sha256)
    current = validate_record(record) if record is not None else None
    base = build_attempt(source, retry_token)
    if accepted:
        return "noop_accepted", base
    if retry_token is None:
        if current is None:
            return "queue", base
        if current["state"] == "running":
            return "noop_active", base
        raise ProcessedStateError("failed source requires an explicit infrastructure retry")
    if current is not None and base.attempt_id in {
        event["attempt_id"] for event in current["events"]
    }:
        raise ProcessedStateError("retry token has already been used for this source")
    if current is None or current["state"] != "failed_infrastructure":
        if current is None and queued_primary:
            return "retry_failed_infrastructure", Attempt(
                source,
                base.attempt_id,
                primary_attempt_id(source),
                base.retry_token_sha256,
            )
        if current is not None and current["state"] == "running":
            # The CNB pipeline owns a single wait=true lock.  A retry can reach
            # preflight only after the earlier holder has stopped, so a
            # remaining running record is an orphan from a hard-killed runner.
            return "retry_failed_infrastructure", Attempt(
                source,
                base.attempt_id,
                current["attempt_id"],
                base.retry_token_sha256,
            )
        raise ProcessedStateError("infrastructure retry requires a recorded failed attempt")
    return "retry_failed_infrastructure", Attempt(
        source, base.attempt_id, current["attempt_id"], base.retry_token_sha256
    )


def transition(
    previous: Mapping[str, Any] | None,
    *,
    attempt: Attempt,
    state: str,
    at: str,
    allow_missing_primary: bool = False,
) -> dict[str, Any]:
    if state not in STATES:
        raise ProcessedStateError("processed transition state is unsupported")
    when = _timestamp(at)
    current = validate_record(previous) if previous is not None else None
    if current is None:
        allowed_missing_retry = (
            allow_missing_primary
            and state == "running"
            and attempt.retry_of == primary_attempt_id(attempt.source_sha256)
        )
        if state != "running" or (attempt.retry_of is not None and not allowed_missing_retry):
            raise ProcessedStateError("first processed transition must start a primary run")
        if allowed_missing_retry:
            primary = primary_attempt_id(attempt.source_sha256)
            events: list[dict[str, Any]] = [
                {"state": "queued", "attempt_id": primary, "retry_of": None, "at": when},
                {
                    "state": "failed_infrastructure",
                    "attempt_id": primary,
                    "retry_of": None,
                    "at": when,
                },
            ]
        else:
            events = []
    else:
        if current["source_sha256"] != attempt.source_sha256:
            raise ProcessedStateError("processed transition source mismatch")
        if state == "running":
            if current["state"] not in {"failed_infrastructure", "running"} or attempt.retry_of != current["attempt_id"]:
                raise ProcessedStateError("retry does not follow the recorded failed attempt")
        elif current["state"] != "running" or current["attempt_id"] != attempt.attempt_id:
            raise ProcessedStateError("terminal transition does not match the running attempt")
        events = list(current["events"])
        if state == "running" and current["state"] == "running":
            events.append(
                {
                    "state": "failed_infrastructure",
                    "attempt_id": current["attempt_id"],
                    "retry_of": current["retry_of"],
                    "at": when,
                }
            )
    if state == "running":
        events.append(
            {
                "state": "queued",
                "attempt_id": attempt.attempt_id,
                "retry_of": attempt.retry_of,
                "at": when,
            }
        )
    event = {"state": state, "attempt_id": attempt.attempt_id, "retry_of": attempt.retry_of, "at": when}
    return validate_record(
        {
            "kind": KIND,
            "schema_version": SCHEMA_VERSION,
            "source_sha256": attempt.source_sha256,
            "state": state,
            "attempt_id": attempt.attempt_id,
            "retry_of": attempt.retry_of,
            "retry_token_sha256": attempt.retry_token_sha256,
            "updated_at": when,
            "events": events + [event],
        }
    )
