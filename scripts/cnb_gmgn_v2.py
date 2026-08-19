#!/usr/bin/env python3
"""Coordinate the manual-only CNB GMGN V2 shadow pipeline.

The commands deliberately split trust boundaries:

* ``fetch`` downloads the public candidate triple without an identity key;
* ``prepare`` runs offline with the identity key and emits fixed shard inputs;
* ``probe`` provisions the Linux network guard before entering ``probe-inside``;
* ``redact`` runs offline with the identity key and removes raw exit data;
* ``finalize`` consumes only fixed artifacts and builds one publish bundle.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import ipaddress
import json
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

import yaml

try:
    from curl_cffi import requests as curl_requests
except ImportError:  # The dependency is mandatory in the isolated V2 image.
    curl_requests = None

from scripts.asia_source_registry import (
    CONTROLLER_HEALTH_TIMEOUT_SECONDS,
    CONTROLLER_SELECTION_TIMEOUT_SECONDS,
    DELAY_REQUEST_OVERHEAD_SECONDS,
    DIRECT_PROBE_TIMEOUT_SECONDS,
    MIHOMO_STARTUP_TIMEOUT_SECONDS,
    REGION_LOOKUP_TIMEOUT_SECONDS,
    estimate_gmgn_capacity,
)
from scripts.candidate_snapshot import (
    CANDIDATE_METADATA_KIND,
    CANDIDATE_STATUS_KIND,
    CandidateSnapshotEntry,
    validate_candidate_snapshot,
)
from scripts.gmgn_history import empty_history, reduce_history, validate_history
from scripts.gmgn_measurement import (
    ERROR_CATEGORIES,
    MINIMUM_OBSERVATION_WINDOW_SECONDS,
    NETWORK_GUARD_POLICY_VERSION,
    RESOLVER_POLICY_VERSION,
    SHARD_COUNT,
    TOTAL_ROUNDS,
    build_manifest_v3,
    build_private_fragment,
    build_redacted_fragment,
    candidate_ids_sha256,
    canonical_json_sha256,
    classify_error,
    normalize_outcome,
    run_measurement_schedule,
    summarize_canaries,
    summarize_control,
    validate_manifest_v3,
    write_private_fragment,
)
from scripts.gmgn_processed_state import (
    Attempt,
    ProcessedStateError,
    build_attempt,
    decide_attempt,
    processed_ref,
    transition as transition_processed_state,
    validate_record as validate_processed_record,
)
from scripts.gmgn_region import (
    REGION_OBSERVATION_KIND,
    REGION_OBSERVATION_SCHEMA_VERSION,
    REGION_PROVIDER_SCHEMA_VERSION,
    resolve_region_decisions,
)
from scripts.gmgn_selection import (
    SELECTION_POLICY_VERSION,
    V2_GROUP_NAMES,
    build_selection_input,
    select_candidates_v2,
)
from scripts.gmgn_validity import (
    accepted_measurement,
    contains_ip_literal,
    validate_run,
)
from scripts.pipeline_utils import dump_clash_yaml
from scripts.probe_network_guard import (
    default_resolver,
    resolve_and_pin_candidates_with_failures,
)
from scripts.probe_network_guard_linux import (
    normalize_auxiliary_targets,
    normalize_pinned_targets,
    provision_guard,
    validate_linux_guard_evidence,
)
from scripts.proxy_identity import (
    IdentitySettings,
    asn_id,
    canonical_asn,
    exit_id,
    validate_public_id,
    verify_identity_test_vector,
)
from scripts.publish_transaction import (
    AUTHORITATIVE_BRANCH,
    PreviousState,
    attach_previous_bundle,
    build_publish_bundle,
    classify_previous_ref,
    read_bundle_from_commit,
    published_count_from_bundle,
    validate_selection_publication,
    write_publish_bundle,
)
from scripts.validate_public_outputs import fetch_no_cache, minimal_mihomo_env


PREPARED_SNAPSHOT_KIND = "cnb-gmgn-prepared-snapshot"
PREPARED_SNAPSHOT_SCHEMA_VERSION = 1
SHARD_INPUT_KIND = "cnb-gmgn-shard-input"
SHARD_INPUT_SCHEMA_VERSION = 2
PROBE_RESOLUTION_KIND = "cnb-gmgn-v2-probe-resolution"
PROBE_RESOLUTION_SCHEMA_VERSION = 2
RAW_REGION_KIND = "cnb-gmgn-private-region-observations"
RAW_REGION_SCHEMA_VERSION = 1
OPAQUE_REGION_KIND = "cnb-gmgn-region-observations"
OPAQUE_REGION_SCHEMA_VERSION = 1
TRIGGER_KIND = "cnb-gmgn-v2-trigger"
TRIGGER_SCHEMA_VERSION = 2
PREFLIGHT_KIND = "cnb-gmgn-v2-preflight"
PREFLIGHT_SCHEMA_VERSION = 2
TRIGGER_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "source_sha256",
        "candidate_commit",
        "retry",
        "retry_token",
    }
)
PREFLIGHT_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "source_sha256",
        "candidate_commit",
        "retry",
        "attempt_id",
        "retry_of",
        "retry_token_sha256",
        "decision",
        "should_run",
        "observed_tip",
        "processed_ref",
        "processed_tip",
    }
)
INTERNAL_GROUP = "__gmgn_v2_probe__"
HTTP_PROBE_GROUP_PREFIX = "__gmgn_v2_http_slot_"
HTTP_PROBE_LISTENER_PREFIX = "gmgn-v2-http-slot-"
HTTP_PROBE_PORT_BASE = 20_000
HTTP_PROBE_PORT_STRIDE = 64
GMGN_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)
GMGN_BROWSER_ACCEPT = (
    "text/html,application/xhtml+xml,application/xml;q=0.9,"
    "image/avif,image/webp,*/*;q=0.8"
)
GMGN_TLS_IMPERSONATE = "chrome"
SAFE_PROBE_DIAGNOSTIC_CATEGORIES = frozenset(
    {
        "tls_certificate_verify",
        "tls_handshake",
        "connection_eof_reset",
        "connection_other",
        "client_timeout",
        "dns",
        "proxy_connect",
        "client_dependency_missing",
        "other",
    }
)

NORMAL_TAG_RE = re.compile(r"^cnb-gmgn-v2-([0-9a-f]{64})-([0-9a-f]{40})$")
RETRY_TAG_RE = re.compile(
    r"^cnb-gmgn-v2-retry-([0-9a-f]{64})-([0-9a-f]{40})-([A-Za-z0-9][A-Za-z0-9._-]{0,63})$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DIRECT_PREFLIGHT_ATTEMPTS = 3
CONTROL_DISCOVERY_SIZE = 128
CONTROL_DISCOVERY_BATCH_SIZE = 32
CONTROL_DISCOVERY_WORKERS = 16
CONTROL_PANEL_SIZE = 8
CONTROL_PANEL_WORKERS = 8
CONTROL_PROBE_TIMEOUT_MS = 5_000
CONTROL_EXPECTED_STATUS = 200
HTTP_PROBE_STARTUP_GRACE_SECONDS = 1.0
HTTP_PROBE_PORTS_PER_SHARD = 32

DIRECT_TARGETS: dict[str, dict[str, Any]] = {
    "control-gmgn-v1": {
        "server": "gmgn.ai",
        "port": 443,
        "path": "/",
        "status_policy": "exact",
        "expected_status": 200,
        "purpose": "control",
    },
    "canary-gstatic-v1": {
        "server": "www.gstatic.com",
        "port": 443,
        "path": "/generate_204",
        "status_policy": "exact",
        "expected_status": 204,
        "purpose": "canary",
    },
    "canary-cloudflare-v1": {
        "server": "cp.cloudflare.com",
        "port": 443,
        "path": "/generate_204",
        "status_policy": "exact",
        "expected_status": 204,
        "purpose": "canary",
    },
    "egress-provider-v1": {
        "server": "api.ip.sb",
        "port": 443,
        "path": "/geoip",
        "status_policy": "exact",
        "expected_status": 200,
        "purpose": "egress",
    },
}
CANARY_IDS = tuple(
    sorted(name for name, item in DIRECT_TARGETS.items() if item["purpose"] == "canary")
)
REGION_PROVIDER_TARGET = "egress-provider-v1"


class CoordinatorError(RuntimeError):
    """A V2 orchestration boundary failed closed."""


class ControlDiscoveryError(CoordinatorError):
    """Control discovery failed with public-safe aggregate diagnostics."""

    def __init__(self, diagnostics: Mapping[str, Any]) -> None:
        self.diagnostics = copy.deepcopy(dict(diagnostics))
        super().__init__(
            "GMGN proxy control discovery failed; safe diagnostics="
            + json.dumps(self.diagnostics, sort_keys=True, separators=(",", ":"))
        )


@dataclass(frozen=True)
class PreparedSnapshot:
    snapshot_id: str
    main_sha: str
    profile_sha256: str
    metadata_sha256: str
    identity_key_version: str
    identity_epoch: str
    ordered_candidates: tuple[CandidateSnapshotEntry, ...]
    metadata: dict[str, Any]
    status: dict[str, Any]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _write_bytes(path: Path, content: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, mode)
        temporary.replace(path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_json(path: Path, value: Any, *, mode: int = 0o600) -> None:
    _write_bytes(path, _json_bytes(value), mode=mode)


def _load_json(path: str | Path) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise CoordinatorError(f"cannot load JSON object: {Path(path).name}") from exc
    if not isinstance(value, Mapping):
        raise CoordinatorError(f"JSON root must be an object: {Path(path).name}")
    return dict(value)


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_trigger_tag(tag: str) -> dict[str, Any]:
    value = str(tag or "")
    match = NORMAL_TAG_RE.fullmatch(value)
    if match is not None:
        source_sha = match.group(1)
        candidate_commit = match.group(2)
        retry = False
        retry_token = None
    else:
        retry_match = RETRY_TAG_RE.fullmatch(value)
        if retry_match is None:
            raise CoordinatorError("V2 trigger tag is malformed")
        source_sha = retry_match.group(1)
        candidate_commit = retry_match.group(2)
        retry = True
        retry_token = retry_match.group(3)
    return {
        "kind": TRIGGER_KIND,
        "schema_version": TRIGGER_SCHEMA_VERSION,
        "source_sha256": source_sha,
        "candidate_commit": candidate_commit,
        "retry": retry,
        "retry_token": retry_token,
    }


def _load_preflight_attempt(
    preflight_path: str | Path,
    trigger_path: str | Path,
    *,
    expected_source_sha256: str,
    expected_candidate_commit: str,
) -> Attempt:
    preflight = _load_json(preflight_path)
    trigger = _load_json(trigger_path)
    if (
        frozenset(preflight) != PREFLIGHT_FIELDS
        or preflight["kind"] != PREFLIGHT_KIND
        or preflight["schema_version"] != PREFLIGHT_SCHEMA_VERSION
    ):
        raise CoordinatorError("prepared preflight fields are incomplete or unexpected")
    if (
        frozenset(trigger) != TRIGGER_FIELDS
        or trigger["kind"] != TRIGGER_KIND
        or trigger["schema_version"] != TRIGGER_SCHEMA_VERSION
    ):
        raise CoordinatorError("prepared trigger fields are incomplete or unexpected")
    source = str(expected_source_sha256).lower()
    if preflight["source_sha256"] != source or trigger["source_sha256"] != source:
        raise CoordinatorError("prepared source SHA differs from preflight or trigger")
    candidate_commit = str(expected_candidate_commit).lower()
    if not GIT_SHA_RE.fullmatch(candidate_commit):
        raise CoordinatorError("expected candidate commit is malformed")
    if (
        preflight["candidate_commit"] != candidate_commit
        or trigger["candidate_commit"] != candidate_commit
    ):
        raise CoordinatorError("prepared candidate commit differs from preflight or trigger")
    retry = trigger["retry"]
    if not isinstance(retry, bool) or preflight["retry"] is not retry:
        raise CoordinatorError("prepared retry flag differs from preflight")
    token_value = trigger["retry_token"]
    if retry:
        if not isinstance(token_value, str) or not token_value:
            raise CoordinatorError("prepared retry token is missing")
        token = token_value
    else:
        if token_value is not None:
            raise CoordinatorError("primary prepared trigger contains a retry token")
        token = None
    try:
        derived = build_attempt(source, token)
    except ProcessedStateError as exc:
        raise CoordinatorError(str(exc)) from exc
    if preflight["attempt_id"] != derived.attempt_id:
        raise CoordinatorError("prepared attempt ID differs from preflight")
    if preflight["retry_token_sha256"] != derived.retry_token_sha256:
        raise CoordinatorError("prepared retry token hash differs from preflight")
    if preflight["should_run"] is not True:
        raise CoordinatorError("prepared preflight is not runnable")
    expected_decision = "retry_failed_infrastructure" if retry else "queue"
    if preflight["decision"] != expected_decision:
        raise CoordinatorError("prepared preflight decision is inconsistent")
    if preflight["processed_ref"] != processed_ref(source):
        raise CoordinatorError("prepared processed ref is inconsistent")
    for label in ("observed_tip", "processed_tip"):
        tip = preflight[label]
        if tip is not None and (
            not isinstance(tip, str) or not re.fullmatch(r"[0-9a-f]{40,64}", tip)
        ):
            raise CoordinatorError(f"prepared {label} is malformed")
    supplied_retry_of = preflight["retry_of"]
    if not retry:
        if supplied_retry_of is not None:
            raise CoordinatorError("primary prepared attempt cannot declare retry_of")
        return derived
    if (
        not isinstance(supplied_retry_of, str)
        or not re.fullmatch(r"[0-9a-f]{24}", supplied_retry_of)
        or supplied_retry_of == derived.attempt_id
    ):
        raise CoordinatorError("prepared retry_of differs from preflight")
    return Attempt(
        derived.source_sha256,
        derived.attempt_id,
        supplied_retry_of,
        derived.retry_token_sha256,
    )


def _accepted_source_shas(
    run_index: Mapping[str, Any] | None,
    history: Mapping[str, Any] | None,
) -> set[str]:
    output: set[str] = set()
    collections: list[tuple[str, Any]] = []
    if run_index is not None:
        collections.append(("previous run index", run_index.get("entries")))
    if history is not None:
        collections.append(("previous history", history.get("recent_accepted_runs")))
    for label, entries in collections:
        if not isinstance(entries, list):
            raise CoordinatorError(f"{label} entries are malformed")
        for item in entries:
            if not isinstance(item, Mapping):
                raise CoordinatorError(f"{label} entry is malformed")
            source = str(item.get("source_sha256") or "")
            if not SHA256_RE.fullmatch(source):
                raise CoordinatorError(f"{label} source SHA is malformed")
            output.add(source)
    return output


def _validate_runtime_capacity(
    candidate_count: int, *, workers_per_shard: int
) -> dict[str, Any]:
    capacity = estimate_gmgn_capacity(
        candidate_count, workers_per_shard=workers_per_shard
    )
    if not capacity["below_candidate_hard_limit"]:
        raise CoordinatorError("candidate pool exceeds the V2 hard limit")
    if not capacity["within_runtime_budget"]:
        raise CoordinatorError("candidate pool exceeds the V2 runtime budget")
    return capacity


def _git_command(args: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        ["git", *args],
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    return completed


def _read_processed_state(
    remote: str, source_sha: str, work_dir: Path
) -> tuple[dict[str, Any] | None, str | None]:
    ref = processed_ref(source_sha)
    lookup = _git_command(["ls-remote", "--refs", remote, ref], cwd=work_dir)
    if lookup.returncode != 0:
        raise CoordinatorError("processed-state ref lookup was unreadable")
    lines = [line for line in lookup.stdout.splitlines() if line.strip()]
    if not lines:
        return None, None
    if len(lines) != 1 or len(lines[0].split()) != 2 or lines[0].split()[1] != ref:
        raise CoordinatorError("processed-state ref lookup was ambiguous")
    tip = lines[0].split()[0]
    if not re.fullmatch(r"[0-9a-f]{40,64}", tip):
        raise CoordinatorError("processed-state tip is malformed")
    repo = Path(tempfile.mkdtemp(prefix="processed-read-", dir=work_dir))
    try:
        if _git_command(["init", "--quiet"], cwd=repo).returncode != 0:
            raise CoordinatorError("processed-state repository initialization failed")
        if _git_command(["fetch", "--quiet", "--depth=1", remote, tip], cwd=repo).returncode != 0:
            raise CoordinatorError("processed-state ref was unreadable")
        tree = _git_command(["ls-tree", "-r", "--name-only", tip], cwd=repo)
        if tree.returncode != 0 or tree.stdout.splitlines() != ["state.json"]:
            raise CoordinatorError("processed-state tree differs from its allowlist")
        shown = _git_command(["show", f"{tip}:state.json"], cwd=repo)
        if shown.returncode != 0:
            raise CoordinatorError("processed-state payload is missing")
        try:
            raw = json.loads(shown.stdout)
            return validate_processed_record(raw), tip
        except (json.JSONDecodeError, ProcessedStateError) as exc:
            raise CoordinatorError("processed-state payload is invalid") from exc
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _write_processed_state(
    *,
    remote: str,
    source_sha: str,
    record: Mapping[str, Any],
    expected_tip: str | None,
    work_dir: Path,
) -> str:
    ref = processed_ref(source_sha)
    normalized = validate_processed_record(record)
    repo = Path(tempfile.mkdtemp(prefix="processed-write-", dir=work_dir))
    try:
        for command in (
            ["init", "--quiet"],
            ["config", "user.name", "cnb-gmgn-v2[bot]"],
            ["config", "user.email", "cnb-gmgn-v2@users.noreply.cnb.cool"],
        ):
            if _git_command(command, cwd=repo).returncode != 0:
                raise CoordinatorError("processed-state repository setup failed")
        _write_json(repo / "state.json", normalized)
        if _git_command(["add", "state.json"], cwd=repo).returncode != 0 or _git_command(
            ["commit", "--quiet", "-m", f"GMGN V2 processed state {normalized['state']}"],
            cwd=repo,
        ).returncode != 0:
            raise CoordinatorError("processed-state commit failed")
        commit = _git_command(["rev-parse", "HEAD"], cwd=repo).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
            raise CoordinatorError("processed-state commit ID is malformed")
        lease_tip = "" if expected_tip is None else expected_tip
        pushed = _git_command(
            [
                "push",
                f"--force-with-lease={ref}:{lease_tip}",
                remote,
                f"{commit}:{ref}",
            ],
            cwd=repo,
        )
        if pushed.returncode != 0:
            raise CoordinatorError("processed-state CAS update failed")
        return commit
    finally:
        shutil.rmtree(repo, ignore_errors=True)


def _preflight(args: argparse.Namespace) -> int:
    source_sha = str(args.source_sha).lower()
    if not SHA256_RE.fullmatch(source_sha):
        raise CoordinatorError("preflight source SHA is malformed")
    candidate_commit = str(args.candidate_commit).lower()
    if not GIT_SHA_RE.fullmatch(candidate_commit):
        raise CoordinatorError("preflight candidate commit is malformed")
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    previous, history, run_index = _remote_previous(args.remote, work_dir)
    accepted_sources = _accepted_source_shas(run_index, history)
    retry_token_value = getattr(args, "retry_token", "")
    retry_token = str(retry_token_value) if retry_token_value else None
    if bool(args.retry) != (retry_token is not None):
        raise CoordinatorError("retry flag and retry token disagree")
    try:
        if source_sha in accepted_sources:
            processed_tip = None
            decision, attempt = decide_attempt(
                source_sha,
                retry_token=retry_token,
                accepted=True,
                record=None,
            )
        else:
            processed, processed_tip = _read_processed_state(
                args.remote, source_sha, work_dir
            )
            queued_lookup = _git_command(
                [
                    "ls-remote",
                    "--refs",
                    "--tags",
                    args.remote,
                    f"refs/tags/cnb-gmgn-v2-{source_sha}-{candidate_commit}",
                ],
                cwd=work_dir,
            )
            legacy_queued_lookup = _git_command(
                [
                    "ls-remote",
                    "--refs",
                    "--tags",
                    args.remote,
                    f"refs/tags/cnb-gmgn-v2-{source_sha}",
                ],
                cwd=work_dir,
            )
            if queued_lookup.returncode != 0 or legacy_queued_lookup.returncode != 0:
                raise CoordinatorError("primary trigger lookup was unreadable")
            queued_primary = bool(
                queued_lookup.stdout.strip() or legacy_queued_lookup.stdout.strip()
            )
            decision, attempt = decide_attempt(
                source_sha,
                retry_token=retry_token,
                accepted=False,
                record=processed,
                queued_primary=queued_primary,
            )
    except ProcessedStateError as exc:
        raise CoordinatorError(str(exc)) from exc
    should_run = decision in {"queue", "retry_failed_infrastructure"}
    payload = {
        "kind": PREFLIGHT_KIND,
        "schema_version": PREFLIGHT_SCHEMA_VERSION,
        "source_sha256": source_sha,
        "candidate_commit": candidate_commit,
        "retry": bool(args.retry),
        "attempt_id": attempt.attempt_id,
        "retry_of": attempt.retry_of,
        "retry_token_sha256": attempt.retry_token_sha256,
        "decision": decision,
        "should_run": should_run,
        "observed_tip": previous.observed_tip,
        "processed_ref": processed_ref(source_sha),
        "processed_tip": processed_tip,
    }
    _write_json(Path(args.output), payload)
    if not should_run and args.noop_file:
        _write_bytes(Path(args.noop_file), b"accepted\n")
    print(
        "GMGN V2 preflight: "
        + ("run required" if should_run else "source already accepted; no-op")
    )
    return 0


def _processed_transition(args: argparse.Namespace) -> int:
    source = str(args.source_sha).lower()
    attempt_id = str(args.attempt_id).lower()
    retry_of = str(args.retry_of).lower() if args.retry_of else None
    retry_token_sha256 = (
        str(args.retry_token_sha256).lower() if args.retry_token_sha256 else None
    )
    attempt = Attempt(source, attempt_id, retry_of, retry_token_sha256)
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    previous, tip = _read_processed_state(args.remote, source, work_dir)
    if args.expected_tip:
        expected = None if args.expected_tip == "absent" else args.expected_tip
        if tip != expected:
            raise CoordinatorError("processed-state tip changed after preflight")
    try:
        record = transition_processed_state(
            previous,
            attempt=attempt,
            state=args.state,
            at=utc_now(),
            allow_missing_primary=bool(args.allow_missing_primary),
        )
    except ProcessedStateError as exc:
        raise CoordinatorError(str(exc)) from exc
    _write_processed_state(
        remote=args.remote,
        source_sha=source,
        record=record,
        expected_tip=tip,
        work_dir=work_dir,
    )
    print(f"GMGN V2 processed state: {args.state}")
    return 0


def _fetch_candidate(args: argparse.Namespace) -> int:
    expected = str(args.expected_source_sha).lower()
    if not SHA256_RE.fullmatch(expected):
        raise CoordinatorError("expected candidate source SHA is malformed")
    candidate_commit = str(args.expected_candidate_commit).lower()
    if not GIT_SHA_RE.fullmatch(candidate_commit):
        raise CoordinatorError("expected candidate commit is malformed")
    for url in (args.profile_url, args.status_url, args.metadata_url):
        parsed = urllib.parse.urlsplit(str(url))
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or candidate_commit not in parsed.path.split("/")
        ):
            raise CoordinatorError("candidate URL is not bound to the expected immutable revision")
    destination = Path(args.output_dir).resolve()
    nonce = secrets.token_hex(16)
    status_bytes = fetch_no_cache(args.status_url, nonce=nonce)
    profile_bytes = fetch_no_cache(args.profile_url, nonce=nonce)
    metadata_bytes = fetch_no_cache(args.metadata_url, nonce=nonce)
    try:
        status = json.loads(status_bytes.decode("utf-8"))
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise CoordinatorError("candidate sidecars are invalid JSON") from exc
    if not isinstance(status, Mapping) or not isinstance(metadata, Mapping):
        raise CoordinatorError("candidate sidecars must be JSON objects")
    if status.get("kind") != CANDIDATE_STATUS_KIND or metadata.get("kind") != CANDIDATE_METADATA_KIND:
        raise CoordinatorError("candidate sidecar kinds are unsupported")
    actual = hashlib.sha256(profile_bytes).hexdigest()
    if actual != expected or status.get("profile_sha256") != expected:
        raise CoordinatorError("candidate profile SHA differs from the manual trigger")
    metadata_sha = hashlib.sha256(metadata_bytes).hexdigest()
    if status.get("candidate_metadata_sha256") != metadata_sha:
        raise CoordinatorError("candidate metadata SHA binding mismatch")
    destination.mkdir(parents=True, exist_ok=True)
    _write_bytes(destination / "clash.yaml", profile_bytes)
    _write_bytes(destination / "status.json", status_bytes)
    _write_bytes(destination / "candidate-metadata.json", metadata_bytes)
    _write_bytes(destination / "request-nonce.txt", f"{nonce}\n".encode("ascii"))
    return 0


def _mihomo_version(
    binary: Path,
    *,
    work_dir: str | Path,
    runner: Any = subprocess.run,
) -> str:
    runtime_root = Path(work_dir).resolve()
    runtime_root.mkdir(parents=True, exist_ok=True)
    completed = runner(
        [str(binary), "-v"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env=minimal_mihomo_env(runtime_root),
    )
    if completed.returncode != 0:
        raise CoordinatorError("Mihomo version probe failed")
    version_output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    match = re.search(
        r"\bv?(\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?)\b", version_output
    )
    if match is None:
        raise CoordinatorError("Mihomo version output is unrecognized")
    return match.group(1)


def _start_mihomo(
    binary: str | Path,
    *,
    work_dir: Path,
    config: Path,
    log: Any,
    runner: Any = subprocess.Popen,
) -> subprocess.Popen[Any]:
    return runner(
        [str(binary), "-d", str(work_dir), "-f", str(config)],
        stdout=log,
        stderr=subprocess.STDOUT,
        env=minimal_mihomo_env(work_dir),
    )


def _prepared_projection(snapshot: Any) -> dict[str, Any]:
    candidates = [
        {
            "candidate_id": entry.candidate_id,
            "proxy": copy.deepcopy(entry.proxy),
            "metadata": copy.deepcopy(entry.metadata),
        }
        for entry in snapshot.ordered_candidates
    ]
    return {
        "kind": PREPARED_SNAPSHOT_KIND,
        "schema_version": PREPARED_SNAPSHOT_SCHEMA_VERSION,
        "snapshot_id": snapshot.snapshot_id,
        "main_sha": snapshot.main_sha,
        "profile_sha256": snapshot.profile_sha256,
        "candidate_metadata_sha256": snapshot.metadata_sha256,
        "identity_key_version": snapshot.identity_key_version,
        "identity_epoch": snapshot.identity_epoch,
        "source_run_at": snapshot.status["run_at"],
        "sources": copy.deepcopy(snapshot.metadata["sources"]),
        "candidates": candidates,
    }


def _bind_shard_control_states(
    shards: Sequence[Sequence[Mapping[str, Any]]],
    snapshot_candidates: Sequence[Any],
) -> list[list[dict[str, Any]]]:
    entries: dict[str, Any] = {}
    for entry in snapshot_candidates:
        candidate_id = validate_public_id(
            entry.get("candidate_id") if isinstance(entry, Mapping) else getattr(entry, "candidate_id", None),
            "candidate",
        )
        if candidate_id in entries:
            raise CoordinatorError("snapshot contains duplicate control-state candidates")
        entries[candidate_id] = entry

    bound = [[copy.deepcopy(dict(candidate)) for candidate in shard] for shard in shards]
    for shard in bound:
        for candidate in shard:
            candidate_id = validate_public_id(candidate.get("candidate_id"), "candidate")
            entry = entries.get(candidate_id)
            if entry is None:
                raise CoordinatorError("shard control-state binding is incomplete")
            metadata = (
                entry.get("metadata")
                if isinstance(entry, Mapping)
                else getattr(entry, "metadata", None)
            )
            state = metadata.get("github_check_state") if isinstance(metadata, Mapping) else None
            if state not in {"passed", "bypassed_asia"}:
                raise CoordinatorError("shard control-state binding is invalid")
            candidate["github_check_state"] = state
    return bound


def _prepare(args: argparse.Namespace) -> int:
    profile = Path(args.profile).read_bytes()
    status = _load_json(args.status)
    metadata = _load_json(args.metadata)
    settings = IdentitySettings.from_environment()
    verify_identity_test_vector(args.identity_fixture)
    snapshot = validate_candidate_snapshot(
        profile,
        status,
        metadata,
        settings=settings,
        fixture_path=args.identity_fixture,
    )
    expected = str(args.expected_source_sha).lower()
    if snapshot.profile_sha256 != expected:
        raise CoordinatorError("validated candidate SHA differs from the trigger")
    _validate_runtime_capacity(
        len(snapshot.ordered_candidates), workers_per_shard=args.workers
    )
    mihomo = Path(args.mihomo).resolve()
    if not mihomo.is_file():
        raise CoordinatorError("fixed Mihomo binary is missing")
    secret_values = [secrets.token_urlsafe(32) for _ in range(SHARD_COUNT)]
    secret_hashes = [hashlib.sha256(value.encode("utf-8")).hexdigest() for value in secret_values]
    created_at = utc_now()
    run_id = f"gmgnv2_{expected[:16]}_{secrets.token_hex(8)}"
    attempt = _load_preflight_attempt(
        args.preflight,
        args.trigger,
        expected_source_sha256=expected,
        expected_candidate_commit=str(args.expected_candidate_commit),
    )
    manifest, raw_shards = build_manifest_v3(
        snapshot,
        run_id=run_id,
        created_at=created_at,
        trigger_type="retry" if attempt.retry_of is not None else "manual",
        attempt_id=attempt.attempt_id,
        retry_of=attempt.retry_of,
        source_run_at=str(status["run_at"]),
        source_sha256=expected,
        canary_set=CANARY_IDS,
        python_version=platform.python_version(),
        pyyaml_version=str(yaml.__version__),
        mihomo_version=_mihomo_version(
            mihomo,
            work_dir=Path(args.output_dir).resolve() / "mihomo-version",
        ),
        mihomo_sha256=_sha256_file(mihomo),
        resolver_policy_version=RESOLVER_POLICY_VERSION,
        network_guard_policy_version=NETWORK_GUARD_POLICY_VERSION,
        controller_secret_sha256s=secret_hashes,
        workers_per_shard=args.workers,
    )
    shards = _bind_shard_control_states(raw_shards, snapshot.ordered_candidates)
    root = Path(args.output_dir).resolve()
    _write_json(root / "manifest.json", manifest)
    _write_json(root / "snapshot.json", _prepared_projection(snapshot))
    for index, shard in enumerate(shards):
        payload = {
            "kind": SHARD_INPUT_KIND,
            "schema_version": SHARD_INPUT_SCHEMA_VERSION,
            "manifest_sha256": canonical_json_sha256(manifest),
            "run_id": run_id,
            "shard_index": index,
            "candidates": shard,
        }
        _write_json(root / "shards" / f"shard-{index}.json", payload)
        _write_bytes(
            root / "controller-secrets" / f"shard-{index}.txt",
            f"{secret_values[index]}\n".encode("utf-8"),
        )
    print(f"Prepared manual GMGN V2 run {run_id} for {len(snapshot.ordered_candidates)} candidates.")
    return 0


def _load_shard(manifest: Mapping[str, Any], path: str | Path, index: int) -> list[dict[str, Any]]:
    if index not in range(SHARD_COUNT):
        raise CoordinatorError("shard index is outside the fixed four-shard range")
    value = _load_json(path)
    if set(value) != {
        "kind",
        "schema_version",
        "manifest_sha256",
        "run_id",
        "shard_index",
        "candidates",
    }:
        raise CoordinatorError("shard input fields are incomplete or unexpected")
    if (
        value["kind"] != SHARD_INPUT_KIND
        or value["schema_version"] != SHARD_INPUT_SCHEMA_VERSION
        or value["manifest_sha256"] != canonical_json_sha256(dict(manifest))
        or value["run_id"] != manifest["run_id"]
        or value["shard_index"] != index
    ):
        raise CoordinatorError("shard input binding mismatch")
    candidates = value["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise CoordinatorError("shard input contains no candidates")
    for item in candidates:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"candidate_id", "proxy", "github_check_state"}
            or not isinstance(item.get("proxy"), Mapping)
            or item.get("github_check_state") not in {"passed", "bypassed_asia"}
        ):
            raise CoordinatorError("shard candidate fields are incomplete or unexpected")
    expected = manifest["shards"][index]
    ids = [validate_public_id(item.get("candidate_id"), "candidate") for item in candidates]
    if len(ids) != expected["candidate_count"] or candidate_ids_sha256(ids) != expected["candidate_ids_sha256"]:
        raise CoordinatorError("shard candidate binding mismatch")
    return copy.deepcopy(candidates)


def _validate_probe_resolution(
    manifest: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    index: int,
    raw: Mapping[str, Any],
) -> dict[str, Any]:
    fields = {
        "kind",
        "schema_version",
        "manifest_sha256",
        "run_id",
        "shard_index",
        "candidate_count",
        "candidate_ids_sha256",
        "guarded_candidate_ids",
        "guarded_candidate_ids_sha256",
        "dns_failed_candidate_ids",
        "dns_failed_candidate_ids_sha256",
        "ipv6_unavailable_candidate_ids",
        "ipv6_unavailable_candidate_ids_sha256",
    }
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise CoordinatorError("probe resolution fields are incomplete or unexpected")
    value = dict(raw)
    ids = [validate_public_id(item.get("candidate_id"), "candidate") for item in candidates]
    expected = manifest["shards"][index]
    if (
        value["kind"] != PROBE_RESOLUTION_KIND
        or value["schema_version"] != PROBE_RESOLUTION_SCHEMA_VERSION
        or value["manifest_sha256"] != canonical_json_sha256(dict(manifest))
        or value["run_id"] != manifest["run_id"]
        or value["shard_index"] != index
        or value["candidate_count"] != expected["candidate_count"]
        or value["candidate_ids_sha256"] != expected["candidate_ids_sha256"]
    ):
        raise CoordinatorError("probe resolution binding mismatch")

    partitions: dict[str, list[str]] = {}
    for field in (
        "guarded_candidate_ids",
        "dns_failed_candidate_ids",
        "ipv6_unavailable_candidate_ids",
    ):
        raw_ids = value[field]
        if not isinstance(raw_ids, list):
            raise CoordinatorError("probe resolution candidate partition is malformed")
        normalized = [validate_public_id(item, "candidate") for item in raw_ids]
        if normalized != sorted(set(normalized)):
            raise CoordinatorError("probe resolution candidate partition is non-canonical")
        hash_field = field.removesuffix("_ids") + "_ids_sha256"
        if value[hash_field] != candidate_ids_sha256(normalized):
            raise CoordinatorError("probe resolution candidate partition hash mismatch")
        partitions[field] = normalized
    guarded = set(partitions["guarded_candidate_ids"])
    dns_failed = set(partitions["dns_failed_candidate_ids"])
    ipv6_unavailable = set(partitions["ipv6_unavailable_candidate_ids"])
    if (
        not guarded
        or guarded & dns_failed
        or guarded & ipv6_unavailable
        or dns_failed & ipv6_unavailable
        or guarded | dns_failed | ipv6_unavailable != set(ids)
    ):
        raise CoordinatorError("probe resolution candidate partition is incomplete")
    return value


def _build_probe_resolution(
    manifest: Mapping[str, Any],
    candidates: Sequence[Mapping[str, Any]],
    index: int,
    *,
    pinned_candidate_ids: Iterable[str],
    dns_failed_candidate_ids: Iterable[str],
    ipv6_unavailable_candidate_ids: Iterable[str],
) -> dict[str, Any]:
    guarded = sorted(validate_public_id(item, "candidate") for item in pinned_candidate_ids)
    failed = sorted(validate_public_id(item, "candidate") for item in dns_failed_candidate_ids)
    ipv6_unavailable = sorted(
        validate_public_id(item, "candidate")
        for item in ipv6_unavailable_candidate_ids
    )
    expected = manifest["shards"][index]
    value = {
        "kind": PROBE_RESOLUTION_KIND,
        "schema_version": PROBE_RESOLUTION_SCHEMA_VERSION,
        "manifest_sha256": canonical_json_sha256(dict(manifest)),
        "run_id": manifest["run_id"],
        "shard_index": index,
        "candidate_count": expected["candidate_count"],
        "candidate_ids_sha256": expected["candidate_ids_sha256"],
        "guarded_candidate_ids": guarded,
        "guarded_candidate_ids_sha256": candidate_ids_sha256(guarded),
        "dns_failed_candidate_ids": failed,
        "dns_failed_candidate_ids_sha256": candidate_ids_sha256(failed),
        "ipv6_unavailable_candidate_ids": ipv6_unavailable,
        "ipv6_unavailable_candidate_ids_sha256": candidate_ids_sha256(
            ipv6_unavailable
        ),
    }
    return _validate_probe_resolution(manifest, candidates, index, value)


def _select_ipv4_pinned_candidates(
    pinned: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, dict[str, Any]], tuple[str, ...]]:
    """Select the address family supported by the managed CNB guard runtime."""

    selected: dict[str, dict[str, Any]] = {}
    ipv6_unavailable: list[str] = []
    for raw_candidate_id, raw_record in pinned.items():
        candidate_id = validate_public_id(raw_candidate_id, "candidate")
        record = copy.deepcopy(dict(raw_record))
        addresses = record.get("addresses")
        if not isinstance(addresses, list) or not addresses:
            raise CoordinatorError("pinned candidate address list is malformed")
        try:
            ipv4_addresses = sorted(
                {
                    ipaddress.ip_address(str(value)).compressed.lower()
                    for value in addresses
                    if ipaddress.ip_address(str(value)).version == 4
                },
                key=lambda value: int(ipaddress.ip_address(value)),
            )
        except ValueError:
            raise CoordinatorError("pinned candidate address is malformed") from None
        if not ipv4_addresses:
            ipv6_unavailable.append(candidate_id)
            continue
        record["addresses"] = ipv4_addresses
        selected[candidate_id] = record
    if not selected:
        raise CoordinatorError("probe candidate set has no IPv4-compatible endpoints")
    return selected, tuple(sorted(ipv6_unavailable))


def _public_addresses(host: str, port: int) -> list[str]:
    values: set[str] = set()
    try:
        resolved = default_resolver(host, port)
    except Exception:
        raise CoordinatorError("auxiliary DNS resolution failed") from None
    for raw in resolved:
        try:
            address = ipaddress.ip_address(str(raw))
        except ValueError as exc:
            raise CoordinatorError("auxiliary resolver returned an invalid address") from exc
        if not address.is_global or any(
            (
                address.is_private,
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_reserved,
                address.is_unspecified,
            )
        ):
            raise CoordinatorError("auxiliary resolver returned a forbidden address")
        if address.version == 4:
            values.add(address.compressed.lower())
    if not values:
        raise CoordinatorError("auxiliary resolver returned no public IPv4 address")
    return sorted(values, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))


def _resolve_auxiliary_targets() -> dict[str, dict[str, Any]]:
    return {
        name: {
            "server": item["server"],
            "port": int(item["port"]),
            "addresses": _public_addresses(str(item["server"]), int(item["port"])),
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
        }
        for name, item in DIRECT_TARGETS.items()
    }


def _probe(args: argparse.Namespace) -> int:
    manifest = validate_manifest_v3(_load_json(args.manifest))
    index = int(args.shard_index)
    if index not in range(SHARD_COUNT):
        raise CoordinatorError("shard index is outside the fixed four-shard range")
    candidates = _load_shard(manifest, args.shard_input, index)
    resolved, dns_failed_candidate_ids = resolve_and_pin_candidates_with_failures(
        candidates
    )
    pinned, ipv6_unavailable_candidate_ids = _select_ipv4_pinned_candidates(
        resolved
    )
    auxiliary = _resolve_auxiliary_targets()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    resolution = _build_probe_resolution(
        manifest,
        candidates,
        index,
        pinned_candidate_ids=pinned,
        dns_failed_candidate_ids=dns_failed_candidate_ids,
        ipv6_unavailable_candidate_ids=ipv6_unavailable_candidate_ids,
    )
    _write_json(output / "probe-resolution.json", resolution)
    context = {
        "manifest": manifest,
        "shard_index": index,
        "candidates": candidates,
        "pinned_candidates": pinned,
        "dns_failed_candidate_ids": list(dns_failed_candidate_ids),
        "ipv6_unavailable_candidate_ids": list(
            ipv6_unavailable_candidate_ids
        ),
        "auxiliary_targets": auxiliary,
        "controller_secret": Path(args.controller_secret).read_text(encoding="utf-8").strip(),
        "mihomo": str(Path(args.mihomo).resolve()),
        "work_dir": str((output / "runtime").resolve()),
        "private_fragment": str((output / "private-fragment.json").resolve()),
        "raw_regions": str((output / "raw-regions.json").resolve()),
    }
    if hashlib.sha256(context["controller_secret"].encode("utf-8")).hexdigest() != manifest["shards"][index]["controller_secret_sha256"]:
        raise CoordinatorError("controller secret does not match the manifest")
    context_path = output / "probe-context.json"
    _write_json(context_path, context)
    state_path = output / "guard-state.json"
    http_probe_ports = tuple(
        HTTP_PROBE_PORT_BASE + index * HTTP_PROBE_PORT_STRIDE + offset
        for offset in range(HTTP_PROBE_PORTS_PER_SHARD)
    )
    lease = provision_guard(
        pinned,
        auxiliary_targets=auxiliary,
        shard_index=index,
        controller_port=int(manifest["shards"][index]["controller_port"]),
        local_ports=(
            int(manifest["shards"][index]["mixed_port"]),
            *http_probe_ports,
        ),
        state_path=state_path,
    )
    try:
        _write_json(output / "guard-evidence.json", lease.evidence)
        command = [
            sys.executable,
            "-m",
            "scripts.cnb_gmgn_v2",
            "probe-inside",
            "--context",
            str(context_path),
        ]
        return_code = lease.launch(command)
        if return_code != 0:
            raise CoordinatorError("guarded shard probe failed")
    finally:
        lease.cleanup()
    return 0


def _controller_request(
    controller: str,
    secret: str,
    method: str,
    path: str,
    *,
    body: Mapping[str, Any] | None = None,
    timeout: float = 4.0,
) -> dict[str, Any]:
    url = f"http://{controller}{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Authorization": f"Bearer {secret}",
        "User-Agent": "aggregator-gmgn-v2/1.0",
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            content = response.read()
            if not content:
                return {}
            value = json.loads(content.decode("utf-8", errors="replace"))
            return dict(value) if isinstance(value, Mapping) else {}
    except urllib.error.HTTPError as exc:
        message = "controller request failed"
        try:
            payload = json.loads(exc.read().decode("utf-8", errors="replace"))
            if isinstance(payload, Mapping):
                message = str(payload.get("message") or message)
        except Exception:
            pass
        raise CoordinatorError(f"{message} (controller status {exc.code})") from None


def _wait_mihomo(controller: str, secret: str, process: subprocess.Popen[Any]) -> str:
    deadline = time.monotonic() + MIHOMO_STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise CoordinatorError("Mihomo exited during guarded startup")
        try:
            payload = _controller_request(controller, secret, "GET", "/version", timeout=1.0)
            version = str(payload.get("version") or "").removeprefix("v")
            if version:
                return version
        except Exception:
            time.sleep(0.25)
    raise CoordinatorError("Mihomo controller did not become ready")


def _pinned_http(
    target: Mapping[str, Any], *, timeout: float = DIRECT_PROBE_TIMEOUT_SECONDS
) -> tuple[int, bytes, int]:
    host = str(target["server"])
    port = int(target["port"])
    address = str(target["addresses"][0])
    started = time.monotonic()
    raw_socket = socket.create_connection((address, port), timeout=timeout)
    connection: socket.socket
    if port == 443:
        connection = ssl.create_default_context().wrap_socket(
            raw_socket, server_hostname=host
        )
    else:
        connection = raw_socket
    try:
        request = (
            f"GET {target['path']} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: aggregator-gmgn-v2/1.0\r\n"
            "Accept: application/json,*/*\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        connection.sendall(request)
        response = http.client.HTTPResponse(connection)
        response.begin()
        content = response.read(1024 * 1024)
        delay_ms = max(1, int(round((time.monotonic() - started) * 1000)))
        return int(response.status), content, delay_ms
    finally:
        connection.close()


def _operational_target(
    name: str, auxiliary_targets: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    if name not in DIRECT_TARGETS or name not in auxiliary_targets:
        raise CoordinatorError("required auxiliary target is missing")
    fixed = auxiliary_targets[name]
    configured = DIRECT_TARGETS[name]
    if (
        fixed.get("server") != configured["server"]
        or fixed.get("port") != configured["port"]
        or fixed.get("resolver_policy_version") != RESOLVER_POLICY_VERSION
    ):
        raise CoordinatorError("auxiliary target binding differs from trusted configuration")
    return {**configured, **dict(fixed)}


def _runtime_hosts(
    pinned_candidates: Mapping[str, Mapping[str, Any]],
    auxiliary_targets: Mapping[str, Mapping[str, Any]],
    *,
    target_url: str,
) -> dict[str, str]:
    """Build a complete hostname pin set for the DNS-less guarded namespace."""

    normalize_pinned_targets(pinned_candidates)
    normalize_auxiliary_targets(auxiliary_targets)
    pinned = {key: dict(value) for key, value in pinned_candidates.items()}
    auxiliary = {key: dict(value) for key, value in auxiliary_targets.items()}
    hosts: dict[str, str] = {}

    def assign(server: Any, addresses: Any) -> None:
        host = str(server)
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if not isinstance(addresses, list) or not addresses:
                raise CoordinatorError("fixed hostname has no pinned address")
            selected = str(addresses[0])
            previous = hosts.get(host)
            if previous is not None and previous != selected:
                raise CoordinatorError("pinned host mapping is inconsistent")
            hosts[host] = selected

    for record in pinned.values():
        assign(record["server"], record["addresses"])
    for name in DIRECT_TARGETS:
        target = _operational_target(name, auxiliary)
        assign(target["server"], target["addresses"])

    required_urls = [
        target_url,
        f"https://{DIRECT_TARGETS[REGION_PROVIDER_TARGET]['server']}"
        f"{DIRECT_TARGETS[REGION_PROVIDER_TARGET]['path']}",
    ]
    for raw_url in required_urls:
        parsed = urllib.parse.urlsplit(raw_url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise CoordinatorError("guarded runtime URL contract is invalid")
        try:
            ipaddress.ip_address(parsed.hostname)
        except ValueError:
            if parsed.hostname not in hosts:
                raise CoordinatorError("guarded runtime URL lacks a fixed host mapping")
    return hosts


@dataclass(frozen=True)
class _HttpProbeSlot:
    group_name: str
    listener_name: str
    port: int


def _http_probe_slots(shard_index: int, workers: int) -> tuple[_HttpProbeSlot, ...]:
    """Return deterministic, non-overlapping loopback listeners for one shard."""

    if (
        isinstance(shard_index, bool)
        or not isinstance(shard_index, int)
        or shard_index not in range(SHARD_COUNT)
        or isinstance(workers, bool)
        or not isinstance(workers, int)
        or workers < 1
        or workers > HTTP_PROBE_PORTS_PER_SHARD
    ):
        raise CoordinatorError("HTTP probe slot contract is invalid")
    start = HTTP_PROBE_PORT_BASE + shard_index * HTTP_PROBE_PORT_STRIDE
    return tuple(
        _HttpProbeSlot(
            group_name=f"{HTTP_PROBE_GROUP_PREFIX}{slot}__",
            listener_name=f"{HTTP_PROBE_LISTENER_PREFIX}{slot}",
            port=start + slot,
        )
        for slot in range(workers)
    )


def _http_probe_runtime(
    candidate_names: Sequence[str], *, shard_index: int, workers: int
) -> tuple[tuple[_HttpProbeSlot, ...], list[dict[str, Any]], list[dict[str, Any]]]:
    """Build isolated selector/listener pairs used by concurrent HTTP probes."""

    names = [str(name) for name in candidate_names]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise CoordinatorError("HTTP probe candidate names are invalid")
    slots = _http_probe_slots(shard_index, workers)
    reserved = {INTERNAL_GROUP, *(slot.group_name for slot in slots)}
    if reserved.intersection(names):
        raise CoordinatorError("candidate name collides with an internal probe group")
    if "DIRECT" in names:
        raise CoordinatorError("candidate name collides with a built-in probe target")
    members = [*names, "DIRECT"]
    groups = [
        {
            "name": slot.group_name,
            "type": "select",
            "proxies": list(members),
        }
        for slot in slots
    ]
    listeners = [
        {
            "name": slot.listener_name,
            "type": "mixed",
            "port": slot.port,
            "listen": "127.0.0.1",
            "proxy": slot.group_name,
        }
        for slot in slots
    ]
    return slots, groups, listeners


def _browser_http_outcome(
    controller: str,
    secret: str,
    *,
    slot: _HttpProbeSlot,
    proxy_name: str,
    target_url: str,
    timeout_ms: int,
    expected_status: int = 200,
) -> dict[str, Any]:
    """Send one Chrome-TLS request through an exclusively held Mihomo slot."""

    parsed = urllib.parse.urlsplit(target_url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or isinstance(timeout_ms, bool)
        or not isinstance(timeout_ms, int)
        or timeout_ms <= 0
        or isinstance(expected_status, bool)
        or not isinstance(expected_status, int)
        or not 100 <= expected_status <= 599
    ):
        raise CoordinatorError("browser HTTP probe contract is invalid")
    try:
        _controller_request(
            controller,
            secret,
            "PUT",
            f"/proxies/{urllib.parse.quote(slot.group_name, safe='')}",
            body={"name": proxy_name},
            timeout=CONTROLLER_SELECTION_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        return {"error": f"controller selection failed: {exc}"}

    target_port = parsed.port or 443
    if not 1 <= target_port <= 65_535:
        raise CoordinatorError("browser HTTP probe target port is invalid")
    if curl_requests is None:
        return {
            "error_category": "other",
            "diagnostic_category": "client_dependency_missing",
        }
    proxy_url = f"http://127.0.0.1:{slot.port}"
    started = time.monotonic()
    response = None
    session = curl_requests.Session(
        trust_env=False,
        verify=True,
        impersonate=GMGN_TLS_IMPERSONATE,
        default_headers=True,
        allow_redirects=False,
    )
    try:
        response = session.get(
            target_url,
            proxy=proxy_url,
            timeout=timeout_ms / 1000,
            verify=True,
            impersonate=GMGN_TLS_IMPERSONATE,
            allow_redirects=False,
            stream=True,
            headers={
                "Accept": GMGN_BROWSER_ACCEPT,
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "no-cache",
            },
        )
        status = int(response.status_code)
    except Exception as exc:
        return _safe_curl_probe_failure(exc)
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        try:
            session.close()
        except Exception:
            pass
    delay_ms = max(1, int(round((time.monotonic() - started) * 1000)))
    if not 100 <= status <= 599:
        return {"error": "browser target returned an invalid HTTP status"}
    if status != expected_status:
        return {"target_status": status}
    return {"delay_ms": delay_ms}


def _safe_curl_probe_failure(exc: Exception) -> dict[str, str]:
    """Map curl failures to coarse scoring and public-safe diagnostic labels."""

    text = str(exc).lower()
    if curl_requests is not None:
        errors = curl_requests.exceptions
        if isinstance(exc, errors.CertificateVerifyError):
            return {
                "error_category": "tls",
                "diagnostic_category": "tls_certificate_verify",
            }
        if isinstance(exc, errors.SSLError):
            return {
                "error_category": "tls",
                "diagnostic_category": "tls_handshake",
            }
        if isinstance(exc, errors.Timeout):
            return {
                "error_category": "client_timeout",
                "diagnostic_category": "client_timeout",
            }
        if isinstance(exc, errors.DNSError):
            return {"error_category": "dns", "diagnostic_category": "dns"}
        if isinstance(exc, errors.ProxyError):
            return {
                "error_category": "connect",
                "diagnostic_category": "proxy_connect",
            }
        if isinstance(exc, errors.ConnectionError):
            detail = (
                "connection_eof_reset"
                if any(token in text for token in ("eof", "reset", "got nothing", "recv"))
                else "connection_other"
            )
            return {"error_category": "connect", "diagnostic_category": detail}
    if "certificate" in text or "verify" in text:
        return {
            "error_category": "tls",
            "diagnostic_category": "tls_certificate_verify",
        }
    if "tls" in text or "ssl" in text or "handshake" in text:
        return {"error_category": "tls", "diagnostic_category": "tls_handshake"}
    if "timeout" in text or "timed out" in text:
        return {
            "error_category": "client_timeout",
            "diagnostic_category": "client_timeout",
        }
    if any(token in text for token in ("eof", "reset", "got nothing", "recv")):
        return {
            "error_category": "connect",
            "diagnostic_category": "connection_eof_reset",
        }
    return {"error_category": "other", "diagnostic_category": "other"}


class _BrowserProbePool:
    """Lease one selector/listener pair per concurrent target request."""

    def __init__(
        self,
        controller: str,
        secret: str,
        slots: Sequence[_HttpProbeSlot],
    ) -> None:
        normalized = tuple(slots)
        if (
            not normalized
            or len({slot.group_name for slot in normalized}) != len(normalized)
            or len({slot.port for slot in normalized}) != len(normalized)
        ):
            raise CoordinatorError("browser HTTP probe slots are invalid")
        self.controller = controller
        self.secret = secret
        self._available: queue.Queue[_HttpProbeSlot] = queue.Queue()
        for slot in normalized:
            self._available.put(slot)

    def probe(
        self,
        candidate: Mapping[str, Any],
        target_url: str,
        timeout_ms: int,
        *,
        expected_status: int = 200,
    ) -> dict[str, Any]:
        proxy = candidate.get("proxy")
        proxy_name = str(proxy.get("name") or "") if isinstance(proxy, Mapping) else ""
        if not proxy_name:
            raise CoordinatorError("browser HTTP probe candidate is invalid")
        slot = self._available.get()
        try:
            return _browser_http_outcome(
                self.controller,
                self.secret,
                slot=slot,
                proxy_name=proxy_name,
                target_url=target_url,
                timeout_ms=timeout_ms,
                expected_status=expected_status,
            )
        finally:
            self._available.put(slot)


def _egress(target: Mapping[str, Any]) -> dict[str, Any]:
    status, body, _delay = _pinned_http(target)
    if status != int(target["expected_status"]):
        raise CoordinatorError("egress provider returned an unexpected status")
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise CoordinatorError("egress provider returned invalid JSON") from exc
    if not isinstance(payload, Mapping):
        raise CoordinatorError("egress provider returned an invalid object")
    public_ip = str(payload.get("ip") or "")
    address = ipaddress.ip_address(public_ip)
    if not address.is_global:
        raise CoordinatorError("egress provider returned a non-public address")
    country = str(payload.get("country_code") or "").upper()
    region = str(payload.get("region_code") or payload.get("region") or country)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", region):
        region = country
    org = str(payload.get("organization") or payload.get("isp") or payload.get("asn_organization") or "unknown")
    return {
        "public_ip": address.compressed.lower(),
        "country": country,
        "region": region,
        "org": org[:120] or "unknown",
    }


def _mihomo_delay_outcome(
    controller: str,
    secret: str,
    *,
    proxy_name: str,
    target_url: str,
    timeout_ms: int,
    expected_status: int | str,
) -> dict[str, Any]:
    if isinstance(expected_status, bool):
        raise CoordinatorError("Mihomo delay contract is invalid")
    if isinstance(expected_status, int):
        if not 100 <= expected_status <= 599:
            raise CoordinatorError("Mihomo delay contract is invalid")
        expected = str(expected_status)
    elif expected_status == "100-599":
        # Mihomo's delay API parses status ranges; keep this narrow escape
        # hatch for reachability diagnostics that accept any HTTP response.
        expected = expected_status
    else:
        raise CoordinatorError("Mihomo delay contract is invalid")
    if timeout_ms <= 0:
        raise CoordinatorError("Mihomo delay contract is invalid")
    path = (
        f"/proxies/{urllib.parse.quote(proxy_name, safe='')}/delay"
        f"?timeout={timeout_ms}&url={urllib.parse.quote(target_url, safe='')}"
        f"&expected={expected}"
    )
    delay_payload: dict[str, Any] | None = None
    delay_error: str | None = None
    delay_controller_status: int | None = None
    try:
        delay_payload = _controller_request(
            controller,
            secret,
            "GET",
            path,
            timeout=timeout_ms / 1000 + DELAY_REQUEST_OVERHEAD_SECONDS,
        )
    except Exception as exc:
        delay_error = str(exc)
        status_match = re.search(r"controller status (\d{3})", delay_error)
        delay_controller_status = (
            int(status_match.group(1)) if status_match else None
        )

    # Mihomo's delay route returns the elapsed time even when ``expected`` did
    # not match the HTTP response.  The URL-specific ``extra`` state is the
    # authoritative status-policy result.  Reading it after the delay call
    # keeps candidate checks strict HTTP 200 and canaries strict HTTP 204.
    try:
        proxy_state = _controller_request(
            controller,
            secret,
            "GET",
            f"/proxies/{urllib.parse.quote(proxy_name, safe='')}",
            timeout=CONTROLLER_HEALTH_TIMEOUT_SECONDS,
        )
        extra = proxy_state.get("extra")
        url_state = extra.get(target_url) if isinstance(extra, Mapping) else None
        if not isinstance(url_state, Mapping) or not isinstance(
            url_state.get("alive"), bool
        ):
            raise CoordinatorError("controller URL-test state is unavailable")
        alive = bool(url_state["alive"])
        history = url_state.get("history")
        history_delay: int | None = None
        if isinstance(history, list) and history and isinstance(history[-1], Mapping):
            raw_history_delay = history[-1].get("delay")
            if (
                isinstance(raw_history_delay, int)
                and not isinstance(raw_history_delay, bool)
                and raw_history_delay > 0
            ):
                history_delay = raw_history_delay
    except Exception as exc:
        if delay_error is not None:
            return {
                "controller_status": delay_controller_status,
                "error": delay_error,
            }
        return {"error": str(exc)}

    if alive:
        raw_delay = delay_payload.get("delay") if delay_payload is not None else None
        if isinstance(raw_delay, int) and not isinstance(raw_delay, bool) and raw_delay > 0:
            delay = raw_delay
        elif history_delay is not None:
            delay = history_delay
        else:
            # Sub-millisecond local URL tests are rounded to zero by Mihomo,
            # even though the expected-status state is satisfied.
            delay = 1
        return {"delay_ms": delay, "controller_status": 200}
    if delay_error is not None:
        return {
            "controller_status": delay_controller_status,
            "error": delay_error,
        }
    return {"controller_status": 200, "error_category": "other"}


def _delay_attempt(
    controller: str,
    secret: str,
    candidate: Mapping[str, Any],
    target_url: str,
    timeout_ms: int,
    *,
    expected_status: int | str = 200,
) -> dict[str, Any]:
    return _mihomo_delay_outcome(
        controller,
        secret,
        proxy_name=str(candidate["proxy"]["name"]),
        target_url=target_url,
        timeout_ms=timeout_ms,
        expected_status=expected_status,
    )


def _spread_candidates(
    candidates: Sequence[Mapping[str, Any]], count: int
) -> list[dict[str, Any]]:
    if count <= 0:
        return []
    normalized = [copy.deepcopy(dict(candidate)) for candidate in candidates]
    if len(normalized) <= count:
        return normalized
    return [normalized[index * len(normalized) // count] for index in range(count)]


def _select_control_candidates(
    candidates: Sequence[Mapping[str, Any]], *, limit: int = CONTROL_DISCOVERY_SIZE
) -> tuple[dict[str, Any], ...]:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise CoordinatorError("GMGN control discovery size is invalid")
    normalized = [copy.deepcopy(dict(candidate)) for candidate in candidates]
    if not normalized:
        raise CoordinatorError("GMGN control discovery has no guarded candidates")
    ids = [str(candidate.get("candidate_id") or "") for candidate in normalized]
    states = [candidate.get("github_check_state") for candidate in normalized]
    if (
        any(not value for value in ids)
        or len(ids) != len(set(ids))
        or any(state not in {"passed", "bypassed_asia"} for state in states)
    ):
        raise CoordinatorError("GMGN control discovery candidates are invalid")

    passed = sorted(
        (candidate for candidate in normalized if candidate["github_check_state"] == "passed"),
        key=lambda candidate: str(candidate["candidate_id"]),
    )
    bypassed = sorted(
        (
            candidate
            for candidate in normalized
            if candidate["github_check_state"] == "bypassed_asia"
        ),
        key=lambda candidate: str(candidate["candidate_id"]),
    )
    target_count = min(limit, len(normalized))
    passed_count = min(len(passed), target_count)
    bypassed_count = min(len(bypassed), target_count - passed_count)
    selected = _spread_candidates(passed, passed_count) + _spread_candidates(
        bypassed, bypassed_count
    )
    selected.sort(key=lambda candidate: str(candidate["candidate_id"]))
    return tuple(selected)


def _dominant_error_category(counts: Mapping[str, int]) -> str:
    category_order = {category: index for index, category in enumerate(ERROR_CATEGORIES)}
    return min(
        ERROR_CATEGORIES,
        key=lambda category: (-int(counts.get(category, 0)), category_order[category]),
    )


def _safe_probe_summary(
    outcomes: Sequence[Mapping[str, Any] | None],
) -> dict[str, Any]:
    error_counts = {category: 0 for category in ERROR_CATEGORIES}
    diagnostic_counts = {
        category: 0 for category in SAFE_PROBE_DIAGNOSTIC_CATEGORIES
    }
    status_counts: dict[str, int] = {}
    successes = 0
    for raw in outcomes:
        outcome = dict(raw or {})
        try:
            delay, category = normalize_outcome(outcome)
        except Exception:
            delay, category = None, "other"
        if delay is not None:
            successes += 1
        else:
            error_counts[str(category or "other")] += 1
        detail = outcome.get("diagnostic_category")
        if detail is not None:
            normalized_detail = (
                str(detail)
                if detail in SAFE_PROBE_DIAGNOSTIC_CATEGORIES
                else "other"
            )
            diagnostic_counts[normalized_detail] += 1
        target_status = outcome.get("target_status")
        if isinstance(target_status, int) and not isinstance(target_status, bool):
            key = str(target_status)
            status_counts[key] = status_counts.get(key, 0) + 1
    return {
        "attempt_count": len(outcomes),
        "success_count": successes,
        "error_counts": {
            category: count for category, count in error_counts.items() if count
        },
        "diagnostic_counts": {
            category: count
            for category, count in diagnostic_counts.items()
            if count
        },
        "target_status_counts": dict(sorted(status_counts.items())),
    }


def _run_safe_probe_group(
    calls: Sequence[Callable[[], Mapping[str, Any] | None]],
    *,
    workers: int = 8,
) -> dict[str, Any]:
    if (
        not calls
        or isinstance(workers, bool)
        or not isinstance(workers, int)
        or workers < 1
    ):
        raise CoordinatorError("safe probe group contract is invalid")
    outcomes: list[Mapping[str, Any] | None] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(calls))) as executor:
        futures = [executor.submit(call) for call in calls]
        for future in as_completed(futures):
            try:
                outcomes.append(future.result())
            except Exception as exc:
                outcomes.append(
                    {
                        "error_category": classify_error(exc),
                        "diagnostic_category": "other",
                    }
                )
    return _safe_probe_summary(outcomes)


def _same_client_probe_matrix(
    candidates: Sequence[Mapping[str, Any]],
    *,
    direct_gmgn_probe: Callable[[], Mapping[str, Any] | None],
    proxy_gmgn_probe: Callable[[Mapping[str, Any]], Mapping[str, Any] | None],
    proxy_canary_probe: Callable[
        [Mapping[str, Any], str], Mapping[str, Any] | None
    ],
    canary_ids: Sequence[str],
    proxy_limit: int = 4,
) -> dict[str, Any]:
    """Compare target and canary paths with one TLS client before discovery."""

    normalized = [dict(candidate) for candidate in candidates]
    normalized_canaries = [str(value) for value in canary_ids]
    if (
        not normalized
        or not normalized_canaries
        or isinstance(proxy_limit, bool)
        or not isinstance(proxy_limit, int)
        or proxy_limit < 1
    ):
        raise CoordinatorError("same-client probe matrix contract is invalid")
    selected = normalized[: min(proxy_limit, len(normalized))]
    return {
        "kind": "cnb-gmgn-v2-same-client-matrix",
        "schema_version": 1,
        "client": {
            "implementation": "curl_cffi",
            "impersonate": GMGN_TLS_IMPERSONATE,
            "tls_verify": True,
            "redirects": False,
            "environment_proxy": False,
        },
        "direct_gmgn": _run_safe_probe_group([direct_gmgn_probe]),
        "proxy_gmgn": _run_safe_probe_group(
            [lambda candidate=candidate: proxy_gmgn_probe(candidate) for candidate in selected]
        ),
        "proxy_canaries": {
            canary_id: _run_safe_probe_group(
                [
                    lambda candidate=candidate, canary_id=canary_id: proxy_canary_probe(
                        candidate, canary_id
                    )
                    for candidate in selected
                ]
            )
            for canary_id in normalized_canaries
        },
    }


def _discover_control_panel(
    candidates: Sequence[Mapping[str, Any]],
    probe: Callable[[Mapping[str, Any]], Mapping[str, Any] | None],
    *,
    panel_size: int = CONTROL_PANEL_SIZE,
    batch_size: int = CONTROL_DISCOVERY_BATCH_SIZE,
    workers: int = CONTROL_DISCOVERY_WORKERS,
) -> tuple[tuple[dict[str, Any], ...], dict[str, Any]]:
    selected = [copy.deepcopy(dict(candidate)) for candidate in candidates]
    if (
        not selected
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in (panel_size, batch_size, workers)
        )
    ):
        raise CoordinatorError("GMGN control discovery contract is invalid")
    successes: list[tuple[int, str, dict[str, Any]]] = []
    counts = {category: 0 for category in ERROR_CATEGORIES}
    diagnostic_counts = {
        category: 0 for category in SAFE_PROBE_DIAGNOSTIC_CATEGORIES
    }
    status_counts: dict[str, int] = {}
    attempted = 0
    for offset in range(0, len(selected), batch_size):
        batch = selected[offset : offset + batch_size]
        with ThreadPoolExecutor(max_workers=min(workers, len(batch))) as executor:
            futures = {
                executor.submit(probe, candidate): candidate for candidate in batch
            }
            for future in as_completed(futures):
                candidate = futures[future]
                attempted += 1
                try:
                    outcome = dict(future.result() or {})
                    delay, category = normalize_outcome(outcome)
                except Exception:
                    outcome = {}
                    delay, category = None, "other"
                detail = outcome.get("diagnostic_category")
                if detail is not None:
                    normalized_detail = (
                        str(detail)
                        if detail in SAFE_PROBE_DIAGNOSTIC_CATEGORIES
                        else "other"
                    )
                    diagnostic_counts[normalized_detail] += 1
                target_status = outcome.get("target_status")
                if isinstance(target_status, int) and not isinstance(
                    target_status, bool
                ):
                    key = str(target_status)
                    status_counts[key] = status_counts.get(key, 0) + 1
                if delay is not None:
                    successes.append(
                        (int(delay), str(candidate["candidate_id"]), candidate)
                    )
                else:
                    counts[str(category or "other")] += 1
        if len(successes) >= panel_size:
            break

    diagnostics = {
        "candidate_count": len(selected),
        "attempt_count": attempted,
        "success_count": len(successes),
        "error_counts": {
            category: counts[category]
            for category in ERROR_CATEGORIES
            if counts[category]
        },
        "diagnostic_counts": {
            category: diagnostic_counts[category]
            for category in sorted(SAFE_PROBE_DIAGNOSTIC_CATEGORIES)
            if diagnostic_counts[category]
        },
        "target_status_counts": dict(sorted(status_counts.items())),
    }
    if not successes:
        raise ControlDiscoveryError(diagnostics)
    successes.sort(key=lambda item: (item[0], item[1]))
    panel = tuple(item[2] for item in successes[:panel_size])
    diagnostics["panel_size"] = len(panel)
    return panel, diagnostics


def _control_panel_outcome(
    candidates: Sequence[Mapping[str, Any]],
    probe: Callable[[Mapping[str, Any]], Mapping[str, Any] | None],
    *,
    workers: int = CONTROL_PANEL_WORKERS,
) -> dict[str, Any]:
    panel = [dict(candidate) for candidate in candidates]
    if (
        not panel
        or isinstance(workers, bool)
        or not isinstance(workers, int)
        or workers < 1
    ):
        raise CoordinatorError("GMGN control panel contract is invalid")
    results: list[tuple[int | None, str | None]] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(panel))) as executor:
        futures = [executor.submit(probe, candidate) for candidate in panel]
        for future in as_completed(futures):
            try:
                outcome = future.result()
                results.append(normalize_outcome(outcome))
            except Exception:
                results.append((None, "other"))
    delays = [delay for delay, _category in results if delay is not None]
    if delays:
        return {"delay_ms": min(delays)}
    counts = {category: 0 for category in ERROR_CATEGORIES}
    for _delay, category in results:
        counts[str(category or "other")] += 1
    return {"error_category": _dominant_error_category(counts)}


def _safe_error_counts(samples: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {category: 0 for category in ERROR_CATEGORIES}
    for sample in samples:
        category = sample.get("error_category")
        if category is not None:
            counts[str(category)] += 1
    return {category: counts[category] for category in ERROR_CATEGORIES if counts[category]}


def _require_direct_probe_preflight(
    *,
    control_probe: Callable[[int], Mapping[str, Any] | None],
    canary_probe: Callable[[str, int], Mapping[str, Any] | None],
    canary_ids: Sequence[str],
    attempts: int = DIRECT_PREFLIGHT_ATTEMPTS,
) -> dict[str, Any]:
    """Reject a broken proxy control panel or direct canary path early."""

    if attempts < 1:
        raise CoordinatorError("direct probe preflight attempt count is invalid")
    normalized_canary_ids = [str(value).strip() for value in canary_ids]
    if (
        not normalized_canary_ids
        or any(not value for value in normalized_canary_ids)
        or len(normalized_canary_ids) != len(set(normalized_canary_ids))
    ):
        raise CoordinatorError("direct probe preflight canary set is invalid")
    control_samples: list[dict[str, Any]] = []
    canary_samples: dict[str, list[dict[str, Any]]] = {
        canary_id: [] for canary_id in normalized_canary_ids
    }
    for round_number in range(1, attempts + 1):
        try:
            control_outcome = dict(control_probe(round_number) or {})
        except Exception as exc:
            control_outcome = {"error": str(exc)}
        delay, category = normalize_outcome(control_outcome)
        control_samples.append(
            {
                "round": round_number,
                "delay_ms": delay,
                "error_category": category,
            }
        )
        for canary_id in canary_samples:
            try:
                canary_outcome = canary_probe(canary_id, round_number)
            except Exception as exc:
                canary_outcome = {"error": str(exc)}
            canary_delay, canary_category = normalize_outcome(canary_outcome)
            canary_samples[canary_id].append(
                {
                    "round": round_number,
                    "delay_ms": canary_delay,
                    "error_category": canary_category,
                }
            )

    control_successes = sum(item["delay_ms"] is not None for item in control_samples)
    canary_summaries = []
    for canary_id, samples in canary_samples.items():
        success_count = sum(item["delay_ms"] is not None for item in samples)
        canary_summaries.append(
            {
                "canary_id": canary_id,
                "attempt_count": attempts,
                "success_count": success_count,
                "error_counts": _safe_error_counts(samples),
            }
        )
    diagnostics = {
        "kind": "cnb-gmgn-safe-direct-probe-preflight",
        "schema_version": 1,
        "control": {
            "attempt_count": attempts,
            "success_count": control_successes,
            "error_counts": _safe_error_counts(control_samples),
        },
        "canaries": canary_summaries,
    }
    if control_successes == 0:
        raise CoordinatorError(
            "GMGN proxy control preflight failed; safe diagnostics="
            + json.dumps(diagnostics, sort_keys=True, separators=(",", ":"))
        )
    if any(item["success_count"] == 0 for item in canary_summaries):
        raise CoordinatorError(
            "direct canary preflight failed; safe diagnostics="
            + json.dumps(diagnostics, sort_keys=True, separators=(",", ":"))
        )
    return diagnostics


def _safe_direct_probe_diagnostics(
    shard_index: int,
    scheduled: Any,
    private_fragment: Mapping[str, Any],
) -> dict[str, Any]:
    # ``private_fragment`` is the credential-bearing input assembled for the
    # same run, but its public projection uses a different ``controller``
    # summary shape.  The scheduler is the authoritative source at this
    # point: its raw health observations live under ``controller_checks``.
    # Reading ``private_fragment["controller"]`` here would only work for the
    # later redacted fragment and fails after a full 20-round probe.
    controller_checks = tuple(scheduled.controller_checks)
    canaries: list[dict[str, Any]] = []
    for summary in summarize_canaries(scheduled.canary_samples, CANARY_IDS):
        canary_id = str(summary["canary_id"])
        samples = [
            sample
            for sample in scheduled.canary_samples
            if str(sample["canary_id"]) == canary_id
        ]
        canaries.append({**summary, "error_counts": _safe_error_counts(samples)})
    return {
        "kind": "cnb-gmgn-safe-probe-diagnostics",
        "schema_version": 3,
        "shard_index": shard_index,
        "clients": {
            "control": "browser-http-proxy-panel-strict-200",
            "canaries": "mihomo-direct-exact-state",
        },
        "control": {
            **summarize_control(scheduled.control_samples),
            "error_counts": _safe_error_counts(scheduled.control_samples),
        },
        "canaries": canaries,
        "controller_unhealthy_count": int(
            sum(not bool(item.get("healthy")) for item in controller_checks)
        ),
    }


def _proxy_region(
    *,
    controller: str,
    secret: str,
    mixed_port: int,
    proxy_name: str,
    provider_target: Mapping[str, Any],
) -> dict[str, Any] | None:
    try:
        _controller_request(
            controller,
            secret,
            "PUT",
            f"/proxies/{urllib.parse.quote(INTERNAL_GROUP, safe='')}",
            body={"name": proxy_name},
            timeout=CONTROLLER_SELECTION_TIMEOUT_SECONDS,
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(
                {
                    "http": f"http://127.0.0.1:{mixed_port}",
                    "https": f"http://127.0.0.1:{mixed_port}",
                }
            )
        )
        request = urllib.request.Request(
            f"https://{provider_target['server']}{provider_target['path']}",
            headers={"User-Agent": "aggregator-gmgn-v2/1.0", "Accept": "application/json"},
        )
        with opener.open(request, timeout=REGION_LOOKUP_TIMEOUT_SECONDS) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read(1024 * 1024).decode("utf-8"))
        if not isinstance(payload, Mapping):
            return None
        address = ipaddress.ip_address(str(payload.get("ip") or ""))
        if not address.is_global:
            return None
        country = str(payload.get("country_code") or "").upper()
        if not re.fullmatch(r"[A-Z]{2}", country):
            return None
        region = str(payload.get("region_code") or payload.get("region") or country)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", region):
            region = country
        raw_asn = payload.get("asn")
        normalized_asn = canonical_asn(raw_asn) if raw_asn not in (None, "") else None
        return {
            "public_ip": address.compressed.lower(),
            "country_code": country,
            "region_code": region,
            "asn": normalized_asn,
            "observed_at": utc_now(),
        }
    except Exception:
        return None


def _probe_inside(args: argparse.Namespace) -> int:
    context = _load_json(args.context)
    expected_context_fields = {
        "manifest",
        "shard_index",
        "candidates",
        "pinned_candidates",
        "dns_failed_candidate_ids",
        "ipv6_unavailable_candidate_ids",
        "auxiliary_targets",
        "controller_secret",
        "mihomo",
        "work_dir",
        "private_fragment",
        "raw_regions",
    }
    if set(context) != expected_context_fields:
        raise CoordinatorError("probe context fields are incomplete or unexpected")
    manifest = validate_manifest_v3(context["manifest"])
    index = int(context["shard_index"])
    candidates = _load_shard(manifest, _write_context_shard(context), index)
    # ``_write_context_shard`` validates the in-memory copy without trusting a
    # second path supplied by the child command.
    normalize_pinned_targets(context["pinned_candidates"])
    normalize_auxiliary_targets(context["auxiliary_targets"])
    pinned = {
        key: dict(value) for key, value in context["pinned_candidates"].items()
    }
    auxiliary = {
        key: dict(value) for key, value in context["auxiliary_targets"].items()
    }
    raw_dns_failed = context["dns_failed_candidate_ids"]
    if not isinstance(raw_dns_failed, list):
        raise CoordinatorError("probe context DNS failure partition is malformed")
    dns_failed_candidate_ids = [
        validate_public_id(item, "candidate") for item in raw_dns_failed
    ]
    if dns_failed_candidate_ids != sorted(set(dns_failed_candidate_ids)):
        raise CoordinatorError("probe context DNS failure partition is non-canonical")
    raw_ipv6_unavailable = context["ipv6_unavailable_candidate_ids"]
    if not isinstance(raw_ipv6_unavailable, list):
        raise CoordinatorError("probe context IPv6 partition is malformed")
    ipv6_unavailable_candidate_ids = [
        validate_public_id(item, "candidate") for item in raw_ipv6_unavailable
    ]
    if ipv6_unavailable_candidate_ids != sorted(
        set(ipv6_unavailable_candidate_ids)
    ):
        raise CoordinatorError("probe context IPv6 partition is non-canonical")
    resolution = _build_probe_resolution(
        manifest,
        candidates,
        index,
        pinned_candidate_ids=pinned,
        dns_failed_candidate_ids=dns_failed_candidate_ids,
        ipv6_unavailable_candidate_ids=ipv6_unavailable_candidate_ids,
    )
    guarded_ids = set(resolution["guarded_candidate_ids"])
    dns_failed_ids = set(resolution["dns_failed_candidate_ids"])
    ipv6_unavailable_ids = set(
        resolution["ipv6_unavailable_candidate_ids"]
    )
    guarded_candidates = [
        item for item in candidates if item["candidate_id"] in guarded_ids
    ]
    secret = str(context["controller_secret"])
    shard = manifest["shards"][index]
    controller = f"127.0.0.1:{shard['controller_port']}"
    work_dir = Path(context["work_dir"])
    work_dir.mkdir(parents=True, exist_ok=True)
    names = [str(item["proxy"]["name"]) for item in candidates]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise CoordinatorError("shard proxy names are missing, duplicated, or reserved")
    guarded_names = [str(item["proxy"]["name"]) for item in guarded_candidates]
    http_slots, http_groups, http_listeners = _http_probe_runtime(
        guarded_names,
        shard_index=index,
        workers=int(manifest["workers_per_shard"]),
    )
    if {
        INTERNAL_GROUP,
        "DIRECT",
        *(slot.group_name for slot in http_slots),
    }.intersection(names):
        raise CoordinatorError("shard proxy names are missing, duplicated, or reserved")
    hosts = _runtime_hosts(
        pinned,
        auxiliary,
        target_url=str(manifest["target_url"]),
    )
    runtime = {
        "mixed-port": int(shard["mixed_port"]),
        "external-controller": controller,
        "secret": secret,
        "allow-lan": False,
        "mode": "global",
        "log-level": "warning",
        "hosts": hosts,
        "proxies": [copy.deepcopy(item["proxy"]) for item in guarded_candidates],
        "proxy-groups": [
            {
                "name": INTERNAL_GROUP,
                "type": "select",
                "proxies": guarded_names + ["DIRECT"],
            },
            *http_groups,
        ],
        "listeners": http_listeners,
        "rules": [f"MATCH,{INTERNAL_GROUP}"],
    }
    runtime_yaml, invalid = dump_clash_yaml(runtime)
    if invalid:
        raise CoordinatorError("guarded runtime contains invalid REALITY IDs")
    config = work_dir / "mihomo-runtime.yaml"
    _write_bytes(config, runtime_yaml.encode("utf-8"))
    log = (work_dir / "mihomo.log").open("wb")
    process = _start_mihomo(
        context["mihomo"],
        work_dir=work_dir,
        config=config,
        log=log,
    )
    stage = "mihomo_startup"
    safe_diagnostics = work_dir.parent / "safe-diagnostics"
    try:
        controller_version = _wait_mihomo(controller, secret, process)
        if controller_version != manifest["mihomo_version"]:
            raise CoordinatorError("Mihomo controller version differs from the manifest")
        time.sleep(HTTP_PROBE_STARTUP_GRACE_SECONDS)
        browser_probe = _BrowserProbePool(controller, secret, http_slots)

        def health(_phase: str, _round: int) -> dict[str, Any]:
            if process.poll() is not None:
                return {"healthy": False, "version": controller_version}
            try:
                payload = _controller_request(
                    controller,
                    secret,
                    "GET",
                    "/version",
                    timeout=CONTROLLER_HEALTH_TIMEOUT_SECONDS,
                )
                version = str(payload.get("version") or "").removeprefix("v")
                return {"healthy": version == controller_version, "version": version}
            except Exception:
                return {"healthy": False, "version": controller_version}

        def attempt(candidate: Mapping[str, Any], _round: int) -> dict[str, Any]:
            candidate_id = str(candidate["candidate_id"])
            if candidate_id in dns_failed_ids:
                return {"error_category": "dns"}
            if candidate_id in ipv6_unavailable_ids:
                return {"error_category": "connect"}
            return browser_probe.probe(
                candidate,
                str(manifest["target_url"]),
                int(manifest["request_timeout_ms"]),
                expected_status=int(manifest["expected_status"]),
            )

        control_target = _operational_target("control-gmgn-v1", auxiliary)
        control_authority = str(control_target["server"])
        if int(control_target["port"]) != 443:
            control_authority = f"{control_authority}:{control_target['port']}"
        control_url = f"https://{control_authority}{control_target['path']}"
        if (
            control_target.get("status_policy") != "exact"
            or int(control_target.get("expected_status", 0))
            != CONTROL_EXPECTED_STATUS
            or control_url != str(manifest["target_url"])
        ):
            raise CoordinatorError("GMGN control reachability target is invalid")

        def control_attempt(
            candidate: Mapping[str, Any], _round: int
        ) -> dict[str, Any]:
            candidate_id = str(candidate["candidate_id"])
            if candidate_id in dns_failed_ids:
                return {"error_category": "dns"}
            if candidate_id in ipv6_unavailable_ids:
                return {"error_category": "connect"}
            return browser_probe.probe(
                candidate,
                control_url,
                min(int(manifest["request_timeout_ms"]), CONTROL_PROBE_TIMEOUT_MS),
                expected_status=CONTROL_EXPECTED_STATUS,
            )

        def mihomo_direct_probe(name: str) -> dict[str, Any]:
            target = _operational_target(name, auxiliary)
            if target.get("status_policy") != "exact":
                raise CoordinatorError("Mihomo direct target policy is invalid")
            port = int(target["port"])
            authority = str(target["server"])
            if port != 443:
                authority = f"{authority}:{port}"
            return _mihomo_delay_outcome(
                controller,
                secret,
                proxy_name="DIRECT",
                target_url=f"https://{authority}{target['path']}",
                timeout_ms=int(DIRECT_PROBE_TIMEOUT_SECONDS * 1000),
                expected_status=int(target["expected_status"]),
            )

        control_candidates = _select_control_candidates(guarded_candidates)
        stage = "same_client_matrix"

        def browser_canary_attempt(
            candidate: Mapping[str, Any], name: str
        ) -> dict[str, Any]:
            target = _operational_target(name, auxiliary)
            if target.get("status_policy") != "exact":
                raise CoordinatorError("browser canary target policy is invalid")
            port = int(target["port"])
            authority = str(target["server"])
            if port != 443:
                authority = f"{authority}:{port}"
            return browser_probe.probe(
                candidate,
                f"https://{authority}{target['path']}",
                int(DIRECT_PROBE_TIMEOUT_SECONDS * 1000),
                expected_status=int(target["expected_status"]),
            )

        same_client_matrix = _same_client_probe_matrix(
            control_candidates,
            direct_gmgn_probe=lambda: browser_probe.probe(
                {"proxy": {"name": "DIRECT"}},
                control_url,
                CONTROL_PROBE_TIMEOUT_MS,
                expected_status=CONTROL_EXPECTED_STATUS,
            ),
            proxy_gmgn_probe=lambda candidate: control_attempt(candidate, 0),
            proxy_canary_probe=browser_canary_attempt,
            canary_ids=CANARY_IDS,
        )
        _write_json(
            safe_diagnostics / "same-client-matrix.json", same_client_matrix
        )
        print(
            "GMGN V2 same-client probe matrix: "
            + json.dumps(
                same_client_matrix,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )

        stage = "control_discovery"
        control_panel, control_discovery = _discover_control_panel(
            control_candidates,
            lambda candidate: control_attempt(candidate, 0),
        )

        def control_probe(round_number: int) -> dict[str, Any]:
            return _control_panel_outcome(
                control_panel,
                lambda candidate: control_attempt(candidate, round_number),
            )

        stage = "direct_preflight"
        preflight_diagnostics = _require_direct_probe_preflight(
            control_probe=control_probe,
            canary_probe=lambda canary, _round: mihomo_direct_probe(canary),
            canary_ids=CANARY_IDS,
        )
        preflight_diagnostics["control_discovery"] = control_discovery
        print(
            "GMGN V2 safe probe preflight: "
            + json.dumps(
                preflight_diagnostics,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )

        stage = "measurement"
        scheduled = run_measurement_schedule(
            candidates,
            attempt,
            workers=int(manifest["workers_per_shard"]),
            total_rounds=int(manifest["total_rounds"]),
            minimum_observation_window_seconds=float(
                manifest["minimum_observation_window_seconds"]
            ),
            health_check=health,
            control_probe=control_probe,
            canary_probe=lambda canary, _round: mihomo_direct_probe(canary),
            canary_ids=CANARY_IDS,
            egress_probe=lambda _phase: _egress(
                _operational_target("egress-provider-v1", auxiliary)
            ),
            stagger_seconds=int(shard["stagger_seconds"]),
        )
        private_fragment = build_private_fragment(
            manifest,
            shard_index=index,
            shard_candidates=candidates,
            scheduled=scheduled,
        )
        print(
            "GMGN V2 safe probe diagnostics: "
            + json.dumps(
                _safe_direct_probe_diagnostics(index, scheduled, private_fragment),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
        write_private_fragment(
            context["private_fragment"],
            private_fragment,
            private_root=Path(context["private_fragment"]).parent,
        )
        stage = "region_lookup"
        summaries = {item["candidate_id"]: item["summary"] for item in private_fragment["results"]}
        raw_regions: dict[str, Any] = {}
        for item in candidates:
            candidate_id_value = item["candidate_id"]
            if int(summaries[candidate_id_value]["response_count"]) < 1:
                continue
            observation = _proxy_region(
                controller=controller,
                secret=secret,
                mixed_port=int(shard["mixed_port"]),
                proxy_name=str(item["proxy"]["name"]),
                provider_target=_operational_target(
                    REGION_PROVIDER_TARGET, auxiliary
                ),
            )
            if observation is not None:
                raw_regions[candidate_id_value] = observation
        _write_json(
            Path(context["raw_regions"]),
            {
                "kind": RAW_REGION_KIND,
                "schema_version": RAW_REGION_SCHEMA_VERSION,
                "run_id": manifest["run_id"],
                "shard_index": index,
                "observations": raw_regions,
            },
        )
    except Exception as exc:
        failure_diagnostics: dict[str, Any] = {
            "kind": "cnb-gmgn-v2-safe-failure-diagnostics",
            "schema_version": 1,
            "shard_index": index,
            "stage": stage,
            "error_category": classify_error(exc),
        }
        if isinstance(exc, ControlDiscoveryError):
            failure_diagnostics["control_discovery"] = exc.diagnostics
        _write_json(
            safe_diagnostics / "failure-diagnostics.json", failure_diagnostics
        )
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()
    return 0


def _write_context_shard(context: Mapping[str, Any]) -> Path:
    path = Path(context["work_dir"]).parent / "context-shard.json"
    _write_json(
        path,
        {
            "kind": SHARD_INPUT_KIND,
            "schema_version": SHARD_INPUT_SCHEMA_VERSION,
            "manifest_sha256": canonical_json_sha256(context["manifest"]),
            "run_id": context["manifest"]["run_id"],
            "shard_index": context["shard_index"],
            "candidates": context["candidates"],
        },
    )
    return path


def _redact(args: argparse.Namespace) -> int:
    manifest = validate_manifest_v3(_load_json(args.manifest))
    settings = IdentitySettings.from_environment()
    verify_identity_test_vector(args.identity_fixture)
    if (
        settings.identity_key_version != manifest["identity_key_version"]
        or settings.identity_epoch != manifest["identity_epoch"]
    ):
        raise CoordinatorError("identity settings differ from the manifest")
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    observations: dict[str, dict[str, Any]] = {}
    for index in range(SHARD_COUNT):
        private = _load_json(Path(args.shard_root) / f"shard-{index}" / "private-fragment.json")
        redacted = build_redacted_fragment(
            manifest,
            private,
            exit_id_resolver=lambda value: exit_id(
                value,
                key=settings.key,
                identity_key_version=settings.identity_key_version,
                identity_epoch=settings.identity_epoch,
            ),
        )
        _write_json(output / "fragments" / f"shard-{index}.json", redacted)
        raw = _load_json(Path(args.shard_root) / f"shard-{index}" / "raw-regions.json")
        if (
            set(raw) != {"kind", "schema_version", "run_id", "shard_index", "observations"}
            or raw["kind"] != RAW_REGION_KIND
            or raw["schema_version"] != RAW_REGION_SCHEMA_VERSION
            or raw["run_id"] != manifest["run_id"]
            or raw["shard_index"] != index
            or not isinstance(raw["observations"], Mapping)
        ):
            raise CoordinatorError("private region observations are malformed")
        for candidate_id_value, item in raw["observations"].items():
            candidate_id_value = validate_public_id(candidate_id_value, "candidate")
            if candidate_id_value in observations or not isinstance(item, Mapping):
                raise CoordinatorError("private region observations are duplicated or malformed")
            raw_asn = item.get("asn")
            observations[candidate_id_value] = {
                "kind": REGION_OBSERVATION_KIND,
                "schema_version": REGION_OBSERVATION_SCHEMA_VERSION,
                "candidate_id": candidate_id_value,
                "identity_key_version": settings.identity_key_version,
                "identity_epoch": settings.identity_epoch,
                "country_code": str(item.get("country_code") or ""),
                "region_code": str(item.get("region_code") or ""),
                "exit_id": exit_id(
                    item.get("public_ip"),
                    key=settings.key,
                    identity_key_version=settings.identity_key_version,
                    identity_epoch=settings.identity_epoch,
                ),
                "asn_id": (
                    asn_id(
                        raw_asn,
                        key=settings.key,
                        identity_key_version=settings.identity_key_version,
                        identity_epoch=settings.identity_epoch,
                    )
                    if raw_asn is not None
                    else None
                ),
                "observed_at": str(item.get("observed_at") or ""),
                "provider_schema": REGION_PROVIDER_SCHEMA_VERSION,
            }
    _write_json(
        output / "region-observations.json",
        {
            "kind": OPAQUE_REGION_KIND,
            "schema_version": OPAQUE_REGION_SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "observations": observations,
        },
    )
    return 0


def _load_prepared_snapshot(path: str | Path, manifest: Mapping[str, Any]) -> PreparedSnapshot:
    value = _load_json(path)
    expected_fields = {
        "kind",
        "schema_version",
        "snapshot_id",
        "main_sha",
        "profile_sha256",
        "candidate_metadata_sha256",
        "identity_key_version",
        "identity_epoch",
        "source_run_at",
        "sources",
        "candidates",
    }
    if set(value) != expected_fields or value["kind"] != PREPARED_SNAPSHOT_KIND or value["schema_version"] != PREPARED_SNAPSHOT_SCHEMA_VERSION:
        raise CoordinatorError("prepared snapshot fields are incomplete or unexpected")
    bindings = {
        "snapshot_id": "snapshot_id",
        "main_sha": "main_sha",
        "profile_sha256": "profile_sha256",
        "candidate_metadata_sha256": "candidate_metadata_sha256",
        "identity_key_version": "identity_key_version",
        "identity_epoch": "identity_epoch",
        "source_run_at": "source_run_at",
    }
    for local, remote in bindings.items():
        if value[local] != manifest[remote]:
            raise CoordinatorError(f"prepared snapshot {local} binding mismatch")
    raw_candidates = value["candidates"]
    if not isinstance(raw_candidates, list) or len(raw_candidates) != manifest["candidate_count"]:
        raise CoordinatorError("prepared snapshot candidate count mismatch")
    entries: list[CandidateSnapshotEntry] = []
    ids: set[str] = set()
    for raw in raw_candidates:
        if not isinstance(raw, Mapping) or set(raw) != {"candidate_id", "proxy", "metadata"}:
            raise CoordinatorError("prepared snapshot candidate is malformed")
        candidate_id_value = validate_public_id(raw["candidate_id"], "candidate")
        if candidate_id_value in ids or not isinstance(raw["proxy"], Mapping) or not isinstance(raw["metadata"], Mapping):
            raise CoordinatorError("prepared snapshot candidate binding is invalid")
        ids.add(candidate_id_value)
        entries.append(
            CandidateSnapshotEntry(
                candidate_id=candidate_id_value,
                proxy=copy.deepcopy(dict(raw["proxy"])),
                metadata=copy.deepcopy(dict(raw["metadata"])),
            )
        )
    metadata = {"schema_version": manifest["candidate_metadata_schema_version"], "sources": copy.deepcopy(value["sources"])}
    return PreparedSnapshot(
        snapshot_id=str(value["snapshot_id"]),
        main_sha=str(value["main_sha"]),
        profile_sha256=str(value["profile_sha256"]),
        metadata_sha256=str(value["candidate_metadata_sha256"]),
        identity_key_version=str(value["identity_key_version"]),
        identity_epoch=str(value["identity_epoch"]),
        ordered_candidates=tuple(entries),
        metadata=metadata,
        status={
            "snapshot_id": value["snapshot_id"],
            "main_sha": value["main_sha"],
            "profile_sha256": value["profile_sha256"],
            "candidate_metadata_sha256": value["candidate_metadata_sha256"],
            "candidate_metadata_schema_version": manifest["candidate_metadata_schema_version"],
            "candidate_metadata_count": manifest["candidate_metadata_count"],
            "candidate_count": manifest["candidate_count"],
            "identity_key_version": value["identity_key_version"],
            "identity_epoch": value["identity_epoch"],
            "run_at": value["source_run_at"],
        },
    )


def _remote_previous(remote: str, work_dir: Path) -> tuple[PreviousState, dict[str, Any] | None, dict[str, Any] | None]:
    ref = f"refs/heads/{AUTHORITATIVE_BRANCH}"
    completed = subprocess.run(
        ["git", "ls-remote", "--refs", remote, ref],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )
    previous = classify_previous_ref(
        branch=AUTHORITATIVE_BRANCH,
        ls_remote_output=completed.stdout,
        command_returncode=completed.returncode,
    )
    if not previous.exists:
        return previous, None, None
    bundle = read_bundle_from_commit(
        remote=remote,
        commit=str(previous.observed_tip),
        work_dir=work_dir,
    )
    previous = attach_previous_bundle(previous, bundle)
    history = json.loads(bundle.files["history.json"].decode("utf-8"))
    history.pop("bundle_hash", None)
    run_index = json.loads(bundle.files["runs/index.json"].decode("utf-8"))
    return previous, validate_history(history, reserved_names=V2_GROUP_NAMES), run_index


def _source_events(snapshot: PreparedSnapshot, history: Mapping[str, Any]) -> dict[str, str]:
    sources = snapshot.metadata["sources"]
    candidate_sources = {
        entry.candidate_id: list(entry.metadata.get("source_ids", []))
        for entry in snapshot.ordered_candidates
    }
    output: dict[str, str] = {}
    for candidate_id_value, source_ids in candidate_sources.items():
        states = [str(sources[source_id]["health_state"]) for source_id in source_ids]
        if any(state in {"healthy", "recovered"} for state in states):
            output[candidate_id_value] = "present"
        elif any(state == "using_last_good" for state in states):
            output[candidate_id_value] = "last_good"
        else:
            output[candidate_id_value] = "temporary_failure"
    for candidate_id_value in history["nodes"]:
        if candidate_id_value in output:
            continue
        missing = [
            item["missing_candidates"][candidate_id_value]
            for item in sources.values()
            if candidate_id_value in item["missing_candidates"]
        ]
        if missing and all(bool(item["confirmed_missing"]) for item in missing):
            output[candidate_id_value] = "confirmed_missing"
        else:
            output[candidate_id_value] = "temporary_failure"
    return output


def _history_measurements(results: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(item["candidate_id"]): {
            "total_rounds": int(item["attempt_count"]),
            "response_count": int(item["response_count"]),
            "within_limit_count": int(item["within_1000_count"]),
            "slow_response_count": int(item["slow_response_count"]),
            "no_result_count": int(item["no_result_count"]),
            "median_delay_ms": item["median_delay_ms"],
            "p90_delay_ms": item["p90_delay_ms"],
            "jitter_ms": item["jitter_ms"],
        }
        for item in results
    }


def _public_region_label(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CoordinatorError("public runner region is missing")
    label = value.strip()
    if contains_ip_literal(label):
        raise CoordinatorError("public runner region contains an IP address")
    return label


def _finalize(args: argparse.Namespace) -> int:
    manifest = validate_manifest_v3(_load_json(args.manifest))
    snapshot = _load_prepared_snapshot(args.snapshot, manifest)
    fragments = [
        _load_json(Path(args.redacted_root) / "fragments" / f"shard-{index}.json")
        for index in range(SHARD_COUNT)
    ]
    validity = validate_run(manifest, fragments)
    if validity["valid_run"] is not True:
        controls = ",".join(
            "shard{index}={success}/{attempts};streak={streak}".format(
                index=int(fragment["shard_index"]),
                success=int(fragment["control"]["success_count"]),
                attempts=int(fragment["control"]["attempt_count"]),
                streak=int(fragment["control"]["max_consecutive_failures"]),
            )
            for fragment in sorted(fragments, key=lambda item: int(item["shard_index"]))
        )
        raise CoordinatorError(
            "GMGN V2 run is invalid: "
            + ",".join(validity["reasons"])
            + f"; control summaries: {controls}"
        )
    accepted = accepted_measurement(manifest, fragments)
    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    previous, previous_history, previous_run_index = _remote_previous(args.remote, work_dir)
    if previous.bundle is not None and previous.bundle.source_sha256 == manifest["source_sha256"]:
        _write_bytes(Path(args.previous_tip_file), f"{previous.observed_tip}\n".encode("ascii"))
        _write_bytes(Path(args.noop_file), b"accepted\n")
        print("Source SHA is already authoritative; finalize is a no-op.")
        return 0
    history = previous_history or empty_history(
        identity_key_version=manifest["identity_key_version"],
        identity_epoch=manifest["identity_epoch"],
        selection_policy_version=SELECTION_POLICY_VERSION,
    )
    opaque_regions = _load_json(Path(args.redacted_root) / "region-observations.json")
    if (
        set(opaque_regions) != {"kind", "schema_version", "run_id", "observations"}
        or opaque_regions["kind"] != OPAQUE_REGION_KIND
        or opaque_regions["schema_version"] != OPAQUE_REGION_SCHEMA_VERSION
        or opaque_regions["run_id"] != manifest["run_id"]
        or not isinstance(opaque_regions["observations"], Mapping)
    ):
        raise CoordinatorError("opaque region observations are malformed")
    measurements = {item["candidate_id"]: item for item in accepted["results"]}
    candidate_metadata = {
        entry.candidate_id: entry.metadata for entry in snapshot.ordered_candidates
    }
    accepted_at = utc_now()
    region_decisions = resolve_region_decisions(
        candidate_metadata,
        measurements,
        history,
        opaque_regions["observations"],
        now=accepted_at,
    )
    selection_input = build_selection_input(
        snapshot, accepted, history, region_decisions
    )
    selection = select_candidates_v2(selection_input)
    validate_selection_publication(
        selection["summary"],
        published_count_from_bundle(previous.bundle),
    )
    updated_history = reduce_history(
        history,
        run_context={
            "run_id": manifest["run_id"],
            "source_sha256": manifest["source_sha256"],
            "accepted_at": accepted_at,
            "valid_run": True,
            "accepted": True,
            "identity_key_version": manifest["identity_key_version"],
            "identity_epoch": manifest["identity_epoch"],
            "selection_policy_version": SELECTION_POLICY_VERSION,
        },
        source_events=_source_events(snapshot, history),
        measurements=_history_measurements(accepted["results"]),
        decisions=selection["history_decisions"],
    )
    guard_summaries: list[dict[str, Any]] = []
    diagnostic_shards: list[dict[str, Any]] = []
    public_metrics = copy.deepcopy(dict(validity["metrics"]))
    public_metrics["runner_region"] = _public_region_label(
        public_metrics.get("runner_region")
    )
    for index, fragment in enumerate(fragments):
        candidates = _load_shard(
            manifest,
            Path(args.shard_input_root) / f"shard-{index}.json",
            index,
        )
        evidence = _load_json(
            Path(args.private_shard_root) / f"shard-{index}" / "guard-evidence.json"
        )
        resolution = _validate_probe_resolution(
            manifest,
            candidates,
            index,
            _load_json(
                Path(args.private_shard_root)
                / f"shard-{index}"
                / "probe-resolution.json"
            ),
        )
        validate_linux_guard_evidence(
            evidence,
            candidate_ids=resolution["guarded_candidate_ids"],
        )
        guard_summaries.append(
            {
                "shard_index": index,
                "backend": evidence["backend"],
                "backend_version": evidence["backend_version"],
                "policy_version": evidence["policy_version"],
                "resolver_policy_version": evidence["resolver_policy_version"],
                "deny_self_test_passed": bool(evidence["self_test"]["deny_rules"]),
                "controller_isolated": bool(
                    evidence["controller_isolation"]["loopback_only"]
                ),
                "rules_sha256": evidence["rules_sha256"],
                "all_fixed_targets_sha256": evidence.get(
                    "all_fixed_targets_sha256", evidence["fixed_targets_sha256"]
                ),
            }
        )
        diagnostic_shards.append(
            {
                "shard_index": index,
                "candidate_count": int(fragment["candidate_count"]),
                "controller_healthy_check_count": int(
                    fragment["controller"]["healthy_check_count"]
                ),
                "controller_unhealthy_count": int(
                    fragment["controller"]["unhealthy_count"]
                ),
                "egress_country": str(fragment["egress"]["before"]["country"]),
                "egress_region": _public_region_label(
                    fragment["egress"]["before"]["region"]
                ),
                "canary_count": len(fragment["canaries"]),
            }
        )
    diagnostics = {
        "kind": "cnb-gmgn-run-diagnostics",
        "schema_version": 1,
        "bundle_hash": None,
        "run_id": manifest["run_id"],
        "attempt_id": manifest["attempt_id"],
        "retry_of": manifest["retry_of"],
        "accepted_at": accepted_at,
        "source_run_at": manifest["source_run_at"],
        "source_sha256": manifest["source_sha256"],
        "main_sha": manifest["main_sha"],
        "profile_sha256": manifest["profile_sha256"],
        "candidate_metadata_sha256": manifest["candidate_metadata_sha256"],
        "identity_key_version": manifest["identity_key_version"],
        "identity_epoch": manifest["identity_epoch"],
        "selection_policy_version": SELECTION_POLICY_VERSION,
        "region_policy_version": selection["region_policy_version"],
        "validity_policy_version": manifest["validity_policy_version"],
        "total_rounds": TOTAL_ROUNDS,
        "shard_count": SHARD_COUNT,
        "minimum_observation_window_seconds": MINIMUM_OBSERVATION_WINDOW_SECONDS,
        "valid_run": True,
        "validity_reasons": [],
        "metrics": {**public_metrics, "network_guard": guard_summaries},
        "shards": diagnostic_shards,
    }
    bundle = build_publish_bundle(
        selection_result=selection,
        history=updated_history,
        diagnostics=diagnostics,
        runtime={
            "python_version": manifest["python_version"],
            "pyyaml_version": manifest["pyyaml_version"],
            "mihomo_version": manifest["mihomo_version"],
            "mihomo_sha256": manifest["mihomo_sha256"],
        },
        accepted_at=accepted_at,
        source_run_at=manifest["source_run_at"],
        previous_run_index=previous_run_index,
    )
    write_publish_bundle(args.bundle_dir, bundle)
    previous_value = previous.observed_tip if previous.observed_tip is not None else "absent"
    _write_bytes(Path(args.previous_tip_file), f"{previous_value}\n".encode("ascii"))
    print(f"Built GMGN V2 bundle {bundle.bundle_hash} with {selection['summary']['published_count']} nodes.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    trigger = commands.add_parser("trigger")
    trigger.add_argument("--tag", required=True)
    trigger.add_argument("--output", required=True)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--source-sha", required=True)
    preflight.add_argument("--candidate-commit", required=True)
    preflight.add_argument("--remote", required=True)
    preflight.add_argument("--work-dir", required=True)
    preflight.add_argument("--output", required=True)
    preflight.add_argument("--noop-file", default="")
    preflight.add_argument("--retry", action="store_true")
    preflight.add_argument("--retry-token", default="")

    processed = commands.add_parser("processed")
    processed.add_argument("--source-sha", required=True)
    processed.add_argument("--attempt-id", required=True)
    processed.add_argument("--retry-of", default="")
    processed.add_argument("--retry-token-sha256", default="")
    processed.add_argument(
        "--state",
        required=True,
        choices=("running", "failed_infrastructure", "rejected"),
    )
    processed.add_argument("--remote", required=True)
    processed.add_argument("--work-dir", required=True)
    processed.add_argument("--expected-tip", default="")
    processed.add_argument("--allow-missing-primary", action="store_true")

    fetch = commands.add_parser("fetch")
    fetch.add_argument("--profile-url", required=True)
    fetch.add_argument("--status-url", required=True)
    fetch.add_argument("--metadata-url", required=True)
    fetch.add_argument("--expected-source-sha", required=True)
    fetch.add_argument("--expected-candidate-commit", required=True)
    fetch.add_argument("--output-dir", required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--status", required=True)
    prepare.add_argument("--metadata", required=True)
    prepare.add_argument("--expected-source-sha", required=True)
    prepare.add_argument("--expected-candidate-commit", required=True)
    prepare.add_argument("--mihomo", required=True)
    prepare.add_argument("--identity-fixture", required=True)
    prepare.add_argument("--preflight", required=True)
    prepare.add_argument("--trigger", required=True)
    prepare.add_argument("--output-dir", required=True)
    prepare.add_argument("--workers", type=int, default=16)

    probe = commands.add_parser("probe")
    probe.add_argument("--manifest", required=True)
    probe.add_argument("--shard-input", required=True)
    probe.add_argument("--shard-index", type=int, required=True)
    probe.add_argument("--controller-secret", required=True)
    probe.add_argument("--mihomo", required=True)
    probe.add_argument("--output-dir", required=True)

    inside = commands.add_parser("probe-inside")
    inside.add_argument("--context", required=True)

    redact = commands.add_parser("redact")
    redact.add_argument("--manifest", required=True)
    redact.add_argument("--shard-root", required=True)
    redact.add_argument("--identity-fixture", required=True)
    redact.add_argument("--output-dir", required=True)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--manifest", required=True)
    finalize.add_argument("--snapshot", required=True)
    finalize.add_argument("--redacted-root", required=True)
    finalize.add_argument("--private-shard-root", required=True)
    finalize.add_argument("--shard-input-root", required=True)
    finalize.add_argument("--remote", required=True)
    finalize.add_argument("--work-dir", required=True)
    finalize.add_argument("--bundle-dir", required=True)
    finalize.add_argument("--previous-tip-file", required=True)
    finalize.add_argument("--noop-file", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "trigger":
        _write_json(Path(args.output), parse_trigger_tag(args.tag))
        return 0
    if args.command == "preflight":
        return _preflight(args)
    if args.command == "processed":
        return _processed_transition(args)
    if args.command == "fetch":
        return _fetch_candidate(args)
    if args.command == "prepare":
        return _prepare(args)
    if args.command == "probe":
        return _probe(args)
    if args.command == "probe-inside":
        return _probe_inside(args)
    if args.command == "redact":
        return _redact(args)
    return _finalize(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)


__all__ = [
    "CANARY_IDS",
    "CoordinatorError",
    "DIRECT_TARGETS",
    "PreparedSnapshot",
    "PREFLIGHT_KIND",
    "PREFLIGHT_SCHEMA_VERSION",
    "REGION_PROVIDER_TARGET",
    "GMGN_BROWSER_ACCEPT",
    "GMGN_BROWSER_USER_AGENT",
    "HTTP_PROBE_PORT_BASE",
    "HTTP_PROBE_PORT_STRIDE",
    "HTTP_PROBE_PORTS_PER_SHARD",
    "_BrowserProbePool",
    "_HttpProbeSlot",
    "_browser_http_outcome",
    "_http_probe_runtime",
    "_http_probe_slots",
    "_operational_target",
    "_runtime_hosts",
    "build_parser",
    "main",
    "parse_trigger_tag",
]
