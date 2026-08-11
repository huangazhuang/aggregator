#!/usr/bin/env python3
"""Validate local or remote GMGN V2 public outputs with no-cache fetches."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping, Sequence

from scripts.candidate_snapshot import (
    CANDIDATE_METADATA_KIND,
    CANDIDATE_METADATA_SCHEMA_VERSION,
    CANDIDATE_STATUS_KIND,
    CANDIDATE_STATUS_SCHEMA_VERSION,
    validate_candidate_snapshot,
)
from scripts.publish_transaction import (
    BUNDLE_KIND,
    BUNDLE_SCHEMA_VERSION,
    PublishBundle,
    PublicationError,
    load_publish_bundle,
    validate_publish_bundle,
)


SMOKE_EVIDENCE_KIND = "cnb-gmgn-v2-smoke-evidence"
SMOKE_EVIDENCE_SCHEMA_VERSION = 1
SMOKE_SCOPES = frozenset({"staging", "current"})
CANDIDATE_SMOKE_EVIDENCE_KIND = "github-candidate-remote-smoke"
CANDIDATE_SMOKE_EVIDENCE_SCHEMA_VERSION = 1
SMOKE_EVIDENCE_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "scope",
        "revision",
        "expected_commit",
        "bundle_hash",
        "source_sha256",
        "run_id",
        "output_profile_sha256",
    }
)
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
SAFE_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
MIHOMO_ENV_PASSTHROUGH = frozenset(
    {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "LANG", "LC_ALL", "TZ"}
)


class RemoteNotFoundError(PublicationError):
    """A requested authoritative object is explicitly absent (HTTP 404)."""


class RemoteReadError(PublicationError):
    """A remote object could not be read reliably."""


class MihomoValidationError(PublicationError):
    """The fixed Mihomo binary or generated profile failed validation."""


def minimal_mihomo_env(work_dir: str | Path) -> dict[str, str]:
    """Return the small, secret-free environment allowed for Mihomo children."""

    allowed = {key.casefold() for key in MIHOMO_ENV_PASSTHROUGH}
    env = {
        key: value
        for key, value in os.environ.items()
        if key.casefold() in allowed
    }
    private_root = str(Path(work_dir).resolve())
    env.update(
        {
            "HOME": private_root,
            "TEMP": private_root,
            "TMP": private_root,
            "TMPDIR": private_root,
        }
    )
    if os.name == "nt":
        env["USERPROFILE"] = private_root
    return env


def _git_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not GIT_SHA_RE.fullmatch(value):
        raise PublicationError(f"{label} must be a canonical Git object ID")
    return value


def _revision(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not SAFE_REVISION_RE.fullmatch(value)
        or value.startswith("/")
        or value.endswith("/")
        or ".." in value.split("/")
    ):
        raise PublicationError("expected revision is unsafe")
    return value


def _bind_base_url_revision(base_url: str, expected_revision: str) -> str:
    revision = _revision(expected_revision)
    parsed = urllib.parse.urlsplit(base_url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise PublicationError("remote bundle base URL must be an authenticated-free HTTPS URL")
    segments = [urllib.parse.unquote(item) for item in parsed.path.split("/") if item]
    if revision not in segments:
        raise PublicationError("remote bundle base URL is not bound to the expected revision")
    return revision


def _cache_busted_url(url: str, nonce: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.append(("gmgn_v2_nonce", nonce))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )


def fetch_no_cache(
    url: str,
    *,
    nonce: str,
    opener: Callable[..., Any] = urllib.request.urlopen,
    timeout: int = 30,
) -> bytes:
    request = urllib.request.Request(
        _cache_busted_url(url, nonce),
        headers={
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "User-Agent": "aggregator-gmgn-v2-validator/1.0",
        },
    )
    try:
        with opener(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise RemoteNotFoundError("remote public object is explicitly absent") from exc
        raise RemoteReadError(f"remote public object returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RemoteReadError("remote public object is temporarily unreadable") from exc


def _write_evidence(root: Path, relative: str, content: bytes) -> None:
    target = root / PurePosixPath(relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.replace(target)


def _parse_bundle_manifest(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except Exception as exc:
        raise PublicationError("remote bundle.json is invalid") from exc
    if not isinstance(value, Mapping):
        raise PublicationError("remote bundle.json must be an object")
    if value.get("kind") != BUNDLE_KIND or value.get("schema_version") != BUNDLE_SCHEMA_VERSION:
        raise PublicationError("remote bundle kind or schema is unsupported")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise PublicationError("remote bundle file list is empty")
    return dict(value)


def validate_mihomo_profile(
    bundle: PublishBundle,
    *,
    mihomo: str | Path,
    evidence_dir: str | Path,
    runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> None:
    binary = Path(mihomo).resolve()
    if not binary.is_file():
        raise MihomoValidationError("fixed Mihomo binary is unavailable")
    status = json.loads(bundle.files["status.json"].decode("utf-8"))
    expected_hash = str(status["runtime"]["mihomo_sha256"])
    actual_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    if actual_hash != expected_hash:
        raise MihomoValidationError("fixed Mihomo binary hash mismatch")
    root = Path(evidence_dir).resolve()
    check_dir = root / "mihomo-check"
    check_dir.mkdir(parents=True, exist_ok=True)
    profile = check_dir / "clash.yaml"
    profile.write_bytes(bundle.files["clash.yaml"])
    completed = runner(
        [str(binary), "-t", "-d", str(check_dir), "-f", str(profile)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        env=minimal_mihomo_env(check_dir),
    )
    if completed.returncode != 0:
        raise MihomoValidationError("fixed Mihomo rejected the published profile")


def validate_remote_bundle(
    *,
    base_url: str,
    expected_commit: str,
    expected_revision: str,
    scope: str,
    expected_bundle_hash: str,
    expected_source_sha: str,
    evidence_dir: str | Path,
    mihomo: str | Path,
    opener: Callable[..., Any] = urllib.request.urlopen,
    mihomo_runner: Callable[..., subprocess.CompletedProcess[Any]] = subprocess.run,
) -> PublishBundle:
    """Download one exact public tree with a shared nonce and validate it."""

    commit = _git_sha(expected_commit, "expected commit")
    revision = _bind_base_url_revision(base_url, expected_revision)
    if scope not in SMOKE_SCOPES:
        raise PublicationError("remote smoke scope is unsupported")
    if scope == "staging" and revision != commit:
        raise PublicationError("staging smoke must use the exact candidate commit revision")
    evidence = Path(evidence_dir).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_hex(16)
    root = base_url.rstrip("/")
    bundle_content = fetch_no_cache(
        f"{root}/bundle.json", nonce=nonce, opener=opener
    )
    manifest = _parse_bundle_manifest(bundle_content)
    files: dict[str, bytes] = {"bundle.json": bundle_content}
    for raw_entry in manifest["files"]:
        if not isinstance(raw_entry, Mapping) or not isinstance(raw_entry.get("path"), str):
            raise PublicationError("remote bundle file entry is malformed")
        path = PurePosixPath(raw_entry["path"])
        if path.is_absolute() or ".." in path.parts or "." in path.parts:
            raise PublicationError("remote bundle file path is unsafe")
        relative = path.as_posix()
        files[relative] = fetch_no_cache(
            f"{root}/{relative}", nonce=nonce, opener=opener
        )
    bundle = validate_publish_bundle(files)
    if bundle.bundle_hash != expected_bundle_hash:
        raise PublicationError("remote bundle hash differs from the promoted bundle")
    if bundle.source_sha256 != expected_source_sha:
        raise PublicationError("remote bundle source SHA differs from the trigger")
    for path, content in bundle.files.items():
        _write_evidence(evidence / "bundle", path, content)
    status = json.loads(bundle.files["status.json"].decode("utf-8"))
    smoke_evidence = {
        "kind": SMOKE_EVIDENCE_KIND,
        "schema_version": SMOKE_EVIDENCE_SCHEMA_VERSION,
        "scope": scope,
        "revision": revision,
        "expected_commit": commit,
        "bundle_hash": bundle.bundle_hash,
        "source_sha256": bundle.source_sha256,
        "run_id": bundle.run_id,
        "output_profile_sha256": status["output_profile_sha256"],
    }
    _write_evidence(
        evidence,
        "smoke-evidence.json",
        (
            json.dumps(
                smoke_evidence,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8"),
    )
    (evidence / "request-nonce.txt").write_text(f"{nonce}\n", encoding="utf-8")
    validate_mihomo_profile(
        bundle, mihomo=mihomo, evidence_dir=evidence, runner=mihomo_runner
    )
    return bundle


def validate_remote_candidate_snapshot(
    *,
    profile_url: str,
    status_url: str,
    metadata_url: str,
    evidence_dir: str | Path,
    expected_profile_sha: str = "",
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> Any:
    evidence = Path(evidence_dir).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    nonce = secrets.token_hex(16)
    status_bytes = fetch_no_cache(status_url, nonce=nonce, opener=opener)
    profile_bytes = fetch_no_cache(profile_url, nonce=nonce, opener=opener)
    metadata_bytes = fetch_no_cache(metadata_url, nonce=nonce, opener=opener)
    try:
        status = json.loads(status_bytes.decode("utf-8"))
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise PublicationError("candidate snapshot sidecars are invalid JSON") from exc
    snapshot = validate_candidate_snapshot(profile_bytes, status, metadata)
    if expected_profile_sha and snapshot.profile_sha256 != expected_profile_sha:
        raise PublicationError("candidate snapshot SHA differs from the trigger")
    _write_evidence(evidence, "clash.yaml", profile_bytes)
    _write_evidence(evidence, "status.json", status_bytes)
    _write_evidence(evidence, "candidate-metadata.json", metadata_bytes)
    (evidence / "request-nonce.txt").write_text(f"{nonce}\n", encoding="utf-8")
    return snapshot


def _candidate_publication_contract(
    *,
    profile_bytes: bytes,
    status_bytes: bytes,
    metadata_bytes: bytes,
    expected_main_sha: str,
) -> dict[str, Any]:
    try:
        status = json.loads(status_bytes.decode("utf-8"))
        metadata = json.loads(metadata_bytes.decode("utf-8"))
    except Exception as exc:
        raise PublicationError("candidate publication sidecars are invalid JSON") from exc
    if not isinstance(status, Mapping) or not isinstance(metadata, Mapping):
        raise PublicationError("candidate publication sidecars must be objects")
    if (
        status.get("kind") != CANDIDATE_STATUS_KIND
        or status.get("schema_version") != CANDIDATE_STATUS_SCHEMA_VERSION
        or metadata.get("kind") != CANDIDATE_METADATA_KIND
        or metadata.get("schema_version") != CANDIDATE_METADATA_SCHEMA_VERSION
    ):
        raise PublicationError("candidate publication schema is unsupported")
    main_sha = _git_sha(expected_main_sha, "candidate main SHA")
    if status.get("main_sha") != main_sha:
        raise PublicationError("candidate publication main SHA mismatch")
    profile_sha = hashlib.sha256(profile_bytes).hexdigest()
    metadata_sha = hashlib.sha256(metadata_bytes).hexdigest()
    if status.get("profile_sha256") != profile_sha or metadata.get("profile_sha256") != profile_sha:
        raise PublicationError("candidate publication profile hash mismatch")
    if status.get("candidate_metadata_sha256") != metadata_sha:
        raise PublicationError("candidate publication metadata hash mismatch")
    counts = (
        status.get("candidate_count"),
        status.get("candidate_metadata_count"),
        metadata.get("candidate_count"),
    )
    if (
        any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in counts)
        or len(set(counts)) != 1
    ):
        raise PublicationError("candidate publication counts are inconsistent")
    return {
        "main_sha": main_sha,
        "profile_sha256": profile_sha,
        "candidate_metadata_sha256": metadata_sha,
        "candidate_count": counts[0],
        "snapshot_id": str(status.get("snapshot_id") or ""),
    }


def validate_remote_candidate_publication(
    *,
    profile: str | Path,
    status: str | Path,
    metadata: str | Path,
    profile_url: str,
    status_url: str,
    metadata_url: str,
    expected_revision: str,
    expected_main_sha: str,
    scope: str,
    evidence_dir: str | Path,
    attempts: int = 5,
    retry_delay_seconds: float = 3.0,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    if scope not in SMOKE_SCOPES:
        raise PublicationError("candidate remote smoke scope is unsupported")
    revision = _revision(expected_revision)
    for url in (profile_url, status_url, metadata_url):
        _bind_base_url_revision(url, revision)
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
        raise PublicationError("candidate remote smoke attempts are invalid")
    if retry_delay_seconds < 0:
        raise PublicationError("candidate remote smoke retry delay is invalid")

    local = {
        "clash.yaml": Path(profile).read_bytes(),
        "status.json": Path(status).read_bytes(),
        "candidate-metadata.json": Path(metadata).read_bytes(),
    }
    contract = _candidate_publication_contract(
        profile_bytes=local["clash.yaml"],
        status_bytes=local["status.json"],
        metadata_bytes=local["candidate-metadata.json"],
        expected_main_sha=expected_main_sha,
    )
    urls = {
        "clash.yaml": profile_url,
        "status.json": status_url,
        "candidate-metadata.json": metadata_url,
    }
    last_error: Exception | None = None
    remote: dict[str, bytes] | None = None
    nonce = ""
    for attempt in range(attempts):
        nonce = secrets.token_hex(16)
        try:
            fetched = {
                name: fetch_no_cache(url, nonce=nonce, opener=opener)
                for name, url in urls.items()
            }
            mismatched = [name for name in local if fetched[name] != local[name]]
            if mismatched:
                last_error = PublicationError(
                    f"remote candidate {mismatched[0]} differs from validated staging"
                )
                if attempt + 1 < attempts:
                    sleeper(float(retry_delay_seconds))
                    continue
                break
            remote = fetched
            break
        except (RemoteNotFoundError, RemoteReadError) as exc:
            last_error = exc
            if attempt + 1 < attempts:
                sleeper(float(retry_delay_seconds))
    if remote is None:
        assert last_error is not None
        raise last_error
    remote_contract = _candidate_publication_contract(
        profile_bytes=remote["clash.yaml"],
        status_bytes=remote["status.json"],
        metadata_bytes=remote["candidate-metadata.json"],
        expected_main_sha=expected_main_sha,
    )
    if remote_contract != contract:
        raise PublicationError("remote candidate publication contract changed")
    evidence = Path(evidence_dir).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": CANDIDATE_SMOKE_EVIDENCE_KIND,
        "schema_version": CANDIDATE_SMOKE_EVIDENCE_SCHEMA_VERSION,
        "scope": scope,
        "revision": revision,
        **contract,
    }
    _write_evidence(
        evidence,
        "candidate-smoke-evidence.json",
        (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )
    _write_evidence(evidence, "request-nonce.txt", f"{nonce}\n".encode("utf-8"))
    return payload


def validate_series(
    bundles: Sequence[PublishBundle],
    *,
    required_valid_runs: int = 3,
    require_distinct_source_sha: bool = True,
    min_spacing_seconds: int = 21_600,
    require_same_policy_version: bool = True,
    require_same_identity: bool = True,
    require_history_canary: bool = True,
) -> dict[str, Any]:
    if required_valid_runs < 1 or required_valid_runs > 5 or len(bundles) < required_valid_runs:
        raise PublicationError("not enough accepted bundles for the rollout series")
    ordered = sorted(
        bundles,
        key=lambda bundle: datetime.fromisoformat(
            bundle.accepted_at.replace("Z", "+00:00")
        ),
    )
    selected = list(ordered)[-required_valid_runs:]
    statuses = [
        json.loads(bundle.files["status.json"].decode("utf-8"))
        for bundle in selected
    ]
    histories = [
        json.loads(bundle.files["history.json"].decode("utf-8"))
        for bundle in selected
    ]
    run_indexes = [
        json.loads(bundle.files["runs/index.json"].decode("utf-8"))
        for bundle in selected
    ]
    if require_distinct_source_sha and len({bundle.source_sha256 for bundle in selected}) != len(
        selected
    ):
        raise PublicationError("rollout series contains duplicate source SHAs")
    times = [
        datetime.fromisoformat(str(status["accepted_at"]).replace("Z", "+00:00"))
        for status in statuses
    ]
    if any((later - earlier).total_seconds() < min_spacing_seconds for earlier, later in zip(times, times[1:])):
        raise PublicationError("rollout series accepted runs are too close together")
    source_times = [
        datetime.fromisoformat(str(status["source_run_at"]).replace("Z", "+00:00"))
        for status in statuses
    ]
    if any(later <= earlier for earlier, later in zip(source_times, source_times[1:])):
        raise PublicationError("rollout series source snapshots are not strictly newer")
    if require_same_policy_version:
        version_sets = {
            (
                status["publish_policy_version"],
                status["selection_policy_version"],
                status["region_policy_version"],
                status["validity_policy_version"],
                status["runtime"]["mihomo_sha256"],
                status["runtime"]["python_version"],
                status["runtime"]["pyyaml_version"],
            )
            for status in statuses
        }
        if len(version_sets) != 1:
            raise PublicationError("rollout series changed policy or runtime versions")
    if require_same_identity:
        identity_versions = {
            (status["identity_key_version"], status["identity_epoch"])
            for status in statuses
        }
        if len(identity_versions) != 1:
            raise PublicationError("rollout series changed identity key or epoch")
    for index in range(1, len(selected)):
        later_index = {
            (entry["run_id"], entry["source_sha256"]): entry
            for entry in run_indexes[index]["entries"]
        }
        later_history = {
            (entry["run_id"], entry["source_sha256"])
            for entry in histories[index]["recent_accepted_runs"]
        }
        for earlier_bundle in selected[:index]:
            identity = (earlier_bundle.run_id, earlier_bundle.source_sha256)
            if identity not in later_index:
                raise PublicationError("later run index does not contain an earlier accepted run")
            earlier_status = json.loads(
                earlier_bundle.files["status.json"].decode("utf-8")
            )
            indexed = later_index[identity]
            if (
                indexed["attempt_id"] != earlier_status["attempt_id"]
                or indexed["retry_of"] != earlier_status["retry_of"]
            ):
                raise PublicationError("later run index changed an accepted retry relation")
            if identity not in later_history:
                raise PublicationError("later history does not contain an earlier accepted run")
    if require_history_canary:
        common_ids: set[str] | None = None
        for history in histories:
            identifiers = set(history.get("nodes", {}))
            common_ids = identifiers if common_ids is None else common_ids & identifiers
        if not common_ids:
            raise PublicationError("rollout series has no stable history canary")
        for candidate_id in common_ids:
            names = {history["nodes"][candidate_id]["output_name"] for history in histories}
            if len(names) != 1:
                raise PublicationError("rollout series changed a stable candidate output name")
    return {
        "valid_runs": len(selected),
        "source_sha256": [bundle.source_sha256 for bundle in selected],
        "bundle_hash": [bundle.bundle_hash for bundle in selected],
        "first_accepted_at": statuses[0]["accepted_at"],
        "last_accepted_at": statuses[-1]["accepted_at"],
        "identity_key_version": statuses[0]["identity_key_version"],
        "identity_epoch": statuses[0]["identity_epoch"],
    }


def validate_migration(
    *,
    shadow: PublishBundle,
    formal: PublishBundle,
    expected_bundle_hash: str,
    legacy_status: Mapping[str, Any] | None = None,
    expect_legacy_frozen: bool = False,
) -> None:
    if shadow.bundle_hash != expected_bundle_hash or formal.bundle_hash != expected_bundle_hash:
        raise PublicationError("migration bundle hash differs from the accepted shadow")
    if shadow.files != formal.files:
        raise PublicationError("formal GMGN tree is not byte-identical to the accepted shadow")
    if expect_legacy_frozen:
        if not isinstance(legacy_status, Mapping) or legacy_status.get("frozen") is not True:
            raise PublicationError("legacy gstatic output is not explicitly frozen")


def _load_bundle_argument(directory: str, base_url: str, args: argparse.Namespace, label: str) -> PublishBundle:
    if bool(directory) == bool(base_url):
        raise PublicationError(f"provide exactly one {label} local directory or base URL")
    if directory:
        bundle = load_publish_bundle(directory)
        if args.mihomo:
            validate_mihomo_profile(
                bundle,
                mihomo=args.mihomo,
                evidence_dir=Path(args.evidence_dir) / label,
            )
        return bundle
    if not args.mihomo:
        raise PublicationError("remote bundle validation requires --mihomo")
    return validate_remote_bundle(
        base_url=base_url,
        expected_commit=args.expected_commit,
        expected_revision=args.expected_revision,
        scope=args.scope,
        expected_bundle_hash=args.expected_bundle_hash,
        expected_source_sha=args.expected_source_sha,
        evidence_dir=Path(args.evidence_dir) / label,
        mihomo=args.mihomo,
    )


def _run_command(args: argparse.Namespace) -> int:
    bundle = _load_bundle_argument(args.bundle_dir, args.bundle_base_url, args, "run")
    if args.expected_bundle_hash and bundle.bundle_hash != args.expected_bundle_hash:
        raise PublicationError("bundle hash differs from --expected-bundle-hash")
    if args.expected_source_sha and bundle.source_sha256 != args.expected_source_sha:
        raise PublicationError("source SHA differs from --expected-source-sha")
    candidate_values = [
        args.candidate_profile,
        args.candidate_status,
        args.candidate_metadata,
    ]
    if any(candidate_values):
        if not all(candidate_values):
            raise PublicationError("candidate remote validation requires all three URLs")
        validate_remote_candidate_snapshot(
            profile_url=args.candidate_profile,
            status_url=args.candidate_status,
            metadata_url=args.candidate_metadata,
            evidence_dir=Path(args.evidence_dir) / "candidate",
            expected_profile_sha=args.expected_source_sha,
        )
    print(bundle.bundle_hash)
    return 0


def _candidate_command(args: argparse.Namespace) -> int:
    result = validate_remote_candidate_publication(
        profile=args.profile,
        status=args.status,
        metadata=args.metadata,
        profile_url=args.profile_url,
        status_url=args.status_url,
        metadata_url=args.metadata_url,
        expected_revision=args.expected_revision,
        expected_main_sha=args.expected_main_sha,
        scope=args.scope,
        evidence_dir=args.evidence_dir,
        attempts=args.attempts,
        retry_delay_seconds=args.retry_delay_seconds,
    )
    print(result["profile_sha256"])
    return 0


def _current_smoke_bundles(evidence_root: str | Path) -> list[PublishBundle]:
    root = Path(evidence_root).resolve()
    if not root.is_dir():
        raise PublicationError("series evidence root does not exist")
    bundles: list[PublishBundle] = []
    for evidence_path in sorted(root.rglob("smoke-evidence.json")):
        try:
            raw = json.loads(evidence_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise PublicationError("smoke evidence is invalid JSON") from exc
        if not isinstance(raw, Mapping) or frozenset(raw) != SMOKE_EVIDENCE_FIELDS:
            raise PublicationError("smoke evidence fields are incomplete or unexpected")
        if (
            raw["kind"] != SMOKE_EVIDENCE_KIND
            or raw["schema_version"] != SMOKE_EVIDENCE_SCHEMA_VERSION
        ):
            raise PublicationError("smoke evidence kind or schema is unsupported")
        if raw["scope"] != "current":
            continue
        _git_sha(raw["expected_commit"], "smoke evidence expected commit")
        _revision(raw["revision"])
        bundle = load_publish_bundle(evidence_path.parent / "bundle")
        status = json.loads(bundle.files["status.json"].decode("utf-8"))
        bindings = {
            "bundle_hash": bundle.bundle_hash,
            "source_sha256": bundle.source_sha256,
            "run_id": bundle.run_id,
            "output_profile_sha256": status["output_profile_sha256"],
        }
        for field, expected in bindings.items():
            if raw[field] != expected:
                raise PublicationError(f"smoke evidence {field} disagrees with bundle")
        bundles.append(bundle)
    if not bundles:
        raise PublicationError("series evidence contains no authoritative current smoke")
    return bundles


def _series_command(args: argparse.Namespace) -> int:
    directories = list(args.bundle_dir or [])
    bundles = [load_publish_bundle(path) for path in directories]
    if args.evidence_root:
        bundles.extend(_current_smoke_bundles(args.evidence_root))
    unique_bundles = {bundle.bundle_hash: bundle for bundle in bundles}
    result = validate_series(
        list(unique_bundles.values()),
        required_valid_runs=args.required_valid_runs,
        require_distinct_source_sha=True,
        min_spacing_seconds=args.min_spacing_seconds,
        require_same_policy_version=True,
        require_same_identity=True,
        require_history_canary=True,
    )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


def _migration_command(args: argparse.Namespace) -> int:
    if not args.mihomo:
        raise PublicationError("migration validation requires the fixed --mihomo binary")

    def load_endpoint(label: str) -> PublishBundle:
        directory = getattr(args, f"{label}_bundle_dir")
        base_url = getattr(args, f"{label}_bundle_base_url")
        if bool(directory) == bool(base_url):
            raise PublicationError(
                f"provide exactly one {label} local directory or base URL"
            )
        if directory:
            bundle = load_publish_bundle(directory)
            validate_mihomo_profile(
                bundle,
                mihomo=args.mihomo,
                evidence_dir=Path(args.evidence_dir) / label,
            )
            return bundle
        if not args.expected_source_sha:
            raise PublicationError("remote migration validation requires --expected-source-sha")
        return validate_remote_bundle(
            base_url=base_url,
            expected_commit=getattr(args, f"{label}_expected_commit"),
            expected_revision=getattr(args, f"{label}_expected_revision"),
            scope="current",
            expected_bundle_hash=args.expected_bundle_hash,
            expected_source_sha=args.expected_source_sha,
            evidence_dir=Path(args.evidence_dir) / label,
            mihomo=args.mihomo,
        )

    shadow = load_endpoint("shadow")
    formal = load_endpoint("formal")
    legacy_status = None
    if args.legacy_status and args.legacy_status_url:
        raise PublicationError("provide only one legacy status file or URL")
    if args.legacy_status:
        legacy_status = json.loads(Path(args.legacy_status).read_text(encoding="utf-8"))
    elif args.legacy_status_url:
        nonce = secrets.token_hex(16)
        content = fetch_no_cache(args.legacy_status_url, nonce=nonce)
        try:
            legacy_status = json.loads(content.decode("utf-8"))
        except Exception as exc:
            raise PublicationError("remote legacy status is invalid JSON") from exc
        _write_evidence(Path(args.evidence_dir), "legacy-status.json", content)
        _write_evidence(
            Path(args.evidence_dir), "legacy-request-nonce.txt", f"{nonce}\n".encode()
        )
    validate_migration(
        shadow=shadow,
        formal=formal,
        expected_bundle_hash=args.expected_bundle_hash,
        legacy_status=legacy_status,
        expect_legacy_frozen=args.expect_legacy_frozen,
    )
    print(args.expected_bundle_hash)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    run = commands.add_parser("run", help="validate one candidate/bundle publication")
    run.add_argument("--bundle-dir", default="")
    run.add_argument("--bundle-base-url", default="")
    run.add_argument("--candidate-profile", default="")
    run.add_argument("--candidate-status", default="")
    run.add_argument("--candidate-metadata", default="")
    run.add_argument("--expected-source-sha", default="")
    run.add_argument("--expected-bundle-hash", default="")
    run.add_argument("--expected-commit", default="")
    run.add_argument("--expected-revision", default="")
    run.add_argument("--scope", choices=sorted(SMOKE_SCOPES), default="current")
    run.add_argument("--mihomo", default="")
    run.add_argument("--evidence-dir", required=True)

    candidate = commands.add_parser(
        "candidate", help="validate one exact GitHub candidate publication"
    )
    candidate.add_argument("--profile", required=True)
    candidate.add_argument("--status", required=True)
    candidate.add_argument("--metadata", required=True)
    candidate.add_argument("--profile-url", required=True)
    candidate.add_argument("--status-url", required=True)
    candidate.add_argument("--metadata-url", required=True)
    candidate.add_argument("--expected-revision", required=True)
    candidate.add_argument("--expected-main-sha", required=True)
    candidate.add_argument("--scope", choices=sorted(SMOKE_SCOPES), required=True)
    candidate.add_argument("--evidence-dir", required=True)
    candidate.add_argument("--attempts", type=int, default=5)
    candidate.add_argument("--retry-delay-seconds", type=float, default=3.0)

    series = commands.add_parser("series", help="validate a rollout acceptance series")
    series.add_argument("--bundle-dir", action="append", default=[])
    series.add_argument("--evidence-root", default="")
    series.add_argument("--required-valid-runs", type=int, default=3)
    series.add_argument("--min-spacing-seconds", type=int, default=21_600)

    migration = commands.add_parser("migration", help="validate an exact formal promotion")
    migration.add_argument("--shadow-bundle-dir", default="")
    migration.add_argument("--shadow-bundle-base-url", default="")
    migration.add_argument("--shadow-expected-commit", default="")
    migration.add_argument("--shadow-expected-revision", default="")
    migration.add_argument("--formal-bundle-dir", default="")
    migration.add_argument("--formal-bundle-base-url", default="")
    migration.add_argument("--formal-expected-commit", default="")
    migration.add_argument("--formal-expected-revision", default="")
    migration.add_argument("--legacy-status", default="")
    migration.add_argument("--legacy-status-url", default="")
    migration.add_argument("--expected-bundle-hash", required=True)
    migration.add_argument("--expected-source-sha", default="")
    migration.add_argument("--mihomo", default="")
    migration.add_argument("--evidence-dir", required=True)
    migration.add_argument("--expect-legacy-frozen", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        return _run_command(args)
    if args.command == "candidate":
        return _candidate_command(args)
    if args.command == "series":
        return _series_command(args)
    return _migration_command(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)


__all__ = [
    "MihomoValidationError",
    "RemoteNotFoundError",
    "RemoteReadError",
    "build_parser",
    "fetch_no_cache",
    "minimal_mihomo_env",
    "validate_migration",
    "validate_mihomo_profile",
    "validate_remote_candidate_publication",
    "validate_remote_bundle",
    "validate_remote_candidate_snapshot",
    "validate_series",
]
