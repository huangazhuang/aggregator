#!/usr/bin/env python3
"""Read-only evaluator for controlled external Asia candidate sources."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

from scripts.asia_source_registry import (
    AsiaSourceError,
    evaluate_source_gain,
    fetch_source_revision,
    source_spec,
)
from scripts.candidate_snapshot import (
    CandidateSnapshotError,
    validate_legacy_candidate_baseline,
)
from scripts.proxy_identity import IdentitySettings, validate_public_id


AUDIT_ROOT = Path(r"D:\xiangmu\linshi\asia-source-expansion-v2")
ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "raw.githubusercontent.com",
        "api.github.com",
        "github.com",
        "cnb.cool",
    }
)
MAX_DOWNLOAD_BYTES = 32 * 1024 * 1024
EVALUATION_KEY_ENV = "ASIA_SOURCE_EVAL_HMAC_KEY"
EVALUATION_KEY_VERSION_ENV = "ASIA_SOURCE_EVAL_KEY_VERSION"
EVALUATION_EPOCH_ENV = "ASIA_SOURCE_EVAL_EPOCH"


class EvaluationError(ValueError):
    """Raised when a read-only source audit cannot be completed safely."""


class DownloadNotFound(EvaluationError):
    """Raised only for an explicit HTTP 404 on an optional legacy sidecar."""


def evaluation_identity_settings(environment: Mapping[str, str] | None = None) -> IdentitySettings:
    """Use an audit-only key, never the production GMGN identity secret."""

    env = os.environ if environment is None else environment
    key = str(env.get(EVALUATION_KEY_ENV, ""))
    key_version = str(env.get(EVALUATION_KEY_VERSION_ENV, ""))
    epoch = str(env.get(EVALUATION_EPOCH_ENV, ""))
    if not key or not key_version or not epoch:
        raise EvaluationError(
            f"{EVALUATION_KEY_ENV}, {EVALUATION_KEY_VERSION_ENV}, and {EVALUATION_EPOCH_ENV} are required"
        )
    return IdentitySettings(
        key=key.encode("utf-8"),
        identity_key_version=key_version,
        identity_epoch=epoch,
    )


def _audit_output_dir(value: str | Path) -> Path:
    root = AUDIT_ROOT.resolve()
    output = Path(value).resolve()
    if output != root and root not in output.parents:
        raise EvaluationError(f"output directory must remain under {root}")
    output.mkdir(parents=True, exist_ok=True)
    return output


def _safe_https_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(str(value or "").strip())
    except ValueError as exc:
        raise EvaluationError("download URL is malformed") from exc
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in ALLOWED_DOWNLOAD_HOSTS:
        raise EvaluationError("download URL must use an approved HTTPS host")
    if parsed.username or parsed.password or parsed.fragment:
        raise EvaluationError("download URL contains unsupported credentials or fragment")
    return urllib.parse.urlunsplit(parsed)


def download_bytes(
    url: str,
    *,
    token: str = "",
    timeout: float = 45.0,
    maximum_bytes: int = MAX_DOWNLOAD_BYTES,
) -> bytes:
    safe_url = _safe_https_url(url)
    headers = {"User-Agent": "aggregator-source-audit", "Accept": "application/octet-stream"}
    if token and urllib.parse.urlsplit(safe_url).hostname in {"api.github.com", "github.com"}:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(safe_url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            final_url = _safe_https_url(response.geturl())
            if not final_url:
                raise EvaluationError("download redirect is invalid")
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > maximum_bytes:
                raise EvaluationError("download exceeds the audit size limit")
            payload = response.read(maximum_bytes + 1)
    except EvaluationError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise DownloadNotFound("download was not found") from exc
        raise EvaluationError("download failed") from exc
    except (OSError, urllib.error.URLError, ValueError) as exc:
        raise EvaluationError("download failed") from exc
    if len(payload) > maximum_bytes:
        raise EvaluationError("download exceeds the audit size limit")
    return payload


def _write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_bytes(payload)
    temporary.replace(path)


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _profile(payload: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = yaml.safe_load(payload)
    except Exception as exc:
        raise EvaluationError(f"{label} profile is invalid YAML") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("proxies"), list):
        raise EvaluationError(f"{label} profile has no proxy list")
    return parsed


def _json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(payload)
    except Exception as exc:
        raise EvaluationError(f"{label} is invalid JSON") from exc
    if not isinstance(parsed, dict):
        raise EvaluationError(f"{label} must be a JSON object")
    return parsed


def _validate_current_hash(profile_bytes: bytes, status: Mapping[str, Any]) -> None:
    expected = str(status.get("profile_sha256", "")).strip().lower()
    actual = hashlib.sha256(profile_bytes).hexdigest()
    if len(expected) != 64 or expected != actual:
        raise EvaluationError("current profile hash does not match status.json")


def _validate_current_metadata_binding(
    profile: Mapping[str, Any],
    profile_bytes: bytes,
    status: Mapping[str, Any],
    metadata: Mapping[str, Any],
    metadata_bytes: bytes,
) -> None:
    """Validate public V2 cross-file bindings without loading the production HMAC key."""

    expected_metadata_sha = str(status.get("candidate_metadata_sha256", "")).strip().lower()
    if expected_metadata_sha != hashlib.sha256(metadata_bytes).hexdigest():
        raise EvaluationError("current candidate metadata hash does not match status.json")
    candidates = metadata.get("candidates")
    if not isinstance(candidates, Mapping):
        raise EvaluationError("current candidate metadata has no candidate mapping")
    profile_count = len(profile.get("proxies", []))
    counts = (
        status.get("candidate_count"),
        status.get("candidate_metadata_count"),
        metadata.get("candidate_count"),
        len(candidates),
        profile_count,
    )
    if any(isinstance(value, bool) or not isinstance(value, int) for value in counts) or len(set(counts)) != 1:
        raise EvaluationError("current candidate counts are inconsistent")
    if metadata.get("profile_sha256") != hashlib.sha256(profile_bytes).hexdigest():
        raise EvaluationError("current metadata is bound to another profile")
    for field in ("snapshot_id", "identity_key_version", "identity_epoch"):
        if not status.get(field) or status.get(field) != metadata.get(field):
            raise EvaluationError(f"current candidate {field} is inconsistent")
    if status.get("candidate_metadata_schema_version") != metadata.get("schema_version"):
        raise EvaluationError("current candidate metadata schema is inconsistent")
    for candidate_id, item in candidates.items():
        if not isinstance(item, Mapping):
            raise EvaluationError("current candidate metadata entry is malformed")
        try:
            validate_public_id(candidate_id, "candidate")
            validate_public_id(item.get("endpoint_id"), "endpoint")
            validate_public_id(item.get("server_id"), "server")
        except ValueError as exc:
            raise EvaluationError("current candidate public identity is malformed") from exc


def build_report(
    *,
    source_key: str,
    source_profile_bytes: bytes,
    current_profile_bytes: bytes,
    current_status_bytes: bytes,
    current_metadata_bytes: bytes | None,
    source_revision: Mapping[str, str],
    evaluated_at: str | None,
    settings: IdentitySettings,
    allow_legacy_current: bool,
) -> dict[str, Any]:
    source_profile = _profile(source_profile_bytes, "source")
    current_profile = _profile(current_profile_bytes, "current")
    current_status = _json_object(current_status_bytes, "current status")
    _validate_current_hash(current_profile_bytes, current_status)
    current_metadata: dict[str, Any] | None = None
    current_proxies = current_profile["proxies"]
    if current_metadata_bytes is not None:
        current_metadata = _json_object(current_metadata_bytes, "current candidate metadata")
        _validate_current_metadata_binding(
            current_profile,
            current_profile_bytes,
            current_status,
            current_metadata,
            current_metadata_bytes,
        )
    else:
        if not allow_legacy_current:
            raise EvaluationError("current candidate metadata is required")
        try:
            validate_legacy_candidate_baseline(current_profile_bytes, current_status)
        except CandidateSnapshotError as exc:
            raise EvaluationError(
                "current snapshot is neither complete candidate V2 nor valid legacy V1"
            ) from exc

    report = evaluate_source_gain(
        source_key,
        source_profile["proxies"],
        current_proxies,
        source_updated_at=source_revision["updated_at"],
        evaluated_at=evaluated_at,
        settings=settings,
    )
    report["source"]["commit_sha"] = source_revision["commit_sha"]
    report["current_snapshot"] = {
        "contract": "candidate-v2" if current_metadata is not None else "legacy-profile-status",
        "profile_sha256": hashlib.sha256(current_profile_bytes).hexdigest(),
        "status_schema_version": current_status.get("schema_version"),
        "metadata_sha256": (
            hashlib.sha256(current_metadata_bytes).hexdigest()
            if current_metadata_bytes is not None
            else ""
        ),
        "identity_key_version": str(current_status.get("identity_key_version", "")),
        "identity_epoch": str(current_status.get("identity_epoch", "")),
    }
    if current_metadata is None:
        report["gate"]["warnings"] = [
            "current snapshot predates candidate-metadata.json; overlap used the exact current profile"
        ]
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, choices=sorted(("awesome-vpn", "mahdibland-asia-limited")))
    parser.add_argument("--current-status-url", required=True)
    parser.add_argument("--current-profile-url", required=True)
    parser.add_argument("--current-metadata-url", default="")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--evaluated-at", default="")
    parser.add_argument(
        "--allow-legacy-current",
        action="store_true",
        help="allow the pre-V2 GitHub profile/status pair while C1 is not published yet",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = _audit_output_dir(args.output_dir)
    spec = source_spec(args.source)
    token = os.environ.get("GH_TOKEN", "")
    settings = evaluation_identity_settings()
    revision = fetch_source_revision(spec, token=token)

    source_bytes = download_bytes(spec.artifact_url, token=token)
    current_profile_bytes = download_bytes(args.current_profile_url, token=token)
    current_status_bytes = download_bytes(args.current_status_url, token=token)
    metadata_bytes: bytes | None = None
    if args.current_metadata_url:
        try:
            metadata_bytes = download_bytes(args.current_metadata_url, token=token)
        except DownloadNotFound:
            if not args.allow_legacy_current:
                raise

    _write_bytes(output / "source-profile.yaml", source_bytes)
    _write_bytes(output / "current-profile.yaml", current_profile_bytes)
    _write_bytes(output / "current-status.json", current_status_bytes)
    if metadata_bytes is not None:
        _write_bytes(output / "current-candidate-metadata.json", metadata_bytes)
    _write_json(output / "source-revision.json", revision)

    report = build_report(
        source_key=args.source,
        source_profile_bytes=source_bytes,
        current_profile_bytes=current_profile_bytes,
        current_status_bytes=current_status_bytes,
        current_metadata_bytes=metadata_bytes,
        source_revision=revision,
        evaluated_at=args.evaluated_at or None,
        settings=settings,
        allow_legacy_current=args.allow_legacy_current,
    )
    _write_json(output / "report.json", report)
    counts = report["counts"]
    print(
        json.dumps(
            {
                "source": args.source,
                "raw": counts["raw_count"],
                "exact_unique": counts["exact_unique_count"],
                "new_endpoints": counts["new_unique_endpoint_count"],
                "new_regions": counts["new_regions"],
                "passed": report["gate"]["passed"],
                "reasons": report["gate"]["reasons"],
                "report": str(output / "report.json"),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AsiaSourceError, EvaluationError) as exc:
        raise SystemExit(f"ERROR: {exc}") from exc
