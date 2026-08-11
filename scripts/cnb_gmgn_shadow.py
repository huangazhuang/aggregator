#!/usr/bin/env python3
"""Run a redacted, non-publishing GMGN shadow probe on CNB.

The shadow pipeline is intentionally isolated from the production CNB selector.
It measures every source proxy through several independent Mihomo shards, then
publishes only aggregate and anonymous metrics to a dedicated branch.  It never
writes a Clash subscription and therefore cannot replace the last good profile.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import secrets
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from subscribe.asia import is_preferred_asian_proxy
from scripts.cnb_mihomo_filter import (
    api_json,
    discover_runner_network,
    load_source_snapshot,
    percentile,
    unique_proxy_names,
    wait_for_mihomo,
)
from scripts.pipeline_utils import dump_clash_yaml, normalize_reality_short_ids


SHADOW_SCHEMA_VERSION = 2
SELECTION_FRAGMENT_SCHEMA_VERSION = 1
FORMAL_TOTAL_ROUNDS = 20
DEFAULT_THRESHOLDS = (20, 18, 16, 14, 12, 10)
REGION_CLASSIFICATION = "source-label heuristic; egress region not verified"
WITHIN_LIMIT_BLOCK_FIELDS = (
    "within_limit_count_rounds_1_5",
    "within_limit_count_rounds_6_10",
    "within_limit_count_rounds_11_15",
    "within_limit_count_rounds_16_20",
)
SHADOW_RESULT_FIELDS = frozenset(
    {
        "node_id",
        "preferred_asia",
        "attempts",
        "response_count",
        "within_limit_count",
        "first_half_within_limit_count",
        "second_half_within_limit_count",
        *WITHIN_LIMIT_BLOCK_FIELDS,
        "slow_response_count",
        "no_result_count",
        "response_rate",
        "within_limit_rate",
        "min_delay_ms",
        "median_delay_ms",
        "p90_delay_ms",
        "max_delay_ms",
        "jitter_ms",
    }
)
SHADOW_ERROR_CATEGORIES = frozenset(
    {
        "http_429",
        "http_403",
        "http_5xx",
        "timeout",
        "connection",
        "no_delay",
        "controller_4xx",
        "controller_5xx",
        "other",
    }
)
SHADOW_FRAGMENT_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "main_sha",
        "source_sha256",
        "target_url",
        "expected_status",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "shard_count",
        "shard_index",
        "shard_profile_sha256",
        "proxy_count",
        "preferred_asia_count",
        "duration_seconds",
        "round_trends",
        "error_counts",
        "results",
    }
)
SHADOW_MANIFEST_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "prepared_at",
        "main_sha",
        "source_run_at",
        "source_sha256",
        "source_age_seconds",
        "source_count",
        "source_asia_count",
        "rejected_reality_count",
        "target_url",
        "expected_status",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "round_gap_seconds",
        "shard_count",
        "workers_per_shard",
        "estimated_worst_case_seconds",
        "runner",
        "shards",
    }
)
SHADOW_MANIFEST_SHARD_FIELDS = frozenset(
    {
        "shard_index",
        "proxy_count",
        "preferred_asia_count",
        "profile_file",
        "profile_sha256",
    }
)
SHADOW_RUNNER_FIELDS = frozenset(
    {
        "runner_country",
        "runner_region",
        "runner_org",
        "runner_geo_provider",
    }
)
SELECTION_FRAGMENT_FIELDS = frozenset(
    {
        "kind",
        "schema_version",
        "run_id",
        "main_sha",
        "source_sha256",
        "target_url",
        "expected_status",
        "request_timeout_ms",
        "qualified_delay_ms",
        "total_rounds",
        "shard_count",
        "shard_index",
        "shard_profile_sha256",
        "proxy_count",
        "preferred_asia_count",
        "results",
    }
)
SELECTION_RESULT_FIELDS = frozenset({"proxy", "summary"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, payload: Any, *, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    content = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    create_mode = mode if mode is not None else 0o666
    descriptor = os.open(temporary, flags, create_mode)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if mode is not None:
            temporary.chmod(mode)
        temporary.replace(path)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def parse_run_at(value: Any) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise ValueError("source status is missing run_at")
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def validate_source_freshness(source_status: dict[str, Any], maximum_age_seconds: int) -> int:
    generated_at = parse_run_at(source_status.get("run_at"))
    age_seconds = int((datetime.now(timezone.utc) - generated_at).total_seconds())
    if not -300 <= age_seconds <= maximum_age_seconds:
        raise RuntimeError(
            f"source profile age {age_seconds}s is outside the accepted window "
            f"[-300, {maximum_age_seconds}]"
        )
    return age_seconds


def cache_busted_source(source: str, nonce: str) -> str:
    if not source.startswith(("http://", "https://")):
        return source
    separator = "&" if "?" in source else "?"
    return f"{source}{separator}cnb_shadow_snapshot={urllib.parse.quote(nonce, safe='')}"


def load_fresh_source_snapshot(
    profile_source: str,
    status_source: str,
    *,
    maximum_age_seconds: int,
    wait_seconds: int,
    poll_seconds: int,
) -> tuple[dict[str, Any], bytes, dict[str, Any], str, int]:
    """Load one hash-pinned source snapshot, optionally waiting for a refresh."""

    deadline = time.monotonic() + wait_seconds
    last_error: Exception | None = None
    while True:
        nonce = str(time.time_ns())
        try:
            profile, content, source_status, source_sha256 = load_source_snapshot(
                cache_busted_source(profile_source, nonce),
                cache_busted_source(status_source, nonce),
            )
            expected_sha256 = str(source_status.get("profile_sha256") or "").lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
                raise RuntimeError("source status profile_sha256 is missing or malformed")
            if expected_sha256 != source_sha256:
                raise RuntimeError("source profile SHA-256 does not match source status")
            source_age_seconds = validate_source_freshness(
                source_status, maximum_age_seconds
            )
            return profile, content, source_status, source_sha256, source_age_seconds
        except Exception as exc:
            last_error = exc
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError(
                    f"cannot obtain a fresh hash-pinned source snapshot: {last_error}"
                ) from exc
            sleep_seconds = min(float(poll_seconds), remaining)
            print(
                f"Source snapshot is not ready ({exc}); retrying in "
                f"{sleep_seconds:.0f}s.",
                flush=True,
            )
            time.sleep(sleep_seconds)


def proxy_fingerprint(proxy: dict[str, Any]) -> str:
    """Return a stable private fingerprint used only for balanced sharding."""

    payload = copy.deepcopy(proxy)
    payload.pop("name", None)
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def partition_proxies(
    proxies: Iterable[dict[str, Any]], shard_count: int
) -> list[list[dict[str, Any]]]:
    if shard_count < 1:
        raise ValueError("shard_count must be at least 1")
    ranked = sorted(
        (copy.deepcopy(proxy) for proxy in proxies),
        key=lambda proxy: (proxy_fingerprint(proxy), str(proxy.get("name", ""))),
    )
    shards: list[list[dict[str, Any]]] = [[] for _ in range(shard_count)]
    for index, proxy in enumerate(ranked):
        shards[index % shard_count].append(proxy)
    return shards


def classify_error(error: Any, controller_status: int | None = None) -> str:
    text = str(error or "").lower()
    if re.search(r"(?:status(?: code)?|unexpected|target)[^0-9]{0,20}429\b", text):
        return "http_429"
    if re.search(r"(?:status(?: code)?|unexpected|target)[^0-9]{0,20}403\b", text):
        return "http_403"
    if (
        controller_status == 504
        or "timed out" in text
        or "timeout" in text
        or "deadline" in text
    ):
        return "timeout"
    if re.search(r"(?:status(?: code)?|unexpected|target)[^0-9]{0,20}5\d\d\b", text):
        return "http_5xx"
    if "connection refused" in text or "connection reset" in text:
        return "connection"
    if "no positive delay" in text:
        return "no_delay"
    if controller_status is not None and 500 <= controller_status <= 599:
        return "controller_5xx"
    if controller_status is not None and 400 <= controller_status <= 499:
        return "controller_4xx"
    return "other"


def check_shadow_proxy(
    controller: str,
    proxy: dict[str, Any],
    target_url: str,
    expected_status: int,
    timeout_ms: int,
) -> dict[str, Any]:
    """Run a Mihomo delay check while retaining controller error details locally."""

    name = str(proxy.get("name", ""))
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_target = urllib.parse.quote(target_url, safe="")
    url = (
        f"http://{controller}/proxies/{encoded_name}/delay"
        f"?timeout={timeout_ms}&url={encoded_target}&expected={expected_status}"
    )
    request = urllib.request.Request(
        url, headers={"User-Agent": "aggregator-cnb-gmgn-shadow/1.0"}
    )
    controller_status: int | None = None
    error = "no positive delay returned"
    try:
        with urllib.request.urlopen(request, timeout=timeout_ms / 1000 + 1) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
        delay = int(payload.get("delay", 0)) if isinstance(payload, dict) else 0
        if delay > 0:
            return {
                "name": name,
                "ok": True,
                "delay_ms": delay,
                "error": "",
                "controller_status": None,
            }
        if isinstance(payload, dict):
            error = str(payload.get("message") or error)
    except urllib.error.HTTPError as exc:
        controller_status = int(exc.code)
        try:
            body = exc.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            if isinstance(payload, dict):
                error = str(payload.get("message") or body or exc.reason)
            else:
                error = body or str(exc.reason)
        except Exception:
            error = str(exc.reason or exc)
    except Exception as exc:
        error = str(exc)
    return {
        "name": name,
        "ok": False,
        "delay_ms": None,
        "error": error[:300],
        "controller_status": controller_status,
    }


def new_shadow_record(proxy: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(proxy.get("name", "")),
        "preferred_asia": bool(is_preferred_asian_proxy(proxy)),
        "samples_ms": [],
        "error_counts": {},
    }


def record_shadow_result(record: dict[str, Any], result: dict[str, Any]) -> None:
    if result.get("ok"):
        record.setdefault("samples_ms", []).append(int(result["delay_ms"]))
        return
    record.setdefault("samples_ms", []).append(None)
    category = classify_error(result.get("error"), result.get("controller_status"))
    counts = record.setdefault("error_counts", {})
    counts[category] = int(counts.get(category, 0)) + 1


def redacted_runner_network(metadata: dict[str, Any]) -> dict[str, str]:
    """Keep enough runner geography for interpretation without publishing its IP."""

    allowed = (
        "runner_country",
        "runner_region",
        "runner_org",
        "runner_geo_provider",
    )
    return {key: str(metadata.get(key) or "") for key in allowed}


def verify_mihomo_health(
    controller: str, process: subprocess.Popen[Any], *, attempts: int = 4
) -> None:
    """Fail the shard when Mihomo itself died or its controller became unavailable."""

    last_error: Exception | None = None
    for attempt in range(attempts):
        if process.poll() is not None:
            raise RuntimeError(f"Mihomo exited during probing (code {process.returncode})")
        try:
            api_json(f"http://{controller}/version", timeout=1.5)
            return
        except Exception as exc:
            last_error = exc
            if attempt + 1 < attempts:
                time.sleep(0.25)
    raise RuntimeError(f"Mihomo controller became unavailable: {last_error}")


def wait_for_shadow_mihomo(
    controller: str,
    process: subprocess.Popen[Any],
    log_path: Path,
) -> None:
    """Wait for startup without ever copying the private Mihomo log to stdout."""

    try:
        wait_for_mihomo(controller, process, log_path)
    except Exception:
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(
                f"Mihomo exited during private shadow startup (code {exit_code}); "
                "startup log contents were suppressed"
            ) from None
        raise RuntimeError(
            "Mihomo private shadow API did not become ready; "
            "startup log contents were suppressed"
        ) from None


def summarize_shadow_record(
    record: dict[str, Any], qualified_delay_ms: int, *, node_id: str | None = None
) -> dict[str, Any]:
    samples = list(record.get("samples_ms", []))
    delays = [int(value) for value in samples if value is not None]
    within_limit = [value for value in delays if value <= qualified_delay_ms]
    slow = [value for value in delays if value > qualified_delay_ms]
    attempts = len(samples)
    halfway = attempts // 2

    def count_within(values: Iterable[Any]) -> int:
        return sum(
            value is not None and int(value) <= qualified_delay_ms for value in values
        )

    first_half_within_limit_count = count_within(samples[:halfway])
    second_half_within_limit_count = count_within(samples[halfway:])
    block_counts = {
        field: count_within(samples[index * 5 : (index + 1) * 5])
        for index, field in enumerate(WITHIN_LIMIT_BLOCK_FIELDS)
    }
    median_ms = float(statistics.median(delays)) if delays else None
    p90_ms = percentile(delays, 0.90)
    jitter_ms = float(statistics.pstdev(delays)) if len(delays) > 1 else (0.0 if delays else None)
    return {
        "node_id": node_id or f"n1_{secrets.token_hex(12)}",
        "preferred_asia": bool(record.get("preferred_asia")),
        "attempts": attempts,
        "response_count": len(delays),
        "within_limit_count": len(within_limit),
        "first_half_within_limit_count": first_half_within_limit_count,
        "second_half_within_limit_count": second_half_within_limit_count,
        **block_counts,
        "slow_response_count": len(slow),
        "no_result_count": attempts - len(delays),
        "response_rate": round(len(delays) / attempts, 4) if attempts else 0.0,
        "within_limit_rate": round(len(within_limit) / attempts, 4) if attempts else 0.0,
        "min_delay_ms": min(delays) if delays else None,
        "median_delay_ms": round(median_ms, 2) if median_ms is not None else None,
        "p90_delay_ms": round(p90_ms, 2) if p90_ms is not None else None,
        "max_delay_ms": max(delays) if delays else None,
        "jitter_ms": round(jitter_ms, 2) if jitter_ms is not None else None,
    }


def aggregate_error_counts(records: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        for category, value in dict(record.get("error_counts", {})).items():
            counts[str(category)] = counts.get(str(category), 0) + int(value)
    return dict(sorted(counts.items()))


def run_shadow_rounds(
    controller: str,
    proxies: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    *,
    target_url: str,
    expected_status: int,
    request_timeout_ms: int,
    qualified_delay_ms: int,
    workers: int,
    total_rounds: int,
    round_gap: float,
    process: subprocess.Popen[Any],
    shard_index: int,
) -> list[dict[str, int]]:
    trends: list[dict[str, int]] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(proxies))) as executor:
        for round_index in range(total_rounds):
            if process.poll() is not None:
                raise RuntimeError(
                    f"Mihomo shard {shard_index} exited during round {round_index + 1} "
                    f"(code {process.returncode})"
                )
            offset = (round_index * max(1, len(proxies) // max(total_rounds, 1))) % len(proxies)
            round_proxies = proxies[offset:] + proxies[:offset]
            futures = {
                executor.submit(
                    check_shadow_proxy,
                    controller,
                    proxy,
                    target_url,
                    expected_status,
                    request_timeout_ms,
                ): proxy
                for proxy in round_proxies
            }
            within_limit_count = 0
            slow_response_count = 0
            no_result_count = 0
            for future in as_completed(futures):
                proxy = futures[future]
                name = str(proxy.get("name", ""))
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"name": name, "ok": False, "delay_ms": None, "error": str(exc)}
                record_shadow_result(records[name], result)
                if not result.get("ok"):
                    no_result_count += 1
                elif int(result["delay_ms"]) <= qualified_delay_ms:
                    within_limit_count += 1
                else:
                    slow_response_count += 1
            trend = {
                "round": round_index + 1,
                "within_limit_count": within_limit_count,
                "slow_response_count": slow_response_count,
                "no_result_count": no_result_count,
            }
            trends.append(trend)
            verify_mihomo_health(controller, process)
            print(
                f"shadow shard {shard_index} round {round_index + 1}/{total_rounds}: "
                f"<= {qualified_delay_ms}ms {within_limit_count}, slow {slow_response_count}, "
                f"no-result {no_result_count}.",
                flush=True,
            )
            if round_index + 1 < total_rounds and round_gap > 0:
                time.sleep(round_gap)
    return trends


def validate_common_settings(
    *,
    request_timeout_ms: int,
    qualified_delay_ms: int,
    total_rounds: int,
    shard_count: int,
) -> None:
    if request_timeout_ms < 1:
        raise ValueError("request timeout must be positive")
    if not 0 < qualified_delay_ms < request_timeout_ms:
        raise ValueError("qualified delay must be positive and below the request timeout")
    if total_rounds < 1:
        raise ValueError("total rounds must be at least 1")
    if shard_count < 1:
        raise ValueError("shard count must be at least 1")


def validate_prepare_settings(args: argparse.Namespace) -> None:
    validate_common_settings(
        request_timeout_ms=args.request_timeout_ms,
        qualified_delay_ms=args.qualified_delay_ms,
        total_rounds=args.total_rounds,
        shard_count=args.shard_count,
    )
    if args.total_rounds != FORMAL_TOTAL_ROUNDS:
        raise ValueError(
            f"formal GMGN shadow runs require exactly {FORMAL_TOTAL_ROUNDS} rounds"
        )
    if not re.fullmatch(r"[0-9a-f]{40}", str(args.main_sha or ""), flags=re.I):
        raise ValueError("main SHA must be a 40-character hexadecimal commit ID")
    if args.target_url != "https://gmgn.ai/":
        raise ValueError("formal GMGN target must be https://gmgn.ai/")
    if args.expected_status != 200:
        raise ValueError("formal GMGN expected status must be 200")
    if args.request_timeout_ms != 3000 or args.qualified_delay_ms != 1000:
        raise ValueError("formal GMGN delay settings must be 3000ms/1000ms")
    if not 100 <= args.expected_status <= 599:
        raise ValueError("expected HTTP status must be between 100 and 599")
    if args.source_max_age_seconds < 1:
        raise ValueError("source maximum age must be positive")
    if args.source_freshness_wait_seconds < 0:
        raise ValueError("source freshness wait cannot be negative")
    if args.source_freshness_poll_seconds < 1:
        raise ValueError("source freshness poll must be positive")
    if args.round_gap < 0:
        raise ValueError("round gap cannot be negative")
    if args.workers_per_shard < 1:
        raise ValueError("workers per shard must be at least 1")
    if args.max_estimated_probe_seconds < 0:
        raise ValueError("maximum estimated probe time cannot be negative")


def estimate_worst_case_probe_seconds(
    shards: Iterable[list[dict[str, Any]]],
    *,
    workers_per_shard: int,
    request_timeout_ms: int,
    total_rounds: int,
    round_gap: float,
) -> float:
    largest_shard = max((len(shard) for shard in shards), default=0)
    batches_per_round = math.ceil(largest_shard / workers_per_shard)
    client_timeout_seconds = request_timeout_ms / 1000 + 1.0
    return round(
        batches_per_round * client_timeout_seconds * total_rounds
        + max(0, total_rounds - 1) * round_gap
        + 30.0,
        2,
    )


def prepare_shadow(args: argparse.Namespace) -> int:
    validate_prepare_settings(args)
    profile, _content, source_status, source_sha256, source_age_seconds = (
        load_fresh_source_snapshot(
            args.source,
            args.source_status,
            maximum_age_seconds=args.source_max_age_seconds,
            wait_seconds=args.source_freshness_wait_seconds,
            poll_seconds=args.source_freshness_poll_seconds,
        )
    )
    normalized, rejected = normalize_reality_short_ids(profile["proxies"])
    if not normalized:
        raise RuntimeError("source profile contains no proxies after REALITY validation")
    proxies = unique_proxy_names(normalized)
    if len(proxies) < args.shard_count:
        raise RuntimeError("source profile has fewer proxies than requested shards")
    shards = partition_proxies(proxies, args.shard_count)
    estimated_worst_case_seconds = estimate_worst_case_probe_seconds(
        shards,
        workers_per_shard=args.workers_per_shard,
        request_timeout_ms=args.request_timeout_ms,
        total_rounds=args.total_rounds,
        round_gap=args.round_gap,
    )
    if (
        args.max_estimated_probe_seconds
        and estimated_worst_case_seconds > args.max_estimated_probe_seconds
    ):
        raise RuntimeError(
            f"estimated all-timeout probe duration {estimated_worst_case_seconds:.0f}s "
            f"exceeds the configured {args.max_estimated_probe_seconds}s safety budget; "
            "increase parallel capacity or split the source before probing"
        )
    output_dir = Path(args.output_dir).resolve()
    shard_dir = output_dir / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)
    shard_metadata: list[dict[str, Any]] = []
    for index, shard in enumerate(shards):
        shard_path = shard_dir / f"shard-{index}.yaml"
        rendered, invalid = dump_clash_yaml({"proxies": shard})
        if invalid:
            raise RuntimeError(f"shard {index} still contains {len(invalid)} invalid REALITY IDs")
        write_text_atomic(shard_path, rendered)
        shard_metadata.append(
            {
                "shard_index": index,
                "proxy_count": len(shard),
                "preferred_asia_count": sum(is_preferred_asian_proxy(proxy) for proxy in shard),
                "profile_file": str(shard_path.relative_to(output_dir)).replace("\\", "/"),
                "profile_sha256": file_sha256(shard_path),
            }
        )
    manifest = {
        "kind": "cnb-gmgn-shadow-manifest",
        "schema_version": SHADOW_SCHEMA_VERSION,
        "run_id": f"shadow_{secrets.token_hex(16)}",
        "prepared_at": utc_now(),
        "main_sha": str(args.main_sha or ""),
        "source_run_at": str(source_status.get("run_at") or ""),
        "source_sha256": source_sha256,
        "source_age_seconds": source_age_seconds,
        "source_count": len(proxies),
        "source_asia_count": sum(is_preferred_asian_proxy(proxy) for proxy in proxies),
        "rejected_reality_count": len(rejected),
        "target_url": args.target_url,
        "expected_status": args.expected_status,
        "request_timeout_ms": args.request_timeout_ms,
        "qualified_delay_ms": args.qualified_delay_ms,
        "total_rounds": args.total_rounds,
        "round_gap_seconds": args.round_gap,
        "shard_count": args.shard_count,
        "workers_per_shard": args.workers_per_shard,
        "estimated_worst_case_seconds": estimated_worst_case_seconds,
        "runner": redacted_runner_network(discover_runner_network()),
        "shards": shard_metadata,
    }
    validate_shadow_manifest(manifest)
    manifest_path = output_dir / "manifest.json"
    write_json_atomic(manifest_path, manifest)
    print(
        f"Prepared GMGN shadow run {manifest['run_id']}: {len(proxies)} proxies in "
        f"{args.shard_count} shard(s), source age {source_age_seconds}s.",
        flush=True,
    )
    return 0


def load_json_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise RuntimeError(f"cannot load JSON object from {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return payload


def validate_shadow_manifest(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate the complete pinned manifest before any shard file is opened."""

    if manifest.get("kind") != "cnb-gmgn-shadow-manifest":
        raise RuntimeError("unsupported shadow manifest")
    if manifest.get("schema_version") != SHADOW_SCHEMA_VERSION:
        raise RuntimeError("unsupported shadow manifest schema")
    if frozenset(manifest) != SHADOW_MANIFEST_FIELDS:
        raise RuntimeError("shadow manifest fields are incomplete or unexpected")
    if not re.fullmatch(r"shadow_[0-9a-f]{32}", str(manifest.get("run_id", ""))):
        raise RuntimeError("shadow manifest run_id is malformed")
    if not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("main_sha", "")), flags=re.I):
        raise RuntimeError("shadow manifest main_sha is malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", str(manifest.get("source_sha256", ""))):
        raise RuntimeError("shadow manifest source_sha256 is malformed")
    for field in ("prepared_at", "source_run_at"):
        try:
            parse_run_at(manifest.get(field))
        except Exception as exc:
            raise RuntimeError(f"shadow manifest {field} is malformed") from exc
    source_age = manifest.get("source_age_seconds")
    if isinstance(source_age, bool) or not isinstance(source_age, int) or source_age < -300:
        raise RuntimeError("shadow manifest source_age_seconds is invalid")

    request_timeout_ms = non_negative_int(
        manifest.get("request_timeout_ms"), "request_timeout_ms"
    )
    qualified_delay_ms = non_negative_int(
        manifest.get("qualified_delay_ms"), "qualified_delay_ms"
    )
    total_rounds = non_negative_int(manifest.get("total_rounds"), "total_rounds")
    shard_count = non_negative_int(manifest.get("shard_count"), "shard_count")
    validate_common_settings(
        request_timeout_ms=request_timeout_ms,
        qualified_delay_ms=qualified_delay_ms,
        total_rounds=total_rounds,
        shard_count=shard_count,
    )
    if total_rounds != FORMAL_TOTAL_ROUNDS:
        raise RuntimeError(
            f"formal GMGN shadow manifests require exactly {FORMAL_TOTAL_ROUNDS} rounds"
        )
    if str(manifest.get("target_url")) != "https://gmgn.ai/":
        raise RuntimeError("shadow manifest target_url must be https://gmgn.ai/")
    if non_negative_int(manifest.get("expected_status"), "expected_status") != 200:
        raise RuntimeError("shadow manifest expected_status must be 200")
    if request_timeout_ms != 3000 or qualified_delay_ms != 1000:
        raise RuntimeError("shadow manifest delay settings must be 3000ms/1000ms")
    workers = non_negative_int(manifest.get("workers_per_shard"), "workers_per_shard")
    if workers < 1:
        raise RuntimeError("shadow manifest workers_per_shard must be at least 1")
    round_gap = finite_number(manifest.get("round_gap_seconds"), "round_gap_seconds")
    if round_gap < 0:
        raise RuntimeError("shadow manifest round gap cannot be negative")
    estimate = finite_number(
        manifest.get("estimated_worst_case_seconds"),
        "estimated_worst_case_seconds",
    )
    if estimate < 0:
        raise RuntimeError("shadow manifest estimated duration cannot be negative")

    source_count = non_negative_int(manifest.get("source_count"), "source_count")
    source_asia_count = non_negative_int(
        manifest.get("source_asia_count"), "source_asia_count"
    )
    non_negative_int(
        manifest.get("rejected_reality_count"), "rejected_reality_count"
    )
    if source_count < 1 or source_asia_count > source_count:
        raise RuntimeError("shadow manifest source counts are invalid")

    runner = manifest.get("runner")
    if not isinstance(runner, dict) or frozenset(runner) != SHADOW_RUNNER_FIELDS:
        raise RuntimeError("shadow manifest runner metadata is incomplete or unexpected")
    if not all(isinstance(runner[field], str) for field in SHADOW_RUNNER_FIELDS):
        raise RuntimeError("shadow manifest runner metadata must contain strings")

    raw_shards = manifest.get("shards")
    if not isinstance(raw_shards, list) or len(raw_shards) != shard_count:
        raise RuntimeError("shadow manifest shard metadata is incomplete")
    shards: list[dict[str, Any]] = []
    for raw_shard in raw_shards:
        if not isinstance(raw_shard, dict) or frozenset(raw_shard) != SHADOW_MANIFEST_SHARD_FIELDS:
            raise RuntimeError("shadow manifest shard fields are incomplete or unexpected")
        shard = dict(raw_shard)
        index = non_negative_int(shard.get("shard_index"), "shard_index")
        proxy_count = non_negative_int(shard.get("proxy_count"), "proxy_count")
        preferred_asia_count = non_negative_int(
            shard.get("preferred_asia_count"), "preferred_asia_count"
        )
        if proxy_count < 1 or preferred_asia_count > proxy_count:
            raise RuntimeError(f"shadow manifest shard {index} counts are invalid")
        profile_file = str(shard.get("profile_file") or "")
        profile_path = Path(profile_file)
        if (
            not profile_file
            or profile_path.is_absolute()
            or ".." in profile_path.parts
        ):
            raise RuntimeError(f"shadow manifest shard {index} profile path is unsafe")
        if not re.fullmatch(r"[0-9a-f]{64}", str(shard.get("profile_sha256", ""))):
            raise RuntimeError(f"shadow manifest shard {index} profile SHA-256 is malformed")
        shards.append(shard)
    shards.sort(key=lambda item: int(item["shard_index"]))
    if [int(item["shard_index"]) for item in shards] != list(range(shard_count)):
        raise RuntimeError("shadow manifest shard indices are incomplete or duplicated")
    if sum(int(item["proxy_count"]) for item in shards) != source_count:
        raise RuntimeError("shadow manifest shard counts do not match the source count")
    if sum(int(item["preferred_asia_count"]) for item in shards) != source_asia_count:
        raise RuntimeError("shadow manifest shard Asia counts do not match the source count")
    return shards


def manifest_shard(manifest: dict[str, Any], shard_index: int) -> dict[str, Any]:
    for shard in manifest.get("shards", []):
        if int(shard.get("shard_index", -1)) == shard_index:
            return dict(shard)
    raise RuntimeError(f"manifest does not contain shard {shard_index}")


def validate_tcp_port(value: int, label: str) -> None:
    if not 1 <= value <= 65535:
        raise ValueError(f"{label} must be between 1 and 65535")


def validate_private_output_paths(
    redacted_output: Path,
    selection_output: Path,
    private_output_root: Path,
) -> None:
    root_parts = {part.lower() for part in private_output_root.parts}
    if ".cnb-runtime" not in root_parts:
        raise RuntimeError("private output root must contain a .cnb-runtime component")
    if any(part == ".git" or part.startswith("public-cn") for part in root_parts):
        raise RuntimeError("private output root cannot use .git or public-cn* components")

    try:
        selection_relative = selection_output.relative_to(private_output_root)
    except ValueError as exc:
        raise RuntimeError("selection output must be inside the private output root") from exc
    if not selection_relative.parts:
        raise RuntimeError("selection output must be a file inside the private output root")
    try:
        redacted_output.relative_to(private_output_root)
    except ValueError:
        return
    raise RuntimeError("redacted output cannot be inside the private output root")


def probe_shadow_shard(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_json_mapping(manifest_path)
    validate_shadow_manifest(manifest)
    shard = manifest_shard(manifest, args.shard_index)
    shard_profile = (manifest_path.parent / str(shard["profile_file"])).resolve()
    if file_sha256(shard_profile) != str(shard.get("profile_sha256") or ""):
        raise RuntimeError(f"shard {args.shard_index} profile SHA-256 mismatch")
    payload = yaml.safe_load(shard_profile.read_text(encoding="utf-8")) or {}
    proxies = [proxy for proxy in payload.get("proxies", []) if isinstance(proxy, dict)]
    if len(proxies) != int(shard.get("proxy_count", -1)) or not proxies:
        raise RuntimeError(f"shard {args.shard_index} proxy count mismatch")
    names = [str(proxy.get("name", "")) for proxy in proxies]
    if not all(names) or len(names) != len(set(names)):
        raise RuntimeError(f"shard {args.shard_index} contains missing or duplicate names")
    request_timeout_ms = int(manifest["request_timeout_ms"])
    qualified_delay_ms = int(manifest["qualified_delay_ms"])
    total_rounds = int(manifest["total_rounds"])
    validate_common_settings(
        request_timeout_ms=request_timeout_ms,
        qualified_delay_ms=qualified_delay_ms,
        total_rounds=total_rounds,
        shard_count=int(manifest["shard_count"]),
    )
    workers = int(manifest["workers_per_shard"])
    if workers < 1:
        raise RuntimeError("manifest workers_per_shard must be at least 1")
    round_gap = float(manifest["round_gap_seconds"])
    if not math.isfinite(round_gap) or round_gap < 0:
        raise RuntimeError("manifest round gap must be a finite non-negative number")
    validate_tcp_port(args.controller_port, "controller port")
    validate_tcp_port(args.mixed_port, "mixed port")
    if args.controller_port == args.mixed_port:
        raise RuntimeError("controller and mixed ports must differ")
    work_dir = Path(args.work_dir).resolve()
    output_path = Path(args.output).resolve()
    selection_output_value = str(getattr(args, "selection_output", "") or "")
    selection_output_path = (
        Path(selection_output_value).resolve() if selection_output_value else None
    )
    private_output_root_value = str(
        getattr(args, "private_output_root", "") or ""
    )
    if selection_output_path is not None:
        if not private_output_root_value:
            raise RuntimeError("selection output requires --private-output-root")
        validate_private_output_paths(
            output_path,
            selection_output_path,
            Path(private_output_root_value).resolve(),
        )
    work_dir.mkdir(parents=True, exist_ok=True)
    controller = f"127.0.0.1:{args.controller_port}"
    runtime_profile = {
        "mixed-port": args.mixed_port,
        "external-controller": controller,
        "mode": "global",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{"name": "probe", "type": "select", "proxies": names}],
        "rules": ["MATCH,probe"],
    }
    runtime_yaml, invalid = dump_clash_yaml(runtime_profile)
    if invalid:
        raise RuntimeError(f"runtime shard contains {len(invalid)} invalid REALITY IDs")
    runtime_config = work_dir / "mihomo-runtime.yaml"
    runtime_log = work_dir / "mihomo.log"
    write_text_atomic(runtime_config, runtime_yaml)
    records = {name: new_shadow_record(proxy) for name, proxy in zip(names, proxies)}
    started = time.monotonic()
    mihomo = Path(args.mihomo).resolve()
    if not mihomo.is_file():
        raise RuntimeError("Mihomo executable does not exist")
    with runtime_log.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [str(mihomo), "-d", str(work_dir), "-f", str(runtime_config)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_shadow_mihomo(controller, process, runtime_log)
            trends = run_shadow_rounds(
                controller,
                proxies,
                records,
                target_url=str(manifest["target_url"]),
                expected_status=int(manifest["expected_status"]),
                request_timeout_ms=request_timeout_ms,
                qualified_delay_ms=qualified_delay_ms,
                workers=workers,
                total_rounds=total_rounds,
                round_gap=round_gap,
                process=process,
                shard_index=args.shard_index,
            )
            verify_mihomo_health(controller, process)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    incomplete = [name for name, record in records.items() if len(record["samples_ms"]) != total_rounds]
    if incomplete:
        raise RuntimeError(
            f"shard {args.shard_index} has {len(incomplete)} incomplete probe record(s)"
        )
    used_ids: set[str] = set()
    results: list[dict[str, Any]] = []
    summaries_by_name: dict[str, dict[str, Any]] = {}
    for proxy in proxies:
        name = str(proxy["name"])
        record = records[name]
        node_id = f"n1_{secrets.token_hex(12)}"
        while node_id in used_ids:
            node_id = f"n1_{secrets.token_hex(12)}"
        used_ids.add(node_id)
        summary = summarize_shadow_record(
            record, qualified_delay_ms, node_id=node_id
        )
        summaries_by_name[name] = summary
        results.append(summary)
    results.sort(key=lambda item: str(item["node_id"]))
    fragment = {
        "kind": "cnb-gmgn-shadow-fragment",
        "schema_version": SHADOW_SCHEMA_VERSION,
        "run_id": manifest["run_id"],
        "main_sha": manifest["main_sha"],
        "source_sha256": manifest["source_sha256"],
        "target_url": manifest["target_url"],
        "expected_status": manifest["expected_status"],
        "request_timeout_ms": request_timeout_ms,
        "qualified_delay_ms": qualified_delay_ms,
        "total_rounds": total_rounds,
        "shard_count": manifest["shard_count"],
        "shard_index": args.shard_index,
        "shard_profile_sha256": shard["profile_sha256"],
        "proxy_count": len(proxies),
        "preferred_asia_count": sum(bool(item["preferred_asia"]) for item in results),
        "duration_seconds": round(time.monotonic() - started, 2),
        "round_trends": trends,
        "error_counts": aggregate_error_counts(records.values()),
        "results": results,
    }
    validate_fragment(manifest, fragment, shard)
    write_json_atomic(output_path, fragment)
    if selection_output_path is not None:
        selection_fragment = {
            "kind": "cnb-gmgn-selection-fragment",
            "schema_version": SELECTION_FRAGMENT_SCHEMA_VERSION,
            "run_id": manifest["run_id"],
            "main_sha": manifest["main_sha"],
            "source_sha256": manifest["source_sha256"],
            "target_url": manifest["target_url"],
            "expected_status": manifest["expected_status"],
            "request_timeout_ms": request_timeout_ms,
            "qualified_delay_ms": qualified_delay_ms,
            "total_rounds": total_rounds,
            "shard_count": manifest["shard_count"],
            "shard_index": args.shard_index,
            "shard_profile_sha256": shard["profile_sha256"],
            "proxy_count": len(proxies),
            "preferred_asia_count": sum(
                bool(item["preferred_asia"]) for item in results
            ),
            "results": [
                {
                    "proxy": copy.deepcopy(proxy),
                    "summary": copy.deepcopy(summaries_by_name[str(proxy["name"])]),
                }
                for proxy in proxies
            ],
        }
        validate_selection_fragment(manifest, selection_fragment, shard)
        write_json_atomic(selection_output_path, selection_fragment, mode=0o600)
    print(
        f"Completed GMGN shadow shard {args.shard_index}: {len(proxies)} proxies in "
        f"{fragment['duration_seconds']}s.",
        flush=True,
    )
    return 0


def count_histogram(
    results: Iterable[dict[str, Any]], key: str, total_rounds: int
) -> dict[str, int]:
    histogram = {str(index): 0 for index in range(total_rounds + 1)}
    for result in results:
        count = max(0, min(int(result.get(key, 0)), total_rounds))
        histogram[str(count)] += 1
    return histogram


def threshold_counts(
    results: Iterable[dict[str, Any]], thresholds: Iterable[int] = DEFAULT_THRESHOLDS
) -> dict[str, dict[str, int]]:
    materialized = list(results)
    payload: dict[str, dict[str, int]] = {}
    for threshold in thresholds:
        eligible = [item for item in materialized if int(item.get("within_limit_count", 0)) >= threshold]
        asia = sum(bool(item.get("preferred_asia")) for item in eligible)
        payload[str(threshold)] = {
            "total": len(eligible),
            "asia": asia,
            "non_asia": len(eligible) - asia,
        }
    return payload


def merge_round_trends(
    fragments: Iterable[dict[str, Any]], total_rounds: int
) -> list[dict[str, int]]:
    merged = [
        {
            "round": index + 1,
            "within_limit_count": 0,
            "slow_response_count": 0,
            "no_result_count": 0,
        }
        for index in range(total_rounds)
    ]
    for fragment in fragments:
        trends = list(fragment.get("round_trends", []))
        if len(trends) != total_rounds:
            raise RuntimeError(f"shard {fragment.get('shard_index')} has incomplete round trends")
        for index, trend in enumerate(trends):
            if int(trend.get("round", 0)) != index + 1:
                raise RuntimeError(f"shard {fragment.get('shard_index')} has unordered round trends")
            for key in ("within_limit_count", "slow_response_count", "no_result_count"):
                merged[index][key] += int(trend.get(key, 0))
    return merged


def merge_error_counts(fragments: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for fragment in fragments:
        for category, value in dict(fragment.get("error_counts", {})).items():
            counts[str(category)] = counts.get(str(category), 0) + int(value)
    return dict(sorted(counts.items()))


def non_negative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeError(f"{label} must be a non-negative integer")
    return value


def finite_number(value: Any, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{label} must be numeric")
    number = float(value)
    if not math.isfinite(number):
        raise RuntimeError(f"{label} must be finite")
    return number


def validate_shadow_result(
    result: Any,
    *,
    shard_index: int,
    total_rounds: int,
    qualified_delay_ms: int,
) -> None:
    if not isinstance(result, dict):
        raise RuntimeError(f"shard {shard_index} contains a non-object result")
    fields = frozenset(result)
    if fields != SHADOW_RESULT_FIELDS:
        raise RuntimeError(
            f"shard {shard_index} result fields are incomplete or not redacted"
        )
    node_id = str(result.get("node_id", ""))
    if not re.fullmatch(r"n1_[0-9a-f]{24}", node_id):
        raise RuntimeError(f"shard {shard_index} contains a malformed node ID")
    if not isinstance(result.get("preferred_asia"), bool):
        raise RuntimeError(f"shard {shard_index} preferred_asia must be boolean")

    attempts = non_negative_int(result.get("attempts"), "attempts")
    response_count = non_negative_int(result.get("response_count"), "response_count")
    within_limit_count = non_negative_int(
        result.get("within_limit_count"), "within_limit_count"
    )
    first_half_within_limit_count = non_negative_int(
        result.get("first_half_within_limit_count"),
        "first_half_within_limit_count",
    )
    second_half_within_limit_count = non_negative_int(
        result.get("second_half_within_limit_count"),
        "second_half_within_limit_count",
    )
    block_counts = [
        non_negative_int(result.get(field), field)
        for field in WITHIN_LIMIT_BLOCK_FIELDS
    ]
    slow_response_count = non_negative_int(
        result.get("slow_response_count"), "slow_response_count"
    )
    no_result_count = non_negative_int(
        result.get("no_result_count"), "no_result_count"
    )
    if attempts != total_rounds:
        raise RuntimeError(f"shard {shard_index} contains an incomplete node result")
    if response_count + no_result_count != attempts:
        raise RuntimeError(f"shard {shard_index} response counts do not sum to attempts")
    if within_limit_count + slow_response_count != response_count:
        raise RuntimeError(f"shard {shard_index} delay classes do not sum to responses")
    first_half_rounds = total_rounds // 2
    second_half_rounds = total_rounds - first_half_rounds
    if first_half_within_limit_count > first_half_rounds:
        raise RuntimeError(f"shard {shard_index} first-half count exceeds its rounds")
    if second_half_within_limit_count > second_half_rounds:
        raise RuntimeError(f"shard {shard_index} second-half count exceeds its rounds")
    if first_half_within_limit_count + second_half_within_limit_count != within_limit_count:
        raise RuntimeError(f"shard {shard_index} half-window counts are inconsistent")
    for index, count in enumerate(block_counts):
        available_rounds = max(min(total_rounds - index * 5, 5), 0)
        if count > available_rounds:
            raise RuntimeError(f"shard {shard_index} five-round block count is invalid")
    represented_rounds = min(total_rounds, len(WITHIN_LIMIT_BLOCK_FIELDS) * 5)
    if total_rounds <= represented_rounds and sum(block_counts) != within_limit_count:
        raise RuntimeError(f"shard {shard_index} five-round block counts are inconsistent")
    if total_rounds > represented_rounds and sum(block_counts) > within_limit_count:
        raise RuntimeError(f"shard {shard_index} five-round block counts exceed the total")
    if total_rounds == 20 and (
        first_half_within_limit_count != sum(block_counts[:2])
        or second_half_within_limit_count != sum(block_counts[2:])
    ):
        raise RuntimeError(f"shard {shard_index} half and block counts disagree")

    response_rate = finite_number(result.get("response_rate"), "response_rate")
    within_limit_rate = finite_number(
        result.get("within_limit_rate"), "within_limit_rate"
    )
    if not math.isclose(response_rate, round(response_count / attempts, 4), abs_tol=0.0001):
        raise RuntimeError(f"shard {shard_index} response_rate is inconsistent")
    if not math.isclose(
        within_limit_rate,
        round(within_limit_count / attempts, 4),
        abs_tol=0.0001,
    ):
        raise RuntimeError(f"shard {shard_index} within_limit_rate is inconsistent")

    metric_names = (
        "min_delay_ms",
        "median_delay_ms",
        "p90_delay_ms",
        "max_delay_ms",
        "jitter_ms",
    )
    if response_count == 0:
        if any(result.get(name) is not None for name in metric_names):
            raise RuntimeError(f"shard {shard_index} empty responses contain delay metrics")
        return
    if any(result.get(name) is None for name in metric_names):
        raise RuntimeError(f"shard {shard_index} response metrics are incomplete")
    minimum = finite_number(result["min_delay_ms"], "min_delay_ms")
    median = finite_number(result["median_delay_ms"], "median_delay_ms")
    p90 = finite_number(result["p90_delay_ms"], "p90_delay_ms")
    maximum = finite_number(result["max_delay_ms"], "max_delay_ms")
    jitter = finite_number(result["jitter_ms"], "jitter_ms")
    if minimum <= 0 or not minimum <= median <= p90 <= maximum:
        raise RuntimeError(f"shard {shard_index} delay metrics are inconsistent")
    if jitter < 0:
        raise RuntimeError(f"shard {shard_index} jitter cannot be negative")
    if (within_limit_count > 0) != (minimum <= qualified_delay_ms):
        raise RuntimeError(f"shard {shard_index} within-limit boundary is inconsistent")
    if (slow_response_count > 0) != (maximum > qualified_delay_ms):
        raise RuntimeError(f"shard {shard_index} slow-response boundary is inconsistent")


def validate_fragment(
    manifest: dict[str, Any], fragment: dict[str, Any], expected_shard: dict[str, Any]
) -> None:
    shard_index = int(expected_shard["shard_index"])
    if frozenset(fragment) != SHADOW_FRAGMENT_FIELDS:
        raise RuntimeError(f"shard {shard_index} fragment fields are incomplete or unexpected")
    expected = {
        "kind": "cnb-gmgn-shadow-fragment",
        "schema_version": SHADOW_SCHEMA_VERSION,
        "run_id": manifest["run_id"],
        "main_sha": manifest["main_sha"],
        "source_sha256": manifest["source_sha256"],
        "target_url": manifest["target_url"],
        "expected_status": manifest["expected_status"],
        "request_timeout_ms": manifest["request_timeout_ms"],
        "qualified_delay_ms": manifest["qualified_delay_ms"],
        "total_rounds": manifest["total_rounds"],
        "shard_count": manifest["shard_count"],
        "shard_index": expected_shard["shard_index"],
        "shard_profile_sha256": expected_shard["profile_sha256"],
        "proxy_count": expected_shard["proxy_count"],
        "preferred_asia_count": expected_shard["preferred_asia_count"],
    }
    for key, value in expected.items():
        if fragment.get(key) != value:
            raise RuntimeError(
                f"shard {expected_shard['shard_index']} field {key} mismatch: "
                f"expected {value!r}, got {fragment.get(key)!r}"
            )
    duration_seconds = finite_number(fragment.get("duration_seconds"), "duration_seconds")
    if duration_seconds < 0:
        raise RuntimeError(f"shard {shard_index} duration cannot be negative")
    raw_results = fragment.get("results")
    if not isinstance(raw_results, list):
        raise RuntimeError(f"shard {shard_index} results must be a list")
    results = list(raw_results)
    if len(results) != int(expected_shard["proxy_count"]):
        raise RuntimeError(f"shard {shard_index} result count mismatch")
    total_rounds = int(manifest["total_rounds"])
    qualified_delay_ms = int(manifest["qualified_delay_ms"])
    for result in results:
        validate_shadow_result(
            result,
            shard_index=shard_index,
            total_rounds=total_rounds,
            qualified_delay_ms=qualified_delay_ms,
        )
    actual_asia_count = sum(bool(result["preferred_asia"]) for result in results)
    if actual_asia_count != int(expected_shard["preferred_asia_count"]):
        raise RuntimeError(f"shard {shard_index} preferred Asia count mismatch")

    raw_trends = fragment.get("round_trends")
    if not isinstance(raw_trends, list) or len(raw_trends) != total_rounds:
        raise RuntimeError(f"shard {shard_index} has incomplete round trends")
    trend_totals = {
        "within_limit_count": 0,
        "slow_response_count": 0,
        "no_result_count": 0,
    }
    expected_trend_fields = frozenset({"round", *trend_totals})
    for round_index, trend in enumerate(raw_trends, start=1):
        if not isinstance(trend, dict) or frozenset(trend) != expected_trend_fields:
            raise RuntimeError(f"shard {shard_index} has malformed round trends")
        if non_negative_int(trend.get("round"), "round") != round_index:
            raise RuntimeError(f"shard {shard_index} has unordered round trends")
        counts = {
            key: non_negative_int(trend.get(key), key) for key in trend_totals
        }
        if sum(counts.values()) != int(expected_shard["proxy_count"]):
            raise RuntimeError(f"shard {shard_index} round totals do not match proxy count")
        for key, value in counts.items():
            trend_totals[key] += value

    result_totals = {
        key: sum(int(result[key]) for result in results) for key in trend_totals
    }
    if trend_totals != result_totals:
        raise RuntimeError(f"shard {shard_index} round totals do not match node results")

    expected_first_half = sum(
        int(trend["within_limit_count"]) for trend in raw_trends[: total_rounds // 2]
    )
    expected_second_half = sum(
        int(trend["within_limit_count"]) for trend in raw_trends[total_rounds // 2 :]
    )
    actual_first_half = sum(
        int(result["first_half_within_limit_count"]) for result in results
    )
    actual_second_half = sum(
        int(result["second_half_within_limit_count"]) for result in results
    )
    if (actual_first_half, actual_second_half) != (
        expected_first_half,
        expected_second_half,
    ):
        raise RuntimeError(f"shard {shard_index} half-window totals do not match round trends")

    expected_blocks = [
        sum(
            int(trend["within_limit_count"])
            for trend in raw_trends[index * 5 : (index + 1) * 5]
        )
        for index in range(len(WITHIN_LIMIT_BLOCK_FIELDS))
    ]
    actual_blocks = [
        sum(int(result[field]) for result in results)
        for field in WITHIN_LIMIT_BLOCK_FIELDS
    ]
    if actual_blocks != expected_blocks:
        raise RuntimeError(f"shard {shard_index} five-round block totals do not match round trends")

    raw_error_counts = fragment.get("error_counts")
    if not isinstance(raw_error_counts, dict):
        raise RuntimeError(f"shard {shard_index} error_counts must be an object")
    error_total = 0
    for category, value in raw_error_counts.items():
        if category not in SHADOW_ERROR_CATEGORIES:
            raise RuntimeError(f"shard {shard_index} contains an unknown error category")
        error_total += non_negative_int(value, f"error count {category}")
    if error_total != result_totals["no_result_count"]:
        raise RuntimeError(f"shard {shard_index} error counts do not match no-result total")


def validate_selection_fragment(
    manifest: dict[str, Any],
    fragment: dict[str, Any],
    expected_shard: dict[str, Any],
) -> None:
    """Validate private proxy identities without changing the publisher schema."""

    validate_shadow_manifest(manifest)
    shard_index = int(expected_shard["shard_index"])
    if frozenset(fragment) != SELECTION_FRAGMENT_FIELDS:
        raise RuntimeError(
            f"selection shard {shard_index} fields are incomplete or unexpected"
        )
    expected = {
        "kind": "cnb-gmgn-selection-fragment",
        "schema_version": SELECTION_FRAGMENT_SCHEMA_VERSION,
        "run_id": manifest["run_id"],
        "main_sha": manifest["main_sha"],
        "source_sha256": manifest["source_sha256"],
        "target_url": manifest["target_url"],
        "expected_status": manifest["expected_status"],
        "request_timeout_ms": manifest["request_timeout_ms"],
        "qualified_delay_ms": manifest["qualified_delay_ms"],
        "total_rounds": manifest["total_rounds"],
        "shard_count": manifest["shard_count"],
        "shard_index": expected_shard["shard_index"],
        "shard_profile_sha256": expected_shard["profile_sha256"],
        "proxy_count": expected_shard["proxy_count"],
        "preferred_asia_count": expected_shard["preferred_asia_count"],
    }
    for field, value in expected.items():
        if fragment.get(field) != value:
            raise RuntimeError(
                f"selection shard {shard_index} field {field} mismatch: "
                f"expected {value!r}, got {fragment.get(field)!r}"
            )

    raw_results = fragment.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != int(
        expected_shard["proxy_count"]
    ):
        raise RuntimeError(f"selection shard {shard_index} result count mismatch")
    names: set[str] = set()
    node_ids: set[str] = set()
    identities: set[tuple[str, str]] = set()
    preferred_asia_count = 0
    for raw_result in raw_results:
        if not isinstance(raw_result, dict) or frozenset(raw_result) != SELECTION_RESULT_FIELDS:
            raise RuntimeError(
                f"selection shard {shard_index} result fields are incomplete or unexpected"
            )
        proxy = raw_result.get("proxy")
        summary = raw_result.get("summary")
        if not isinstance(proxy, dict):
            raise RuntimeError(f"selection shard {shard_index} proxy must be an object")
        name = str(proxy.get("name") or "").strip()
        if not name or name in names:
            raise RuntimeError(
                f"selection shard {shard_index} contains missing or duplicate proxy names"
            )
        names.add(name)
        validate_shadow_result(
            summary,
            shard_index=shard_index,
            total_rounds=int(manifest["total_rounds"]),
            qualified_delay_ms=int(manifest["qualified_delay_ms"]),
        )
        node_id = str(summary["node_id"])
        if node_id in node_ids:
            raise RuntimeError(f"selection shard {shard_index} contains duplicate node IDs")
        node_ids.add(node_id)
        fingerprint = proxy_fingerprint(proxy)
        identity = (name, fingerprint)
        if identity in identities:
            raise RuntimeError(f"selection shard {shard_index} contains duplicate identities")
        identities.add(identity)
        preferred_asia = bool(is_preferred_asian_proxy(proxy))
        if bool(summary["preferred_asia"]) != preferred_asia:
            raise RuntimeError(
                f"selection shard {shard_index} Asia classification disagrees with its proxy"
            )
        preferred_asia_count += int(preferred_asia)
    if preferred_asia_count != int(expected_shard["preferred_asia_count"]):
        raise RuntimeError(f"selection shard {shard_index} preferred Asia count mismatch")


def build_shadow_readme(status: dict[str, Any], results_url: str) -> str:
    thresholds = status["within_limit_threshold_counts"]
    lines = [
        "# CNB GMGN 影子测速",
        "",
        "该分支只保存脱敏的 GMGN 影子测速数据，不是 Clash 订阅，也不会影响",
        "`clash-cn-output` 中最后一版可用配置。",
        "",
        f"- 测速目标：`{status['target_url']}`",
        f"- HTTP 期望状态：`{status['expected_status']}`",
        f"- 单轮采样超时：{status['request_timeout_ms']} ms",
        f"- Clash 对齐达标线：≤ {status['qualified_delay_ms']} ms",
        f"- 轮数：{status['total_rounds']}",
        f"- 源节点：{status['source_count']}（亚洲 {status['source_asia_count']}）",
        "- 地区口径：按源名称/标记暂分，尚未验证真实出口地区",
        f"- 18/20 达标：{thresholds['18']['total']}（亚洲 {thresholds['18']['asia']}）",
        f"- 14/20 达标：{thresholds['14']['total']}（亚洲 {thresholds['14']['asia']}）",
        f"- 10/20 达标：{thresholds['10']['total']}（亚洲 {thresholds['10']['asia']}）",
        "",
        f"完整脱敏结果：{results_url or 'gmgn-shadow-results.json'}",
        "",
        "逐节点记录不包含名称、服务器、端口、UUID、密码、原始错误或逐轮样本；",
        "匿名 ID 每次运行重新生成，不能跨运行追踪。",
        "",
    ]
    return "\n".join(lines)


def merge_shadow(args: argparse.Namespace) -> int:
    manifest_path = Path(args.manifest).resolve()
    manifest = load_json_mapping(manifest_path)
    expected_shards = validate_shadow_manifest(manifest)
    fragment_paths = [Path(path).resolve() for path in args.fragments]
    if len(fragment_paths) != len(expected_shards):
        raise RuntimeError("the number of fragments does not match the manifest")
    fragments: list[dict[str, Any]] = []
    by_index: dict[int, dict[str, Any]] = {}
    for path in fragment_paths:
        fragment = load_json_mapping(path)
        if fragment.get("kind") != "cnb-gmgn-shadow-fragment":
            raise RuntimeError(f"unsupported shadow fragment: {path}")
        if fragment.get("schema_version") != SHADOW_SCHEMA_VERSION:
            raise RuntimeError(f"unsupported shadow fragment schema: {path}")
        if frozenset(fragment) != SHADOW_FRAGMENT_FIELDS:
            raise RuntimeError(f"shadow fragment fields are incomplete or unexpected: {path}")
        index = non_negative_int(fragment.get("shard_index"), "shard_index")
        if index in by_index:
            raise RuntimeError(f"duplicate fragment for shard {index}")
        by_index[index] = fragment
    for expected_shard in expected_shards:
        index = int(expected_shard["shard_index"])
        if index not in by_index:
            raise RuntimeError(f"missing fragment for shard {index}")
        validate_fragment(manifest, by_index[index], expected_shard)
        fragments.append(by_index[index])
    results = [item for fragment in fragments for item in fragment["results"]]
    if len(results) != int(manifest["source_count"]):
        raise RuntimeError("merged result count does not match the source count")
    node_ids = [str(item.get("node_id", "")) for item in results]
    if not all(re.fullmatch(r"n1_[0-9a-f]{24}", node_id) for node_id in node_ids):
        raise RuntimeError("one or more shadow node IDs are malformed")
    if len(node_ids) != len(set(node_ids)):
        raise RuntimeError("shadow node IDs are not unique")
    total_rounds = int(manifest["total_rounds"])
    asia_results = [item for item in results if bool(item.get("preferred_asia"))]
    non_asia_results = [item for item in results if not bool(item.get("preferred_asia"))]
    threshold_payload = threshold_counts(results)
    status = {
        "kind": "cnb-gmgn-shadow-status",
        "schema_version": SHADOW_SCHEMA_VERSION,
        "run_id": manifest["run_id"],
        "run_at": utc_now(),
        "main_sha": manifest["main_sha"],
        "source_run_at": manifest["source_run_at"],
        "source_sha256": manifest["source_sha256"],
        "target_url": manifest["target_url"],
        "expected_status": manifest["expected_status"],
        "request_timeout_ms": manifest["request_timeout_ms"],
        "qualified_delay_ms": manifest["qualified_delay_ms"],
        "total_rounds": total_rounds,
        "round_gap_seconds": manifest["round_gap_seconds"],
        "shard_count": manifest["shard_count"],
        "workers_per_shard": manifest["workers_per_shard"],
        "estimated_worst_case_seconds": manifest.get("estimated_worst_case_seconds"),
        "source_count": len(results),
        "source_asia_count": len(asia_results),
        "source_non_asia_count": len(non_asia_results),
        "region_classification": REGION_CLASSIFICATION,
        "within_limit_threshold_counts": threshold_payload,
        "asia_within_limit_histogram": count_histogram(
            asia_results, "within_limit_count", total_rounds
        ),
        "non_asia_within_limit_histogram": count_histogram(
            non_asia_results, "within_limit_count", total_rounds
        ),
        "asia_response_histogram": count_histogram(asia_results, "response_count", total_rounds),
        "non_asia_response_histogram": count_histogram(
            non_asia_results, "response_count", total_rounds
        ),
        "round_trends": merge_round_trends(fragments, total_rounds),
        "error_counts": merge_error_counts(fragments),
        "runner": redacted_runner_network(dict(manifest.get("runner", {}))),
        "shards": [
            {
                "shard_index": int(fragment["shard_index"]),
                "proxy_count": int(fragment["proxy_count"]),
                "preferred_asia_count": int(fragment["preferred_asia_count"]),
                "duration_seconds": float(fragment["duration_seconds"]),
            }
            for fragment in fragments
        ],
        "results_file": "gmgn-shadow-results.json",
    }
    results_payload = {
        **status,
        "kind": "cnb-gmgn-shadow-results",
        "redaction": {
            "node_id": "random per-run 96-bit identifier",
            "omitted": [
                "name",
                "server",
                "port",
                "uuid",
                "password",
                "raw_errors",
                "per_round_samples",
            ],
        },
        "results": sorted(results, key=lambda item: str(item["node_id"])),
    }
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json_atomic(output_dir / "status.json", status)
    write_json_atomic(output_dir / "gmgn-shadow-results.json", results_payload)
    write_text_atomic(
        output_dir / "README.md",
        build_shadow_readme(status, args.results_url),
    )
    print(
        f"Merged complete GMGN shadow run: {len(results)} proxies, "
        f"18/20={threshold_payload['18']['total']}, "
        f"14/20={threshold_payload['14']['total']}, "
        f"10/20={threshold_payload['10']['total']}.",
        flush=True,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare", help="pin and partition a source profile")
    prepare.add_argument("--source", required=True)
    prepare.add_argument("--source-status", required=True)
    prepare.add_argument("--source-max-age-seconds", type=int, default=36000)
    prepare.add_argument("--source-freshness-wait-seconds", type=int, default=0)
    prepare.add_argument("--source-freshness-poll-seconds", type=int, default=60)
    prepare.add_argument("--main-sha", default="")
    prepare.add_argument("--output-dir", required=True)
    prepare.add_argument("--target-url", default="https://gmgn.ai/")
    prepare.add_argument("--expected-status", type=int, default=200)
    prepare.add_argument("--request-timeout-ms", type=int, default=3000)
    prepare.add_argument("--qualified-delay-ms", type=int, default=1000)
    prepare.add_argument("--total-rounds", type=int, default=20)
    prepare.add_argument("--round-gap", type=float, default=0.75)
    prepare.add_argument("--shard-count", type=int, default=4)
    prepare.add_argument("--workers-per-shard", type=int, default=16)
    prepare.add_argument("--max-estimated-probe-seconds", type=int, default=0)
    prepare.set_defaults(handler=prepare_shadow)

    probe = subparsers.add_parser("probe", help="run one prepared Mihomo shard")
    probe.add_argument("--manifest", required=True)
    probe.add_argument("--shard-index", type=int, required=True)
    probe.add_argument("--mihomo", required=True)
    probe.add_argument("--work-dir", required=True)
    probe.add_argument("--output", required=True)
    probe.add_argument("--selection-output", default="")
    probe.add_argument("--private-output-root", default="")
    probe.add_argument("--controller-port", type=int, required=True)
    probe.add_argument("--mixed-port", type=int, required=True)
    probe.set_defaults(handler=probe_shadow_shard)

    merge = subparsers.add_parser("merge", help="validate and merge all shadow fragments")
    merge.add_argument("--manifest", required=True)
    merge.add_argument("--fragments", nargs="+", required=True)
    merge.add_argument("--output-dir", required=True)
    merge.add_argument("--results-url", default="")
    merge.set_defaults(handler=merge_shadow)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
