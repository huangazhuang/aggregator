#!/usr/bin/env python3
"""Filter a Clash profile with protocol-level checks through a local Mihomo."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import math
import os
import socket
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from subscribe.asia import is_preferred_asian_proxy
from scripts.pipeline_utils import (
    calculate_publish_floor,
    dump_clash_yaml,
    filtered_profile,
    normalize_reality_short_ids,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Use Mihomo to keep the fastest proxies that work from this machine."
    )
    parser.add_argument("--source", required=True, help="Clash YAML file path or HTTP(S) URL")
    parser.add_argument("--mihomo", required=True, help="Path to the Mihomo executable")
    parser.add_argument("--work-dir", required=True, help="Directory for Mihomo runtime files")
    parser.add_argument("--output-dir", required=True, help="Directory for generated public files")
    parser.add_argument("--source-status", default="", help="Source status.json path or URL")
    parser.add_argument("--previous-status", default="", help="Previously published status.json path or URL")
    parser.add_argument("--main-sha", default="", help="GitHub/CNB main branch commit SHA")
    parser.add_argument(
        "--target-url", default="https://www.gstatic.com/generate_204", help="URL requested through each proxy"
    )
    parser.add_argument("--expected-status", type=int, default=204)
    parser.add_argument("--timeout-ms", type=int, default=3000)
    parser.add_argument("--preliminary-rounds", type=int, default=3)
    parser.add_argument("--total-rounds", type=int, default=20)
    parser.add_argument("--round-gap", type=float, default=0.75)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--candidate-limit", type=int, default=360)
    parser.add_argument("--asia-candidate-target", type=int, default=300)
    parser.add_argument("--non-asia-candidate-target", type=int, default=60)
    parser.add_argument("--base-target", type=int, default=80)
    parser.add_argument("--max-nodes", type=int, default=150)
    parser.add_argument("--non-asia-min", type=int, default=10)
    parser.add_argument("--non-asia-max", type=int, default=20)
    parser.add_argument("--min-success-rate", type=float, default=0.70)
    parser.add_argument("--base-preferred-success-rate", type=float, default=0.80)
    parser.add_argument("--elite-min-success-rate", type=float, default=0.90)
    parser.add_argument("--max-qualified-p90-ms", type=float, default=2800.0)
    parser.add_argument("--elite-max-p90-ms", type=float, default=2000.0)
    parser.add_argument("--min-success", type=int, default=80)
    parser.add_argument("--min-retain-ratio", type=float, default=0.50)
    return parser.parse_args()


def read_source(source: str) -> bytes:
    if source.startswith(("http://", "https://")):
        request = urllib.request.Request(source, headers={"User-Agent": "aggregator-cnb-probe/1.0"})
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    return response.read()
            except Exception as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(2**attempt)
        raise RuntimeError(f"cannot download source profile: {last_error}")
    return Path(source).read_bytes()


def load_profile(source: str) -> tuple[dict[str, Any], bytes]:
    try:
        content = read_source(source)
        profile = yaml.safe_load(content) or {}
    except Exception as exc:
        raise RuntimeError(f"cannot load Clash YAML: {exc}") from exc
    if not isinstance(profile, dict):
        raise RuntimeError("source profile must be a YAML mapping")
    proxies = profile.get("proxies")
    if not isinstance(proxies, list) or not proxies:
        raise RuntimeError("source profile contains no proxies")
    profile["proxies"] = [proxy for proxy in proxies if isinstance(proxy, dict)]
    if not profile["proxies"]:
        raise RuntimeError("source profile contains no valid proxy mappings")
    return profile, content


def load_optional_json(source: str) -> dict[str, Any]:
    if not source:
        return {}
    try:
        payload = json.loads(read_source(source).decode("utf-8", errors="replace"))
        return payload if isinstance(payload, dict) else {}
    except Exception as exc:
        print(f"WARNING: cannot load optional metadata from {source}: {exc}", flush=True)
        return {}


def load_source_snapshot(
    profile_source: str, status_source: str
) -> tuple[dict[str, Any], bytes, dict[str, Any], str]:
    """Load profile/status from one output-branch revision when a hash is available."""

    for attempt in range(3):
        source_status = load_optional_json(status_source)
        profile, content = load_profile(profile_source)
        digest = hashlib.sha256(content).hexdigest()
        expected = str(source_status.get("profile_sha256") or "").lower()
        if not expected or expected == digest:
            return profile, content, source_status, digest
        if attempt < 2:
            print("WARNING: source profile changed while metadata was being read; retrying.", flush=True)
            time.sleep(1)
    raise RuntimeError("source profile SHA-256 does not match source status after three attempts")


def _valid_public_ip(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value).strip())
        return str(address) if address.is_global else ""
    except ValueError:
        return ""


def discover_runner_network() -> dict[str, str]:
    """Best-effort public egress and region lookup; metadata failure is non-fatal."""

    providers = (
        (
            "ipapi.co",
            "https://ipapi.co/json/",
            lambda data: {
                "runner_public_ip": _valid_public_ip(data.get("ip")),
                "runner_country": str(data.get("country_name") or data.get("country") or ""),
                "runner_region": str(data.get("region") or ""),
                "runner_city": str(data.get("city") or ""),
                "runner_org": str(data.get("org") or ""),
            },
        ),
        (
            "ipwho.is",
            "https://ipwho.is/",
            lambda data: {
                "runner_public_ip": _valid_public_ip(data.get("ip")),
                "runner_country": str(data.get("country") or ""),
                "runner_region": str(data.get("region") or ""),
                "runner_city": str(data.get("city") or ""),
                "runner_org": str((data.get("connection") or {}).get("org") or ""),
            },
        ),
    )

    for provider, url, parser in providers:
        try:
            data = api_json(url, timeout=8)
            metadata = parser(data)
            if metadata.get("runner_public_ip"):
                metadata["runner_geo_provider"] = provider
                return metadata
        except Exception as exc:
            print(f"WARNING: runner metadata lookup via {provider} failed: {exc}", flush=True)

    return {
        "runner_public_ip": "",
        "runner_country": "",
        "runner_region": "",
        "runner_city": "",
        "runner_org": "",
        "runner_geo_provider": "",
    }


def unique_proxy_names(proxies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    used: set[str] = set()
    counters: dict[str, int] = {}
    for original in proxies:
        proxy = copy.deepcopy(original)
        base = str(proxy.get("name", "")).strip() or "unnamed"
        name = base
        while name in used:
            counters[base] = counters.get(base, 1) + 1
            name = f"{base}-{counters[base]}"
        proxy["name"] = name
        used.add(name)
        result.append(proxy)
    return result


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def api_json(url: str, timeout: float) -> dict[str, Any]:
    request = urllib.request.Request(url, headers={"User-Agent": "aggregator-cnb-probe/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8", errors="replace"))
    return payload if isinstance(payload, dict) else {}


def wait_for_mihomo(controller: str, process: subprocess.Popen[Any], log_path: Path) -> None:
    deadline = time.monotonic() + 25
    url = f"http://{controller}/version"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            details = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise RuntimeError(f"Mihomo exited during startup (code {process.returncode}):\n{details}")
        try:
            api_json(url, timeout=1)
            return
        except Exception:
            time.sleep(0.25)
    raise RuntimeError("Mihomo API did not become ready within 25 seconds")


def check_proxy(
    controller: str,
    proxy: dict[str, Any],
    target_url: str,
    expected_status: int,
    timeout_ms: int,
) -> dict[str, Any]:
    """Run one protocol-level request through a proxy."""

    name = str(proxy.get("name", ""))
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_target = urllib.parse.quote(target_url, safe="")
    url = (
        f"http://{controller}/proxies/{encoded_name}/delay"
        f"?timeout={timeout_ms}&url={encoded_target}&expected={expected_status}"
    )
    error = "no positive delay returned"
    try:
        payload = api_json(url, timeout=timeout_ms / 1000 + 1)
        delay = int(payload.get("delay", 0))
        if delay > 0:
            return {"name": name, "ok": True, "delay_ms": delay, "error": ""}
        error = str(payload.get("message") or error)
    except Exception as exc:
        error = str(exc)
    return {
        "name": name,
        "ok": False,
        "delay_ms": None,
        "error": error[:300],
    }


def new_probe_record(proxy: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(proxy.get("name", "")),
        "type": str(proxy.get("type", "")),
        "server": str(proxy.get("server", "")),
        "port": proxy.get("port"),
        "preferred_asia": is_preferred_asian_proxy(proxy),
        "attempts": 0,
        "success_count": 0,
        "samples_ms": [],
        "last_error": "",
    }


def record_probe_result(record: dict[str, Any], result: dict[str, Any]) -> None:
    record["attempts"] = int(record.get("attempts", 0)) + 1
    if result.get("ok"):
        record["success_count"] = int(record.get("success_count", 0)) + 1
        record.setdefault("samples_ms", []).append(int(result["delay_ms"]))
    else:
        record.setdefault("samples_ms", []).append(None)
        record["last_error"] = str(result.get("error") or "")[:300]


def run_probe_rounds(
    controller: str,
    proxies: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    target_url: str,
    expected_status: int,
    timeout_ms: int,
    workers: int,
    rounds: int,
    round_gap: float,
    stage: str,
    process: subprocess.Popen[Any] | None = None,
) -> None:
    """Probe every supplied proxy once per round and accumulate samples."""

    if not proxies or rounds <= 0:
        return
    with ThreadPoolExecutor(max_workers=min(workers, len(proxies))) as executor:
        for round_index in range(rounds):
            if process is not None and process.poll() is not None:
                raise RuntimeError(f"Mihomo exited during {stage} (code {process.returncode})")
            offset = (round_index * max(1, len(proxies) // max(rounds, 1))) % len(proxies)
            round_proxies = proxies[offset:] + proxies[:offset]
            futures = {
                executor.submit(
                    check_proxy,
                    controller,
                    proxy,
                    target_url,
                    expected_status,
                    timeout_ms,
                ): proxy
                for proxy in round_proxies
            }
            passed = 0
            for future in as_completed(futures):
                proxy = futures[future]
                name = str(proxy.get("name", ""))
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"name": name, "ok": False, "delay_ms": None, "error": str(exc)}
                record_probe_result(records[name], result)
                passed += int(bool(result.get("ok")))
            print(
                f"{stage} round {round_index + 1}/{rounds}: "
                f"{passed}/{len(round_proxies)} proxies passed.",
                flush=True,
            )
            if round_index + 1 < rounds and round_gap > 0:
                time.sleep(round_gap)


def percentile(values: list[int], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(math.ceil(min(max(quantile, 0.0), 1.0) * len(ordered)) - 1, 0)
    return float(ordered[index])


def summarize_probe_record(record: dict[str, Any]) -> dict[str, Any]:
    samples = list(record.get("samples_ms", []))
    delays = [int(value) for value in samples if value is not None]
    attempts = max(int(record.get("attempts", 0)), 0)
    successes = max(int(record.get("success_count", 0)), 0)
    median_ms = float(statistics.median(delays)) if delays else None
    p90_ms = percentile(delays, 0.90)
    jitter_ms = float(statistics.pstdev(delays)) if len(delays) > 1 else (0.0 if delays else None)
    return {
        "name": str(record.get("name", "")),
        "type": str(record.get("type", "")),
        "server": str(record.get("server", "")),
        "port": record.get("port"),
        "preferred_asia": bool(record.get("preferred_asia")),
        "attempts": attempts,
        "success_count": successes,
        "failure_count": max(attempts - successes, 0),
        "success_rate": round(successes / attempts, 4) if attempts else 0.0,
        "min_delay_ms": min(delays) if delays else None,
        "median_delay_ms": round(median_ms, 2) if median_ms is not None else None,
        "p90_delay_ms": round(p90_ms, 2) if p90_ms is not None else None,
        "max_delay_ms": max(delays) if delays else None,
        "jitter_ms": round(jitter_ms, 2) if jitter_ms is not None else None,
        "samples_ms": samples,
        "last_error": str(record.get("last_error") or ""),
    }


def stability_sort_key(summary: dict[str, Any]) -> tuple[Any, ...]:
    infinity = float("inf")

    def metric(name: str) -> float:
        value = summary.get(name)
        return infinity if value is None else float(value)

    return (
        -float(summary.get("success_rate", 0.0)),
        metric("p90_delay_ms"),
        metric("median_delay_ms"),
        metric("jitter_ms"),
        metric("min_delay_ms"),
        str(summary.get("name", "")),
    )


def select_preliminary_candidates(
    summaries: list[dict[str, Any]],
    limit: int,
    asia_target: int,
    non_asia_target: int,
) -> list[str]:
    """Choose a broad second-stage pool while preventing Asia from being crowded out."""

    ranked = sorted(summaries, key=stability_sort_key)
    asia = [summary for summary in ranked if summary.get("preferred_asia")]
    non_asia = [summary for summary in ranked if not summary.get("preferred_asia")]
    selected: list[str] = []
    used: set[str] = set()

    def take(items: list[dict[str, Any]], count: int) -> None:
        for item in items:
            if len(selected) >= limit or count <= 0:
                break
            name = str(item.get("name", ""))
            if not name or name in used:
                continue
            selected.append(name)
            used.add(name)
            count -= 1

    take(asia, asia_target)
    take(non_asia, non_asia_target)
    take(ranked, max(limit - len(selected), 0))
    return selected


def is_elite_result(
    summary: dict[str, Any],
    min_success_rate: float,
    max_p90_ms: float,
) -> bool:
    return (
        float(summary.get("success_rate", 0.0)) >= min_success_rate
        and float(summary.get("p90_delay_ms") or math.inf) <= max_p90_ms
    )


def select_stable_results(
    summaries: list[dict[str, Any]],
    min_success_rate: float,
    base_preferred_success_rate: float,
    max_qualified_p90_ms: float,
    base_target: int,
    maximum: int,
    non_asia_min: int,
    non_asia_max: int,
    elite_min_success_rate: float,
    elite_max_p90_ms: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build an Asia-heavy stable set, then expand only with elite results."""

    qualified = sorted(
        (
            summary
            for summary in summaries
            if float(summary.get("success_rate", 0.0)) >= min_success_rate
            and float(summary.get("p90_delay_ms") or math.inf) <= max_qualified_p90_ms
        ),
        key=stability_sort_key,
    )
    asia = [summary for summary in qualified if summary.get("preferred_asia")]
    non_asia = [summary for summary in qualified if not summary.get("preferred_asia")]
    preferred_asia = [
        summary
        for summary in asia
        if float(summary.get("success_rate", 0.0)) >= base_preferred_success_rate
    ]
    fallback_asia = [summary for summary in asia if summary not in preferred_asia]
    preferred_non_asia = [
        summary
        for summary in non_asia
        if float(summary.get("success_rate", 0.0)) >= base_preferred_success_rate
    ]
    fallback_non_asia = [summary for summary in non_asia if summary not in preferred_non_asia]
    selected_names: set[str] = set()

    for item in (preferred_non_asia + fallback_non_asia)[: min(non_asia_min, maximum)]:
        selected_names.add(str(item["name"]))

    for item in preferred_asia + fallback_asia:
        if len(selected_names) >= min(base_target, maximum):
            break
        selected_names.add(str(item["name"]))

    selected_non_asia = sum(
        1 for item in non_asia if str(item.get("name", "")) in selected_names
    )
    for item in preferred_non_asia + fallback_non_asia:
        if len(selected_names) >= min(base_target, maximum) or selected_non_asia >= non_asia_max:
            break
        name = str(item["name"])
        if name in selected_names:
            continue
        selected_names.add(name)
        selected_non_asia += 1

    elite_remaining = sorted(
        (
            item
            for item in qualified
            if str(item.get("name", "")) not in selected_names
            and is_elite_result(item, elite_min_success_rate, elite_max_p90_ms)
        ),
        key=stability_sort_key,
    )
    for item in elite_remaining:
        if len(selected_names) >= maximum:
            break
        name = str(item["name"])
        if name in selected_names:
            continue
        if not item.get("preferred_asia"):
            if selected_non_asia >= non_asia_max:
                continue
            selected_non_asia += 1
        selected_names.add(name)

    selected = [item for item in qualified if str(item.get("name", "")) in selected_names]
    return selected, qualified


def main() -> int:
    args = parse_args()
    for label, value in (
        ("timeout-ms", args.timeout_ms),
        ("preliminary-rounds", args.preliminary_rounds),
        ("total-rounds", args.total_rounds),
        ("workers", args.workers),
        ("candidate-limit", args.candidate_limit),
        ("base-target", args.base_target),
        ("max-nodes", args.max_nodes),
        ("min-success", args.min_success),
    ):
        if value <= 0:
            raise RuntimeError(f"--{label} must be greater than zero")
    if args.preliminary_rounds >= args.total_rounds:
        raise RuntimeError("--preliminary-rounds must be smaller than --total-rounds")
    if args.candidate_limit < args.max_nodes:
        raise RuntimeError("--candidate-limit must be at least --max-nodes")
    if args.base_target > args.max_nodes:
        raise RuntimeError("--base-target cannot exceed --max-nodes")
    if args.min_success > args.max_nodes:
        raise RuntimeError("--min-success cannot exceed --max-nodes")
    if not 0 <= args.non_asia_min <= args.non_asia_max <= args.max_nodes:
        raise RuntimeError("non-Asia limits must satisfy 0 <= min <= max <= max-nodes")
    if args.non_asia_min > args.base_target:
        raise RuntimeError("--non-asia-min cannot exceed --base-target")
    if min(args.asia_candidate_target, args.non_asia_candidate_target) < 0:
        raise RuntimeError("candidate region targets cannot be negative")
    if args.asia_candidate_target + args.non_asia_candidate_target > args.candidate_limit:
        raise RuntimeError("candidate region targets cannot exceed --candidate-limit in total")
    if args.round_gap < 0:
        raise RuntimeError("--round-gap cannot be negative")
    if not 0.0 <= args.min_retain_ratio <= 1.0:
        raise RuntimeError("--min-retain-ratio must be between zero and one")
    for label, value in (
        ("min-success-rate", args.min_success_rate),
        ("base-preferred-success-rate", args.base_preferred_success_rate),
        ("elite-min-success-rate", args.elite_min_success_rate),
    ):
        if not 0.0 <= value <= 1.0:
            raise RuntimeError(f"--{label} must be between zero and one")
    if not (
        args.min_success_rate
        <= args.base_preferred_success_rate
        <= args.elite_min_success_rate
    ):
        raise RuntimeError("success-rate thresholds must be ordered from minimum to elite")
    for label, value in (
        ("max-qualified-p90-ms", args.max_qualified_p90_ms),
        ("elite-max-p90-ms", args.elite_max_p90_ms),
    ):
        if value <= 0:
            raise RuntimeError(f"--{label} must be greater than zero")
    if args.elite_max_p90_ms > args.max_qualified_p90_ms:
        raise RuntimeError("--elite-max-p90-ms cannot exceed --max-qualified-p90-ms")

    mihomo = Path(args.mihomo).resolve()
    if not mihomo.is_file():
        raise RuntimeError(f"Mihomo executable does not exist: {mihomo}")

    profile, _source_content, source_status, source_sha256 = load_source_snapshot(
        args.source,
        args.source_status,
    )
    normalized, rejected = normalize_reality_short_ids(profile["proxies"])
    if rejected:
        print(f"Config validation: dropped {len(rejected)} malformed REALITY proxies.", flush=True)
    if not normalized:
        raise RuntimeError("source profile contains no proxies after REALITY validation")
    profile["proxies"] = normalized
    proxies = unique_proxy_names(normalized)
    proxies_by_name = {str(proxy["name"]): proxy for proxy in proxies}
    work_dir = Path(args.work_dir).resolve()
    output_dir = Path(args.output_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    controller = f"127.0.0.1:{free_port()}"
    runtime_profile = {
        "mixed-port": free_port(),
        "external-controller": controller,
        "mode": "global",
        "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": [{"name": "probe", "type": "select", "proxies": list(proxies_by_name)}],
        "rules": ["MATCH,probe"],
    }
    runtime_config = work_dir / "mihomo-runtime.yaml"
    runtime_log = work_dir / "mihomo.log"
    runtime_yaml, runtime_rejected = dump_clash_yaml(runtime_profile)
    if runtime_rejected:
        raise RuntimeError(f"runtime profile still contains {len(runtime_rejected)} invalid REALITY short IDs")
    runtime_config.write_text(runtime_yaml, encoding="utf-8")

    records = {str(proxy["name"]): new_probe_record(proxy) for proxy in proxies}
    candidate_names: list[str] = []
    print(
        f"Loaded {len(proxies)} proxies; starting {args.preliminary_rounds}-round preliminary checks.",
        flush=True,
    )
    with runtime_log.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [str(mihomo), "-d", str(work_dir), "-f", str(runtime_config)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_mihomo(controller, process, runtime_log)
            run_probe_rounds(
                controller,
                proxies,
                records,
                args.target_url,
                args.expected_status,
                args.timeout_ms,
                args.workers,
                args.preliminary_rounds,
                args.round_gap,
                "preliminary",
                process,
            )
            preliminary = [summarize_probe_record(record) for record in records.values()]
            candidate_names = select_preliminary_candidates(
                preliminary,
                args.candidate_limit,
                args.asia_candidate_target,
                args.non_asia_candidate_target,
            )
            candidate_set = set(candidate_names)
            candidates = [
                proxy for proxy in proxies if str(proxy.get("name", "")) in candidate_set
            ]
            asia_candidates = sum(is_preferred_asian_proxy(proxy) for proxy in candidates)
            print(
                f"Advanced {len(candidates)} candidates to full testing "
                f"(Asia {asia_candidates}, non-Asia {len(candidates) - asia_candidates}).",
                flush=True,
            )
            run_probe_rounds(
                controller,
                candidates,
                records,
                args.target_url,
                args.expected_status,
                args.timeout_ms,
                args.workers,
                args.total_rounds - args.preliminary_rounds,
                args.round_gap,
                "full-test",
                process,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    results = [summarize_probe_record(record) for record in records.values()]
    candidate_set = set(candidate_names)
    candidate_results = [
        item for item in results if str(item.get("name", "")) in candidate_set
    ]
    incomplete = [
        str(item.get("name", ""))
        for item in candidate_results
        if int(item.get("attempts", 0)) != args.total_rounds
    ]
    if incomplete:
        raise RuntimeError(
            f"{len(incomplete)} candidates did not complete all {args.total_rounds} rounds"
        )

    selected_results, qualified_results = select_stable_results(
        candidate_results,
        args.min_success_rate,
        args.base_preferred_success_rate,
        args.max_qualified_p90_ms,
        args.base_target,
        args.max_nodes,
        args.non_asia_min,
        args.non_asia_max,
        args.elite_min_success_rate,
        args.elite_max_p90_ms,
    )
    previous_status = load_optional_json(args.previous_status)
    try:
        previous_published_count = max(int(previous_status.get("published_count", 0)), 0)
    except (TypeError, ValueError):
        previous_published_count = 0
    previous_baseline = min(previous_published_count, args.max_nodes)
    required_count = max(
        args.base_target,
        calculate_publish_floor(
            args.min_success,
            previous_baseline,
            args.min_retain_ratio,
        ),
    )
    print(
        "Stable publish floor: "
        f"{required_count} (previous baseline={previous_baseline}, minimum={args.min_success}, "
        f"ratio={args.min_retain_ratio:.2f}).",
        flush=True,
    )
    if len(qualified_results) < required_count or len(selected_results) < required_count:
        qualified_asia = sum(bool(item.get("preferred_asia")) for item in qualified_results)
        qualified_non_asia = len(qualified_results) - qualified_asia
        raise RuntimeError(
            f"only {len(qualified_results)} qualified and {len(selected_results)} selectable proxies; "
            f"qualified regions: Asia {qualified_asia}, non-Asia {qualified_non_asia}; "
            f"at least {required_count} are required; "
            "refusing to replace the last good profile"
        )

    selected_names = [str(item["name"]) for item in selected_results]
    selected = [copy.deepcopy(proxies_by_name[name]) for name in selected_names]
    output_profile = filtered_profile(profile, selected)

    profile_path = output_dir / "clash.yaml"
    output_yaml, output_rejected = dump_clash_yaml(output_profile)
    if output_rejected:
        raise RuntimeError(f"output profile contains {len(output_rejected)} invalid REALITY short IDs")
    profile_path.write_text(output_yaml, encoding="utf-8")
    yaml.safe_load(profile_path.read_text(encoding="utf-8"))

    qualified_names = {str(item["name"]) for item in qualified_results}
    selected_rank = {name: index + 1 for index, name in enumerate(selected_names)}
    for item in results:
        name = str(item.get("name", ""))
        item["candidate"] = name in candidate_set
        item["qualified"] = name in qualified_names
        item["elite"] = bool(
            item["candidate"]
            and is_elite_result(
                item,
                args.elite_min_success_rate,
                args.elite_max_p90_ms,
            )
        )
        item["selected"] = name in selected_rank
        item["selected_rank"] = selected_rank.get(name)
        if not item["candidate"]:
            item["drop_reason"] = "not_advanced_after_preliminary_rounds"
        elif not item["qualified"]:
            item["drop_reason"] = "below_stability_or_p90_threshold"
        elif not item["selected"]:
            item["drop_reason"] = "outside_dynamic_capacity_or_region_limit"
        else:
            item["drop_reason"] = ""
    results.sort(
        key=lambda item: (
            not bool(item.get("selected")),
            not bool(item.get("qualified")),
            stability_sort_key(item),
        )
    )
    (output_dir / "probe-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    runner_network = discover_runner_network()
    status = {
        "run_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runner_ip": os.environ.get("CNB_RUNNER_IP", ""),
        **runner_network,
        "source": args.source,
        "source_status_url": args.source_status,
        "source_run_at": str(source_status.get("run_at") or ""),
        "source_sha256": source_sha256,
        "main_sha": args.main_sha,
        "selection_schema_version": 2,
        "target_url": args.target_url,
        "expected_status": args.expected_status,
        "timeout_ms": args.timeout_ms,
        "attempts": args.total_rounds,
        "preliminary_rounds": args.preliminary_rounds,
        "total_rounds": args.total_rounds,
        "round_gap_seconds": args.round_gap,
        "source_count": len(proxies),
        "source_asia_count": sum(is_preferred_asian_proxy(proxy) for proxy in proxies),
        "preliminary_passed_count": sum(
            any(
                sample is not None
                for sample in list(item.get("samples_ms", []))[: args.preliminary_rounds]
            )
            for item in results
        ),
        "candidate_count": len(candidate_results),
        "candidate_asia_count": sum(bool(item.get("preferred_asia")) for item in candidate_results),
        "passed_count": len(qualified_results),
        "qualified_count": len(qualified_results),
        "qualified_asia_count": sum(bool(item.get("preferred_asia")) for item in qualified_results),
        "elite_count": sum(
            is_elite_result(item, args.elite_min_success_rate, args.elite_max_p90_ms)
            for item in candidate_results
        ),
        "elite_asia_count": sum(
            bool(item.get("preferred_asia"))
            and is_elite_result(item, args.elite_min_success_rate, args.elite_max_p90_ms)
            for item in candidate_results
        ),
        "published_count": len(selected),
        "published_asia_count": sum(bool(item.get("preferred_asia")) for item in selected_results),
        "published_non_asia_count": sum(
            not bool(item.get("preferred_asia")) for item in selected_results
        ),
        "base_target": args.base_target,
        "publish_limit": args.max_nodes,
        "candidate_limit": args.candidate_limit,
        "asia_candidate_target": args.asia_candidate_target,
        "non_asia_candidate_target": args.non_asia_candidate_target,
        "non_asia_min": args.non_asia_min,
        "non_asia_max": args.non_asia_max,
        "minimum_success_rate": args.min_success_rate,
        "base_preferred_success_rate": args.base_preferred_success_rate,
        "elite_min_success_rate": args.elite_min_success_rate,
        "max_qualified_p90_ms": args.max_qualified_p90_ms,
        "elite_max_p90_ms": args.elite_max_p90_ms,
        "minimum_success": args.min_success,
        "minimum_retain_ratio": args.min_retain_ratio,
        "previous_published_count": previous_published_count,
        "previous_publish_baseline": previous_baseline,
        "required_count": required_count,
        "fastest_delay_ms": min(
            (float(item["median_delay_ms"]) for item in selected_results), default=None
        ),
        "slowest_published_delay_ms": max(
            (float(item["p90_delay_ms"]) for item in selected_results), default=None
        ),
        "lowest_published_success_rate": min(
            (float(item["success_rate"]) for item in selected_results), default=None
        ),
    }
    (output_dir / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Published {len(selected)} stable proxies from {len(qualified_results)} qualified candidates: "
        f"Asia {sum(bool(item.get('preferred_asia')) for item in selected_results)}, "
        f"non-Asia {sum(not bool(item.get('preferred_asia')) for item in selected_results)}."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
