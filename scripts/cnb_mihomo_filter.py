#!/usr/bin/env python3
"""Filter a Clash profile with protocol-level checks through a local Mihomo."""

from __future__ import annotations

import argparse
import copy
import hashlib
import ipaddress
import json
import os
import socket
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
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--max-nodes", type=int, default=80, help="Publish cap; zero publishes every passing node")
    parser.add_argument("--min-success", type=int, default=20)
    parser.add_argument("--min-retain-ratio", type=float, default=0.25)
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
    attempts: int,
) -> dict[str, Any]:
    name = str(proxy.get("name", ""))
    encoded_name = urllib.parse.quote(name, safe="")
    encoded_target = urllib.parse.quote(target_url, safe="")
    url = (
        f"http://{controller}/proxies/{encoded_name}/delay"
        f"?timeout={timeout_ms}&url={encoded_target}&expected={expected_status}"
    )
    error = "no positive delay returned"
    for attempt in range(max(1, attempts)):
        try:
            payload = api_json(url, timeout=timeout_ms / 1000 + 3)
            delay = int(payload.get("delay", 0))
            if delay > 0:
                return {
                    "name": name,
                    "type": str(proxy.get("type", "")),
                    "server": str(proxy.get("server", "")),
                    "port": proxy.get("port"),
                    "ok": True,
                    "delay_ms": delay,
                    "attempt": attempt + 1,
                }
            error = str(payload.get("message") or error)
        except Exception as exc:
            error = str(exc)
        if attempt + 1 < max(1, attempts):
            time.sleep(0.15)
    return {
        "name": name,
        "type": str(proxy.get("type", "")),
        "server": str(proxy.get("server", "")),
        "port": proxy.get("port"),
        "ok": False,
        "delay_ms": None,
        "error": error[:300],
    }


def select_fastest(
    proxies_by_name: dict[str, dict[str, Any]], results: list[dict[str, Any]], maximum: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    passed = sorted((item for item in results if item.get("ok")), key=lambda item: int(item["delay_ms"]))
    selected_results = passed[:maximum] if maximum > 0 else passed
    selected = [copy.deepcopy(proxies_by_name[str(item["name"])]) for item in selected_results]
    return selected, selected_results


def main() -> int:
    args = parse_args()
    for label, value in (
        ("timeout-ms", args.timeout_ms),
        ("attempts", args.attempts),
        ("workers", args.workers),
        ("min-success", args.min_success),
    ):
        if value <= 0:
            raise RuntimeError(f"--{label} must be greater than zero")
    if args.max_nodes < 0:
        raise RuntimeError("--max-nodes cannot be negative")
    if not 0.0 <= args.min_retain_ratio <= 1.0:
        raise RuntimeError("--min-retain-ratio must be between zero and one")

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

    print(f"Loaded {len(proxies)} proxies; starting protocol-level checks from this runner.", flush=True)
    with runtime_log.open("w", encoding="utf-8") as log_file:
        process = subprocess.Popen(
            [str(mihomo), "-d", str(work_dir), "-f", str(runtime_config)],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_mihomo(controller, process, runtime_log)
            results: list[dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=min(args.workers, len(proxies))) as executor:
                futures = {
                    executor.submit(
                        check_proxy,
                        controller,
                        proxy,
                        args.target_url,
                        args.expected_status,
                        args.timeout_ms,
                        args.attempts,
                    ): proxy
                    for proxy in proxies
                }
                for index, future in enumerate(as_completed(futures), start=1):
                    results.append(future.result())
                    if index % 25 == 0 or index == len(futures):
                        passed_so_far = sum(1 for item in results if item.get("ok"))
                        print(f"Checked {index}/{len(futures)}; {passed_so_far} passed.", flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)

    passed_count = sum(1 for item in results if item.get("ok"))
    previous_status = load_optional_json(args.previous_status)
    try:
        previous_count = max(int(previous_status.get("published_count", 0)), 0)
    except (TypeError, ValueError):
        previous_count = 0
    required_count = calculate_publish_floor(
        args.min_success,
        previous_count,
        args.min_retain_ratio,
    )
    print(
        "Publish floor: "
        f"{required_count} (previous={previous_count}, minimum={args.min_success}, "
        f"ratio={args.min_retain_ratio:.2f}).",
        flush=True,
    )
    if passed_count < required_count:
        raise RuntimeError(
            f"only {passed_count}/{len(proxies)} proxies passed; at least {required_count} are required; "
            "refusing to replace the last good profile"
        )

    selected, selected_results = select_fastest(proxies_by_name, results, args.max_nodes)
    output_profile = filtered_profile(profile, selected)

    profile_path = output_dir / "clash.yaml"
    output_yaml, output_rejected = dump_clash_yaml(output_profile)
    if output_rejected:
        raise RuntimeError(f"output profile contains {len(output_rejected)} invalid REALITY short IDs")
    profile_path.write_text(output_yaml, encoding="utf-8")
    yaml.safe_load(profile_path.read_text(encoding="utf-8"))

    results.sort(key=lambda item: (not bool(item.get("ok")), item.get("delay_ms") or sys.maxsize, item["name"]))
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
        "target_url": args.target_url,
        "timeout_ms": args.timeout_ms,
        "attempts": args.attempts,
        "source_count": len(proxies),
        "passed_count": passed_count,
        "published_count": len(selected),
        "publish_limit": args.max_nodes or None,
        "minimum_success": args.min_success,
        "minimum_retain_ratio": args.min_retain_ratio,
        "previous_published_count": previous_count,
        "required_count": required_count,
        "fastest_delay_ms": selected_results[0]["delay_ms"] if selected_results else None,
        "slowest_published_delay_ms": selected_results[-1]["delay_ms"] if selected_results else None,
    }
    (output_dir / "status.json").write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"Published candidate set: {len(selected)} proxies from {passed_count}/{len(proxies)} passing proxies."
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
