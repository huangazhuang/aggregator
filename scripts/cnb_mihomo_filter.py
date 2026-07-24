#!/usr/bin/env python3
"""Filter a Clash profile with protocol-level checks through a local Mihomo."""

from __future__ import annotations

import argparse
import copy
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


BUILTIN_PROXY_NAMES = {"DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Use Mihomo to keep the fastest proxies that work from this machine."
    )
    parser.add_argument("--source", required=True, help="Clash YAML file path or HTTP(S) URL")
    parser.add_argument("--mihomo", required=True, help="Path to the Mihomo executable")
    parser.add_argument("--work-dir", required=True, help="Directory for Mihomo runtime files")
    parser.add_argument("--output-dir", required=True, help="Directory for generated public files")
    parser.add_argument(
        "--target-url", default="https://www.gstatic.com/generate_204", help="URL requested through each proxy"
    )
    parser.add_argument("--expected-status", type=int, default=204)
    parser.add_argument("--timeout-ms", type=int, default=3000)
    parser.add_argument("--attempts", type=int, default=2)
    parser.add_argument("--workers", type=int, default=48)
    parser.add_argument("--max-nodes", type=int, default=80)
    parser.add_argument("--min-success", type=int, default=5)
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


def load_profile(source: str) -> dict[str, Any]:
    try:
        profile = yaml.safe_load(read_source(source)) or {}
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
    return profile


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


def filter_groups(profile: dict[str, Any], selected_names: list[str]) -> None:
    groups = profile.get("proxy-groups", [])
    if not isinstance(groups, list):
        return
    group_names = {str(group.get("name")) for group in groups if isinstance(group, dict) and group.get("name")}
    selected_set = set(selected_names)
    allowed_refs = selected_set | group_names | BUILTIN_PROXY_NAMES
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("proxies"), list):
            continue
        references = [str(item) for item in group["proxies"] if str(item) in allowed_refs]
        fixed_references = [item for item in references if item in group_names or item in BUILTIN_PROXY_NAMES]
        selected_members = [item for item in selected_names if item in references]
        group["proxies"] = list(dict.fromkeys(fixed_references + selected_members))


def select_fastest(
    proxies_by_name: dict[str, dict[str, Any]], results: list[dict[str, Any]], maximum: int
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    passed = sorted((item for item in results if item.get("ok")), key=lambda item: int(item["delay_ms"]))
    selected_results = passed[:maximum]
    selected = [copy.deepcopy(proxies_by_name[str(item["name"])]) for item in selected_results]
    return selected, selected_results


def main() -> int:
    args = parse_args()
    for label, value in (
        ("timeout-ms", args.timeout_ms),
        ("attempts", args.attempts),
        ("workers", args.workers),
        ("max-nodes", args.max_nodes),
        ("min-success", args.min_success),
    ):
        if value <= 0:
            raise RuntimeError(f"--{label} must be greater than zero")

    mihomo = Path(args.mihomo).resolve()
    if not mihomo.is_file():
        raise RuntimeError(f"Mihomo executable does not exist: {mihomo}")

    profile = load_profile(args.source)
    proxies = unique_proxy_names(profile["proxies"])
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
    runtime_config.write_text(
        yaml.safe_dump(runtime_profile, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )

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
    if passed_count < args.min_success:
        raise RuntimeError(
            f"only {passed_count}/{len(proxies)} proxies passed; refusing to replace the last good profile"
        )

    selected, selected_results = select_fastest(proxies_by_name, results, args.max_nodes)
    selected_names = [str(proxy["name"]) for proxy in selected]
    output_profile = copy.deepcopy(profile)
    output_profile["proxies"] = selected
    filter_groups(output_profile, selected_names)

    profile_path = output_dir / "clash.yaml"
    profile_path.write_text(
        yaml.safe_dump(output_profile, allow_unicode=True, sort_keys=False), encoding="utf-8"
    )
    yaml.safe_load(profile_path.read_text(encoding="utf-8"))

    results.sort(key=lambda item: (not bool(item.get("ok")), item.get("delay_ms") or sys.maxsize, item["name"]))
    (output_dir / "probe-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    status = {
        "run_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "runner_ip": os.environ.get("CNB_RUNNER_IP", ""),
        "source": args.source,
        "target_url": args.target_url,
        "timeout_ms": args.timeout_ms,
        "attempts": args.attempts,
        "source_count": len(proxies),
        "passed_count": passed_count,
        "published_count": len(selected),
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
