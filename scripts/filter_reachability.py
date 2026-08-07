#!/usr/bin/env python3
"""Fail-closed protocol-level reachability filter for the GitHub profile."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, os.path.abspath("subscribe"))

import clash  # noqa: E402
import executable  # noqa: E402
import utils  # noqa: E402

from scripts.pipeline_utils import calculate_publish_floor


def fail_closed(message: str, lines: list[str] | None = None) -> None:
    print(f"::error::{message}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### Reachability filter\n")
            for line in lines or []:
                handle.write(f"- {line}\n")
            handle.write(f"- FAILED CLOSED: {message}\n")
    raise RuntimeError(message)


def integer_setting(name: str, default: int) -> int:
    try:
        return max(int(os.environ.get(name, str(default))), 1)
    except Exception:
        return default


def ratio_setting(name: str, default: float) -> float:
    try:
        return min(max(float(os.environ.get(name, str(default))), 0.0), 1.0)
    except Exception:
        return default


def previous_proxy_count(path: Path) -> int:
    try:
        data = json.loads(path.read_text(encoding="utf-8")) or {}
        return max(int(data.get("proxy_count", 0)), 0)
    except Exception:
        return 0


def select_reachability_passes(
    checks: list[dict[str, Any]],
    tested: list[dict[str, Any]],
    valid_masks: list[list[bool]],
) -> list[dict[str, Any]]:
    """Keep protected Asia plus ordinary proxies that passed every target."""

    tested_passed_names = (
        {
            str(tested[index].get("name", ""))
            for index in range(len(tested))
            if all(mask[index] for mask in valid_masks)
        }
        if valid_masks
        else set()
    )
    return [
        proxy
        for proxy in checks
        if utils.is_preferred_asian_proxy(proxy)
        or str(proxy.get("name", "")) in tested_passed_names
    ]


def main() -> int:
    targets = [
        (os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/"), 200),
        ("https://www.google.com/generate_204", 204),
        ("https://www.youtube.com/generate_204", 204),
    ]
    profile = Path("data") / os.environ.get("PROFILE_FILE", "clash.yaml")
    previous_count = previous_proxy_count(Path("data/previous-status.json"))
    data = yaml.load(profile.read_text(encoding="utf-8", errors="ignore"), Loader=yaml.SafeLoader) or {}
    proxies = [proxy for proxy in data.get("proxies", []) if isinstance(proxy, dict)]
    if not proxies:
        fail_closed("the candidate profile contains no proxies; keeping the previous published profile")

    validated: list[dict[str, Any]] = []
    for proxy in proxies:
        try:
            if clash.verify(proxy, mihomo=True):
                validated.append(proxy)
        except Exception:
            pass
    invalid_count = len(proxies) - len(validated)
    if invalid_count:
        print(f"config validation: dropped {invalid_count} malformed proxies")
    if not validated:
        fail_closed("all candidate proxies failed config validation; keeping the previous published profile")

    workspace = Path.cwd() / "clash"
    clash_bin, _ = executable.which_bin()
    binary = workspace / clash_bin
    utils.chmod(str(binary))
    checks = clash.generate_config(str(workspace), validated, "reach-check.yaml")
    if not checks:
        fail_closed("Mihomo test configuration contains no valid proxies")

    protected = [utils.is_preferred_asian_proxy(proxy) for proxy in checks]
    tested = [proxy for index, proxy in enumerate(checks) if not protected[index]]

    def reachable(proxy: dict[str, Any], target: str, expected: int) -> bool:
        name = urllib.parse.quote(str(proxy.get("name", "")), safe="")
        quoted = urllib.parse.quote(target)
        url = (
            f"http://{clash.EXTERNAL_CONTROLLER}/proxies/{name}/delay"
            f"?timeout=3000&url={quoted}&expected={expected}"
        )
        content = utils.http_get(url=url, retry=2, interval=0.1)
        try:
            return json.loads(content).get("delay", -1) > 0
        except Exception:
            return False

    process: subprocess.Popen[Any] | None = None
    lines: list[str] = [
        f"protected Asia skipped from network tests: {sum(protected)}/{len(checks)}"
    ]
    valid_masks: list[list[bool]] = []
    if tested:
        try:
            process = subprocess.Popen(
                [str(binary), "-d", str(workspace), "-f", str(workspace / "reach-check.yaml")]
            )
            time.sleep(8)
            if process.poll() is not None:
                fail_closed(f"Mihomo exited before reachability checks (code {process.returncode})", lines)

            for target, expected in targets:
                masks = utils.multi_thread_run(
                    func=reachable,
                    tasks=[[proxy, target, expected] for proxy in tested],
                    num_threads=128,
                    show_progress=False,
                )
                if not isinstance(masks, list) or len(masks) != len(tested):
                    fail_closed(f"incomplete reachability results for {target}", lines)
                count = sum(1 for mask in masks if mask)
                lines.append(f"{target}: {count}/{len(tested)} tested proxies reachable")
                print(lines[-1])
                if count <= 0:
                    fail_closed(f"no proxy passed {target}; treating the target check as unavailable", lines)
                valid_masks.append(masks)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    else:
        lines.append("all valid proxies are protected Asia; network tests skipped")
        print(lines[-1])

    passed = select_reachability_passes(checks, tested, valid_masks)
    lines.append(
        f"kept {len(passed)}/{len(checks)} proxies (protected Asia {sum(protected)})"
    )
    print(f"reachability filter: kept {len(passed)}/{len(checks)} proxies")

    minimum = integer_setting("STRICT_MIN_NODES", 20)
    ratio = ratio_setting("STRICT_MIN_RETAIN_RATIO", 0.25)
    required = calculate_publish_floor(minimum, previous_count, ratio)
    lines.append(
        f"publish floor: {required} proxies (previous={previous_count}, minimum={minimum}, ratio={ratio:.2f})"
    )
    if len(passed) < required:
        fail_closed(
            f"only {len(passed)} proxies passed all required sites; at least {required} are required",
            lines,
        )

    summary = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### Reachability filter\n" + "".join(f"- {line}\n" for line in lines))

    config = {
        "mixed-port": 7890,
        "external-controller": clash.EXTERNAL_CONTROLLER,
        "mode": "Rule",
        "log-level": "silent",
    }
    config.update(clash.filter_proxies(passed))
    for group in config.get("proxy-groups", []):
        if group.get("type") == "url-test":
            group["url"] = os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/")

    with profile.open("w", encoding="utf-8") as handle:
        yaml.add_representer(clash.QuotedStr, clash.quoted_scalar)
        yaml.dump(config, handle, allow_unicode=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
