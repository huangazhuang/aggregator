#!/usr/bin/env python3
"""Fail-closed protocol-level reachability filter for the GitHub profile."""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any, Callable

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(1, str(ROOT / "subscribe"))

import clash  # noqa: E402
import executable  # noqa: E402
import utils  # noqa: E402

from scripts.pipeline_utils import (
    build_candidate_v2_clash_profile,
    calculate_publish_floor,
    dump_clash_yaml,
)
from scripts.cnb_gmgn_v2 import (  # Reuse the audited CNB browser probe transport.
    HTTP_PROBE_PORTS_PER_SHARD,
    _BrowserProbePool,
    _http_probe_runtime,
    curl_requests as browser_requests,
)


REPORT_FILE = Path("data/github-check-report.json")


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


def candidate_v2_enabled() -> bool:
    return os.environ.get("ENABLE_CANDIDATE_V2", "false").strip().lower() == "true"


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
    *,
    bind_by_index: bool = False,
) -> list[dict[str, Any]]:
    """Keep protected Asia plus ordinary proxies that passed every target."""

    tested_passed_indexes = {
        index
        for index in range(len(tested))
        if valid_masks and all(mask[index] for mask in valid_masks)
    }
    if bind_by_index:
        tested_index = 0
        selected: list[dict[str, Any]] = []
        for proxy in checks:
            if utils.is_preferred_asian_proxy(proxy):
                selected.append(proxy)
                continue
            if tested_index in tested_passed_indexes:
                selected.append(proxy)
            tested_index += 1
        return selected

    tested_passed_names = {
        str(tested[index].get("name", "")) for index in tested_passed_indexes
    }
    return [
        proxy
        for proxy in checks
        if utils.is_preferred_asian_proxy(proxy)
        or str(proxy.get("name", "")) in tested_passed_names
    ]


def mihomo_expected_status_passed(
    proxy: dict[str, Any],
    target: str,
    expected: int,
    *,
    controller: str = clash.EXTERNAL_CONTROLLER,
    getter: Callable[..., str] | None = None,
) -> bool:
    """Require both a current delay and Mihomo's expected-status alive state."""

    if (
        not isinstance(target, str)
        or not target
        or isinstance(expected, bool)
        or not isinstance(expected, int)
        or not 100 <= expected <= 599
    ):
        return False
    name = urllib.parse.quote(str(proxy.get("name", "")), safe="")
    if not name:
        return False
    fetch = getter or utils.http_get
    quoted = urllib.parse.quote(target, safe="")
    delay_url = (
        f"http://{controller}/proxies/{name}/delay"
        f"?timeout=3000&url={quoted}&expected={expected}"
    )
    state_url = f"http://{controller}/proxies/{name}"
    try:
        delay_payload = json.loads(fetch(url=delay_url, retry=2, interval=0.1))
        state_payload = json.loads(fetch(url=state_url, retry=2, interval=0.1))
    except Exception:
        return False
    delay = delay_payload.get("delay") if isinstance(delay_payload, dict) else None
    if (
        isinstance(delay, bool)
        or not isinstance(delay, (int, float))
        or delay <= 0
    ):
        return False
    extra = state_payload.get("extra") if isinstance(state_payload, dict) else None
    target_state = extra.get(target) if isinstance(extra, dict) else None
    return isinstance(target_state, dict) and target_state.get("alive") is True


def configure_candidate_browser_probes(
    profile: dict[str, Any],
    tested: list[dict[str, Any]],
    *,
    secret: str,
    workers: int,
) -> tuple[Any, ...]:
    """Add loopback-only selector/listener pairs without starting URL tests."""

    names = [str(proxy.get("name") or "") for proxy in tested]
    slots, groups, listeners = _http_probe_runtime(
        names,
        shard_index=0,
        workers=workers,
    )
    profile["secret"] = secret
    profile.pop("mixed-port", None)
    profile["proxy-groups"] = groups
    profile["listeners"] = listeners
    profile["rules"] = ["MATCH,DIRECT"]
    return slots


def browser_probe_outcome(
    pool: Any,
    proxy: dict[str, Any],
    target: str,
    expected: int,
) -> dict[str, Any]:
    """Run one strict browser request through the listener assigned by the pool."""

    outcome = pool.probe(
        {"proxy": proxy},
        target,
        3_000,
        expected_status=expected,
    )
    return dict(outcome) if isinstance(outcome, dict) else {"error": "invalid outcome"}


def browser_probe_passed(outcome: Any) -> bool:
    """Accept only the positive delay emitted after the exact expected status."""

    if not isinstance(outcome, dict):
        return False
    delay = outcome.get("delay_ms")
    return (
        not isinstance(delay, bool)
        and isinstance(delay, (int, float))
        and delay > 0
        and "target_status" not in outcome
        and "error" not in outcome
        and "error_category" not in outcome
    )


def summarize_browser_probe_outcomes(outcomes: list[Any]) -> str:
    """Return aggregate, credential-free diagnostics for one target."""

    categories: Counter[str] = Counter()
    for outcome in outcomes:
        if browser_probe_passed(outcome):
            categories["passed"] += 1
        elif isinstance(outcome, dict) and isinstance(outcome.get("target_status"), int):
            status = int(outcome["target_status"])
            categories[f"http_{status}" if status in {403, 429} else "http_other"] += 1
        elif isinstance(outcome, dict):
            category = str(
                outcome.get("diagnostic_category")
                or outcome.get("error_category")
                or "other"
            )
            categories[category] += 1
        else:
            categories["invalid_outcome"] += 1
    return ", ".join(f"{key}={categories[key]}" for key in sorted(categories))


def main() -> int:
    candidate_v2 = candidate_v2_enabled()
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
    check_profile: dict[str, Any] | None = None
    if candidate_v2:
        check_profile = build_candidate_v2_clash_profile(
            validated,
            external_controller=clash.EXTERNAL_CONTROLLER,
            test_url=os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/"),
        )
        checks = check_profile["proxies"]
    else:
        checks = clash.generate_config(str(workspace), validated, "reach-check.yaml")
    if not checks:
        fail_closed("Mihomo test configuration contains no valid proxies")

    protected = [utils.is_preferred_asian_proxy(proxy) for proxy in checks]
    tested = [proxy for index, proxy in enumerate(checks) if not protected[index]]

    browser_pool: Any | None = None
    if candidate_v2 and tested:
        if browser_requests is None:
            fail_closed("curl_cffi is required for Candidate V2 browser probes")
        workers = min(
            integer_setting("STRICT_BROWSER_PROBE_WORKERS", HTTP_PROBE_PORTS_PER_SHARD),
            HTTP_PROBE_PORTS_PER_SHARD,
            len(tested),
        )
        controller_secret = secrets.token_hex(32)
        slots = configure_candidate_browser_probes(
            check_profile,
            tested,
            secret=controller_secret,
            workers=workers,
        )
        browser_pool = _BrowserProbePool(
            clash.EXTERNAL_CONTROLLER,
            controller_secret,
            slots,
        )
    if candidate_v2:
        check_text, rejected = dump_clash_yaml(check_profile)
        if rejected:
            fail_closed("Candidate V2 contains invalid REALITY short IDs")
        (workspace / "reach-check.yaml").write_text(check_text, encoding="utf-8")

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
                if candidate_v2:
                    outcomes = utils.multi_thread_run(
                        func=browser_probe_outcome,
                        tasks=[[browser_pool, proxy, target, expected] for proxy in tested],
                        num_threads=workers,
                        show_progress=False,
                    )
                    masks = [browser_probe_passed(outcome) for outcome in outcomes]
                else:
                    masks = utils.multi_thread_run(
                        func=mihomo_expected_status_passed,
                        tasks=[[proxy, target, expected] for proxy in tested],
                        num_threads=128,
                        show_progress=False,
                    )
                    outcomes = []
                if not isinstance(masks, list) or len(masks) != len(tested):
                    fail_closed(f"incomplete reachability results for {target}", lines)
                count = sum(1 for mask in masks if mask)
                lines.append(f"{target}: {count}/{len(tested)} tested proxies reachable")
                if outcomes:
                    lines.append(
                        f"{target} diagnostics: {summarize_browser_probe_outcomes(outcomes)}"
                    )
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

    passed = select_reachability_passes(
        checks,
        tested,
        valid_masks,
        bind_by_index=candidate_v2,
    )
    ordinary_passed = sum(1 for proxy in passed if not utils.is_preferred_asian_proxy(proxy))
    report = {
        "kind": "github-reachability-report",
        "schema_version": 1,
        "policy_version": "github-reachability-v3",
        "tested": len(tested),
        "passed": ordinary_passed,
        "failed": len(tested) - ordinary_passed,
        "bypassed_asia": sum(protected),
    }
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text(
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
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

    if candidate_v2:
        config = build_candidate_v2_clash_profile(
            passed,
            external_controller=clash.EXTERNAL_CONTROLLER,
            test_url=os.environ.get("GMGN_CHECK_URL", "https://gmgn.ai/"),
        )
        content, rejected = dump_clash_yaml(config)
        if rejected:
            fail_closed("Candidate V2 contains invalid REALITY short IDs", lines)
        profile.write_text(content, encoding="utf-8")
    else:
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
