"""脱敏的 CNB 节点测速诊断和离线回放数据辅助函数。

这些函数只处理已经汇总的测速结果，不接触运行时 Mihomo YAML。公开的
逐节点记录只有每轮随机匿名标识、区域标记和聚合延迟指标；节点名称、服务器、
端口、认证字段、原始错误以及逐轮样本都不会写入诊断文件。
"""

from __future__ import annotations

import json
import math
import re
import secrets
from pathlib import Path
from typing import Any, Iterable


DEFAULT_ASIA_THRESHOLDS: tuple[tuple[str, int, float | None], ...] = (
    ("strict", 14, 2800.0),
    ("fallback", 12, 2800.0),
    ("emergency", 10, 2800.0),
    ("elite", 18, 2000.0),
)
REDACTED_RESULTS_FILENAME = "redacted-probe-results.json"
POLICY_NODE_ID_KEY = "_policy_node_id"
SELECTION_SCHEMA_VERSION = 4


def _success_count(summary: dict[str, Any]) -> int:
    try:
        return max(int(summary.get("success_count", 0)), 0)
    except (TypeError, ValueError):
        return 0


def _non_negative_int(value: Any) -> int:
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


def _finite_metric(value: Any) -> float | int | None:
    """Return a JSON-safe finite metric without manufacturing missing data."""

    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(numeric) or numeric < 0:
        return None
    return int(numeric) if numeric.is_integer() else numeric


def _p90_passes(summary: dict[str, Any], limit_ms: float | None) -> bool:
    if limit_ms is None:
        return True
    try:
        value = summary.get("p90_delay_ms")
        return value is not None and math.isfinite(float(value)) and float(value) <= limit_ms
    except (TypeError, ValueError):
        return False


def _partition(
    summaries: Iterable[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    asia: list[dict[str, Any]] = []
    non_asia: list[dict[str, Any]] = []
    for summary in summaries:
        (asia if bool(summary.get("preferred_asia")) else non_asia).append(summary)
    return asia, non_asia


def success_histogram(
    summaries: Iterable[dict[str, Any]],
    *,
    total_rounds: int = 20,
) -> dict[str, int]:
    """Return a stable 0..N success-count histogram."""

    rounds = max(int(total_rounds), 1)
    histogram = {str(index): 0 for index in range(rounds + 1)}
    for summary in summaries:
        count = min(_success_count(summary), rounds)
        histogram[str(count)] += 1
    return histogram


def _eligible(
    summaries: Iterable[dict[str, Any]],
    *,
    minimum_success: int,
    p90_limit_ms: float | None,
) -> list[dict[str, Any]]:
    return [
        summary
        for summary in summaries
        if _success_count(summary) >= minimum_success
        and _p90_passes(summary, p90_limit_ms)
    ]


def threshold_matrix(
    summaries: Iterable[dict[str, Any]],
    *,
    total_rounds: int = 20,
    asia_thresholds: tuple[tuple[str, int, float | None], ...] = DEFAULT_ASIA_THRESHOLDS,
    non_asia_minimum_success: int = 14,
    non_asia_p90_limit_ms: float | None = 2800.0,
    non_asia_max: int = 20,
    base_target: int = 80,
    asia_emergency_max_count: int = 0,
) -> dict[str, Any]:
    """Build the what-if counts used to explain a failed publication.

    ``selectable_count`` applies only the base target and the non-Asia cap; it
    deliberately does not pretend that elite expansion can repair a base-floor
    failure.
    """

    all_summaries = list(summaries)
    asia, non_asia = _partition(all_summaries)
    strict_non_asia = _eligible(
        non_asia,
        minimum_success=non_asia_minimum_success,
        p90_limit_ms=non_asia_p90_limit_ms,
    )
    non_asia_available = min(len(strict_non_asia), max(int(non_asia_max), 0))
    threshold_data: dict[str, Any] = {}
    for label, minimum_success, p90_limit in asia_thresholds:
        eligible_asia = _eligible(
            asia,
            minimum_success=int(minimum_success),
            p90_limit_ms=p90_limit,
        )
        if str(label) == "emergency" and int(asia_emergency_max_count) > 0:
            eligible_asia = eligible_asia[: int(asia_emergency_max_count)]
        available = len(eligible_asia) + non_asia_available
        threshold_data[str(label)] = {
            "minimum_success": int(minimum_success),
            "p90_limit_ms": p90_limit,
            "asia_count": len(eligible_asia),
            "non_asia_count_under_cap": non_asia_available,
            "selectable_count": min(max(int(base_target), 0), available),
            "base_reachable": available >= max(int(base_target), 0),
        }

    strict_asia = threshold_data.get("strict", {})
    return {
        "total_rounds": max(int(total_rounds), 1),
        "source_count": len(all_summaries),
        "asia_count": len(asia),
        "non_asia_count": len(non_asia),
        "asia_success_histogram": success_histogram(asia, total_rounds=total_rounds),
        "non_asia_success_histogram": success_histogram(non_asia, total_rounds=total_rounds),
        "strict_qualified_count": int(strict_asia.get("asia_count", 0)) + len(strict_non_asia),
        "strict_qualified_asia_count": int(strict_asia.get("asia_count", 0)),
        "strict_qualified_non_asia_count": len(strict_non_asia),
        "thresholds": threshold_data,
    }


def _safe_node_id() -> str:
    """Return a run-local random ID that cannot be enumerated from the source."""

    return f"n1_{secrets.token_hex(12)}"


def ensure_policy_node_ids(summaries: Iterable[dict[str, Any]]) -> None:
    """Attach unique run-local IDs used by production and offline tie-breaking."""

    used: set[str] = set()
    for summary in summaries:
        node_id = str(summary.get(POLICY_NODE_ID_KEY) or "")
        if not re.fullmatch(r"n1_[0-9a-f]{24}", node_id) or node_id in used:
            node_id = _safe_node_id()
            while node_id in used:
                node_id = _safe_node_id()
            summary[POLICY_NODE_ID_KEY] = node_id
        used.add(node_id)


def redacted_result(summary: dict[str, Any]) -> dict[str, Any]:
    """Keep replay metrics while omitting all connection and credential fields."""

    attempts = _non_negative_int(summary.get("attempts", 0))
    successes = min(_success_count(summary), attempts) if attempts else 0
    node_id = str(summary.get(POLICY_NODE_ID_KEY) or "")
    if not re.fullmatch(r"n1_[0-9a-f]{24}", node_id):
        node_id = _safe_node_id()
    return {
        "node_id": node_id,
        "preferred_asia": bool(summary.get("preferred_asia")),
        "attempts": attempts,
        "success_count": successes,
        "success_rate": round(successes / attempts, 4) if attempts else 0.0,
        "min_delay_ms": _finite_metric(summary.get("min_delay_ms")),
        "median_delay_ms": _finite_metric(summary.get("median_delay_ms")),
        "p90_delay_ms": _finite_metric(summary.get("p90_delay_ms")),
        "jitter_ms": _finite_metric(summary.get("jitter_ms")),
    }


def _threshold_lookup(
    thresholds: Iterable[tuple[str, int, float | None]],
) -> dict[str, tuple[int, float | None]]:
    result: dict[str, tuple[int, float | None]] = {}
    for label, minimum_success, p90_limit_ms in thresholds:
        result[str(label)] = (max(int(minimum_success), 0), p90_limit_ms)
    return result


def replay_policy_snapshot(
    *,
    total_rounds: int = 20,
    asia_thresholds: tuple[tuple[str, int, float | None], ...] = DEFAULT_ASIA_THRESHOLDS,
    non_asia_minimum_success: int = 14,
    non_asia_p90_limit_ms: float | None = 2800.0,
    non_asia_min: int = 10,
    non_asia_max: int = 20,
    base_target: int = 80,
    max_nodes: int = 150,
    asia_emergency_max_count: int = 0,
    required_count: int | None = None,
) -> dict[str, Any]:
    """Capture every value needed to replay the tiered production selector."""

    thresholds = _threshold_lookup(asia_thresholds)
    strict = thresholds.get("strict", (non_asia_minimum_success, non_asia_p90_limit_ms))
    fallback = thresholds.get("fallback", strict)
    emergency = thresholds.get("emergency", fallback)
    elite = thresholds.get("elite", strict)
    target = max(int(base_target), 0)
    return {
        "selection_schema_version": SELECTION_SCHEMA_VERSION,
        "asia_tiering": True,
        "total_rounds": max(int(total_rounds), 1),
        "strict_min_success": int(strict[0]),
        "fallback_min_success": int(fallback[0]),
        "emergency_min_success": int(emergency[0]),
        "qualified_p90_ms": strict[1],
        "non_asia_min_success": max(int(non_asia_minimum_success), 0),
        "non_asia_p90_ms": non_asia_p90_limit_ms,
        "emergency_p90_ms": emergency[1],
        "elite_min_success": int(elite[0]),
        "elite_p90_ms": elite[1],
        "base_target": target,
        "max_nodes": max(int(max_nodes), target),
        "non_asia_min": max(int(non_asia_min), 0),
        "non_asia_max": max(int(non_asia_max), 0),
        "emergency_max_count": max(int(asia_emergency_max_count), 0),
        "required_count": max(int(required_count if required_count is not None else target), 0),
    }


def _passes_replay_line(
    result: dict[str, Any],
    *,
    total_rounds: int,
    minimum_success: int,
    p90_limit_ms: float | None,
) -> bool:
    return (
        int(result["attempts"]) == total_rounds
        and int(result["success_count"]) >= minimum_success
        and _p90_passes(result, p90_limit_ms)
    )


def _annotate_replay_result(result: dict[str, Any], policy: dict[str, Any]) -> None:
    rounds = int(policy["total_rounds"])
    result["complete"] = int(result["attempts"]) == rounds
    tier = ""
    if result["preferred_asia"]:
        for label, minimum_key, p90_key in (
            ("asia-strict", "strict_min_success", "qualified_p90_ms"),
            ("asia-fallback", "fallback_min_success", "qualified_p90_ms"),
            ("asia-emergency", "emergency_min_success", "emergency_p90_ms"),
        ):
            if _passes_replay_line(
                result,
                total_rounds=rounds,
                minimum_success=int(policy[minimum_key]),
                p90_limit_ms=policy[p90_key],
            ):
                tier = label
                break
    elif _passes_replay_line(
        result,
        total_rounds=rounds,
        minimum_success=int(policy["non_asia_min_success"]),
        p90_limit_ms=policy["non_asia_p90_ms"],
    ):
        tier = "non-asia-strict"
    result["policy_tier"] = tier
    result["qualified"] = bool(tier)
    result["elite_eligible"] = _passes_replay_line(
        result,
        total_rounds=rounds,
        minimum_success=int(policy["elite_min_success"]),
        p90_limit_ms=policy["elite_p90_ms"],
    )


def build_redacted_probe_results(
    *,
    summaries: Iterable[dict[str, Any]],
    total_rounds: int = 20,
    asia_thresholds: tuple[tuple[str, int, float | None], ...] | None = None,
    non_asia_minimum_success: int = 14,
    non_asia_p90_limit_ms: float | None = 2800.0,
    non_asia_min: int = 10,
    non_asia_max: int = 20,
    base_target: int = 80,
    max_nodes: int = 150,
    asia_emergency_max_count: int = 0,
    required_count: int | None = None,
    run_id: str | None = None,
    main_sha: str = "",
    source_sha256: str = "",
) -> dict[str, Any]:
    """Build the standalone, secret-free input consumed by policy replay."""

    all_summaries = list(summaries)
    ensure_policy_node_ids(all_summaries)
    replay_run_id = str(run_id or f"r1_{secrets.token_hex(16)}")
    if not re.fullmatch(r"r1_[0-9a-f]{32}", replay_run_id):
        raise ValueError("replay run_id must match r1_<32 lowercase hex characters>")
    policy = replay_policy_snapshot(
        total_rounds=total_rounds,
        asia_thresholds=asia_thresholds or DEFAULT_ASIA_THRESHOLDS,
        non_asia_minimum_success=non_asia_minimum_success,
        non_asia_p90_limit_ms=non_asia_p90_limit_ms,
        non_asia_min=non_asia_min,
        non_asia_max=non_asia_max,
        base_target=base_target,
        max_nodes=max_nodes,
        asia_emergency_max_count=asia_emergency_max_count,
        required_count=required_count,
    )
    results = [redacted_result(summary) for summary in all_summaries]
    for result in results:
        _annotate_replay_result(result, policy)
    results.sort(key=lambda item: str(item["node_id"]))
    return {
        "schema_version": 1,
        "kind": "cnb-redacted-probe-results",
        "run_id": replay_run_id,
        "main_sha": str(main_sha),
        "source_sha256": str(source_sha256),
        "redaction": {
            "node_id": "n1_random_96bit",
            "omitted": [
                "name",
                "type",
                "server",
                "port",
                "uuid",
                "password",
                "raw_errors",
                "round_samples",
            ],
        },
        "policy": policy,
        "result_count": len(results),
        "results": results,
    }


def build_failure_diagnostic(
    *,
    failure_kind: str,
    message: str,
    summaries: Iterable[dict[str, Any]],
    required_count: int,
    selected_count: int,
    previous_published_count: int = 0,
    previous_publish_baseline: int = 0,
    total_rounds: int = 20,
    asia_thresholds: tuple[tuple[str, int, float | None], ...] | None = None,
    non_asia_minimum_success: int = 14,
    non_asia_p90_limit_ms: float | None = 2800.0,
    non_asia_min: int = 10,
    non_asia_max: int = 20,
    base_target: int = 80,
    max_nodes: int = 150,
    asia_emergency_max_count: int = 0,
    replay_results_file: str | None = None,
    replay_run_id: str | None = None,
    main_sha: str = "",
    source_sha256: str = "",
) -> dict[str, Any]:
    """Create a small aggregate failure report with a replay-file reference."""

    all_summaries = list(summaries)
    matrix = threshold_matrix(
        all_summaries,
        total_rounds=total_rounds,
        asia_thresholds=asia_thresholds or DEFAULT_ASIA_THRESHOLDS,
        non_asia_minimum_success=non_asia_minimum_success,
        non_asia_p90_limit_ms=non_asia_p90_limit_ms,
        non_asia_max=non_asia_max,
        base_target=base_target,
        asia_emergency_max_count=asia_emergency_max_count,
    )
    policy = replay_policy_snapshot(
        total_rounds=total_rounds,
        asia_thresholds=asia_thresholds or DEFAULT_ASIA_THRESHOLDS,
        non_asia_minimum_success=non_asia_minimum_success,
        non_asia_p90_limit_ms=non_asia_p90_limit_ms,
        non_asia_min=non_asia_min,
        non_asia_max=non_asia_max,
        base_target=base_target,
        max_nodes=max_nodes,
        asia_emergency_max_count=asia_emergency_max_count,
        required_count=required_count,
    )
    payload: dict[str, Any] = {
        "schema_version": 2,
        "failure_kind": str(failure_kind),
        "message": str(message)[:500],
        "main_sha": str(main_sha),
        "source_sha256": str(source_sha256),
        "required_count": int(required_count),
        "selected_count": int(selected_count),
        "previous_published_count": int(previous_published_count),
        "previous_publish_baseline": int(previous_publish_baseline),
        "diagnostic": matrix,
    }
    if replay_results_file:
        if not re.fullmatch(r"r1_[0-9a-f]{32}", str(replay_run_id or "")):
            raise ValueError("a valid replay_run_id is required with replay_results_file")
        payload["replay"] = {
            "schema_version": 1,
            "run_id": str(replay_run_id),
            "results_file": Path(replay_results_file).name,
            "result_count": len(all_summaries),
            "policy": policy,
        }
    return payload


def write_failure_diagnostic(output_dir: str | Path, payload: dict[str, Any]) -> Path:
    """Atomically write ``failure.json`` and return its path."""

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "failure.json"
    return _write_json_atomic(destination, payload)


def _write_json_atomic(destination: Path, payload: dict[str, Any]) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination


def write_redacted_probe_results(
    output_dir: str | Path,
    payload: dict[str, Any],
    filename: str = REDACTED_RESULTS_FILENAME,
) -> Path:
    """Atomically write the standalone replay input next to ``failure.json``."""

    if Path(filename).name != filename or not filename.endswith(".json"):
        raise ValueError("replay results filename must be a plain .json basename")
    return _write_json_atomic(Path(output_dir) / filename, payload)
