"""脱敏的 CNB 节点测速诊断辅助函数。

这些函数只处理已经汇总的测速结果，不接触运行时 Mihomo YAML，方便在
发布门槛失败前生成可回看的统计。诊断中的节点标识使用短哈希，避免把
节点配置或可能意外写进名称的凭据发布出去。
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable


def _success_count(summary: dict[str, Any]) -> int:
    try:
        return max(int(summary.get("success_count", 0)), 0)
    except (TypeError, ValueError):
        return 0


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
    asia_thresholds: tuple[tuple[str, int, float | None], ...] = (
        ("strict", 14, 2800.0),
        ("fallback", 12, 2800.0),
        ("emergency", 10, 2800.0),
        ("elite", 18, 2000.0),
    ),
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


def _safe_node_id(summary: dict[str, Any]) -> str:
    """Return a deterministic, non-reversible-enough short diagnostic ID."""

    material = "|".join(
        str(summary.get(key, ""))
        for key in ("name", "type", "server", "port")
    )
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16]


def redacted_result(summary: dict[str, Any]) -> dict[str, Any]:
    """Keep useful metrics while omitting server, port and raw error text."""

    result: dict[str, Any] = {
        "node_id": _safe_node_id(summary),
        "type": str(summary.get("type", "")),
        "preferred_asia": bool(summary.get("preferred_asia")),
        "attempts": int(summary.get("attempts", 0) or 0),
        "success_count": _success_count(summary),
        "success_rate": float(summary.get("success_rate", 0.0) or 0.0),
        "p90_delay_ms": summary.get("p90_delay_ms"),
        "median_delay_ms": summary.get("median_delay_ms"),
        "jitter_ms": summary.get("jitter_ms"),
        "drop_reason": str(summary.get("drop_reason", "")),
    }
    if "qualification_tier" in summary:
        result["qualification_tier"] = str(summary.get("qualification_tier") or "")
    return result


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
    non_asia_max: int = 20,
    base_target: int = 80,
    asia_emergency_max_count: int = 0,
    main_sha: str = "",
    source_sha256: str = "",
) -> dict[str, Any]:
    """Create an aggregate-only failure report."""

    all_summaries = list(summaries)
    matrix = threshold_matrix(
        all_summaries,
        total_rounds=total_rounds,
        asia_thresholds=asia_thresholds
        or (
            ("strict", 14, 2800.0),
            ("fallback", 12, 2800.0),
            ("emergency", 10, 2800.0),
            ("elite", 18, 2000.0),
        ),
        non_asia_minimum_success=non_asia_minimum_success,
        non_asia_p90_limit_ms=non_asia_p90_limit_ms,
        non_asia_max=non_asia_max,
        base_target=base_target,
        asia_emergency_max_count=asia_emergency_max_count,
    )
    return {
        "schema_version": 1,
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


def write_failure_diagnostic(output_dir: str | Path, payload: dict[str, Any]) -> Path:
    """Atomically write ``failure.json`` and return its path."""

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "failure.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
