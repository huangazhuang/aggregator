#!/usr/bin/env python3
"""Finalize CNB status and README files before publishing the output branch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--profile-url", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    public = Path(args.output_dir)
    status_path = public / "status.json"
    status = json.loads(status_path.read_text(encoding="utf-8"))
    status["profile_url"] = args.profile_url
    status_path.write_text(
        json.dumps(status, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    region = ", ".join(
        value
        for value in (
            status.get("runner_country"),
            status.get("runner_region"),
            status.get("runner_city"),
        )
        if value
    )
    if status.get("full_scan"):
        probe_summary = (
            f"全量测速：全部 {status.get('candidate_count', 0)} 个节点先测 "
            f"{status.get('preliminary_rounds', 0)} 轮，再补足到 {status.get('total_rounds', 0)} 轮"
        )
        selection_summary = (
            f"本次从 {status['source_count']} 个节点全部复测，"
            f"其中 {status.get('qualified_count', 0)} 个达到稳定门槛，"
            f"最终动态发布 {status['published_count']} 个。"
        )
    else:
        probe_summary = (
            f"两阶段测速：全量 {status.get('preliminary_rounds', 0)} 轮，"
            f"{status.get('candidate_count', 0)} 个候选补足到 {status.get('total_rounds', 0)} 轮"
        )
        selection_summary = (
            f"本次从 {status['source_count']} 个节点中选出 {status.get('candidate_count', 0)} 个复测候选，"
            f"其中 {status.get('qualified_count', 0)} 个达到稳定门槛，"
            f"最终动态发布 {status['published_count']} 个。"
        )
    metadata_lines = [
        f"源运行时间：{status.get('source_run_at') or '未知'}",
        f"源文件 SHA-256：`{status.get('source_sha256') or '未知'}`",
        f"主分支 SHA：`{status.get('main_sha') or '未知'}`",
        f"CNB 公网出口：{status.get('runner_public_ip') or '查询失败'}"
        + (f"（{region}）" if region else ""),
        probe_summary,
        f"稳定门槛：成功率至少 {float(status.get('minimum_success_rate', 0)):.0%}，"
        f"P90 不高于 {status.get('max_qualified_p90_ms', 0)} ms",
        f"发布构成：亚洲 {status.get('published_asia_count', 0)} 个，"
        f"非亚洲 {status.get('published_non_asia_count', 0)} 个",
        f"亚洲分级：严格 {status.get('strict_qualified_asia_count', 0)} 个，"
        f"12/20 兜底 {status.get('asia_fallback_count', 0)} 个，"
        f"10/20 应急 {status.get('asia_emergency_count', 0)} 个",
    ]
    (public / "README.md").write_text(
        "# 中国大陆 20 轮稳定性实测 Clash 订阅\n\n"
        f"订阅地址：{args.profile_url}\n\n"
        f"{selection_summary}\n\n"
        + "\n".join(f"- {line}" for line in metadata_lines)
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
