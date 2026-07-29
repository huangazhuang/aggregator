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
    metadata_lines = [
        f"源运行时间：{status.get('source_run_at') or '未知'}",
        f"源文件 SHA-256：`{status.get('source_sha256') or '未知'}`",
        f"主分支 SHA：`{status.get('main_sha') or '未知'}`",
        f"CNB 公网出口：{status.get('runner_public_ip') or '查询失败'}"
        + (f"（{region}）" if region else ""),
    ]
    (public / "README.md").write_text(
        "# 中国大陆实测 Clash 订阅\n\n"
        f"订阅地址：{args.profile_url}\n\n"
        f"本次从 {status['source_count']} 个节点中实测通过 {status['passed_count']} 个，"
        f"发布 {status['published_count']} 个。\n\n"
        + "\n".join(f"- {line}" for line in metadata_lines)
        + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
