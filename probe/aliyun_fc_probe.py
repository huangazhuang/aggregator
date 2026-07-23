# -*- coding: utf-8 -*-
"""阿里云函数计算 (FC) 探针: 从国内机房视角批量测 TCP 可达性.

部署到国内区域(如杭州)后, GitHub Actions 每轮把节点的 host:port 批量 POST
过来, 本函数并发做 TCP 握手, 返回每个 endpoint 从国内是否可达 —— 被 GFW 拦的
入口在这里会 connect 超时, 从而在云端就被剔除, 无需任何本地组件.

请求 (HTTP trigger, POST):
    Header:  X-Probe-Token: <与环境变量 PROBE_TOKEN 一致>
    Body:    {"endpoints": ["1.2.3.4:443", "example.com:8443", ...],
              "timeout": 3.0}         # 可选, 单位秒, 默认 3
响应:
    {"ok": {"1.2.3.4:443": true, "example.com:8443": false, ...},
     "tested": 500, "reachable": 137}

环境变量:
    PROBE_TOKEN   必填, 调用方需在 X-Probe-Token 头带上同值做鉴权

FC 配置建议: Python 3.x runtime, 内存 512MB, 超时 120s, HTTP 触发器(匿名或
签名均可, 这里用自带 token 头做二次校验).
"""

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor

MAX_ENDPOINTS = 2000
MAX_WORKERS = 200
DEFAULT_TIMEOUT = 3.0


def _tcp_ok(hostport: str, timeout: float) -> bool:
    # 国内机房 -> 目标入口的 TCP 握手. 成功 / 被 RST / 拒绝 都算"入口未被墙";
    # 只有 SYN 无响应(GFW 丢包)导致的 socket.timeout 才判为不可达.
    host, _, port = hostport.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return False
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except socket.timeout:
        return False
    except OSError:
        # ConnectionRefused / Reset / unreachable: 握手已抵达目标, 入口可达
        return True


def _run(body: dict) -> dict:
    endpoints = body.get("endpoints") or []
    if not isinstance(endpoints, list):
        endpoints = []
    endpoints = [str(e) for e in endpoints][:MAX_ENDPOINTS]

    try:
        timeout = float(body.get("timeout", DEFAULT_TIMEOUT))
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    timeout = max(0.5, min(timeout, 10.0))

    result = {}
    if endpoints:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(endpoints))) as pool:
            for ep, ok in zip(endpoints, pool.map(lambda e: _tcp_ok(e, timeout), endpoints)):
                result[ep] = ok

    return {"ok": result, "tested": len(result), "reachable": sum(1 for v in result.values() if v)}


# ---- 阿里云 FC HTTP 函数入口 (Python runtime) ----
def handler(environ, start_response):
    token = os.environ.get("PROBE_TOKEN", "")
    got = environ.get("HTTP_X_PROBE_TOKEN", "")
    if not token or got != token:
        start_response("401 Unauthorized", [("Content-Type", "application/json")])
        return [b'{"error":"unauthorized"}']

    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    raw = environ["wsgi.input"].read(length) if length else b"{}"

    try:
        body = json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        start_response("400 Bad Request", [("Content-Type", "application/json")])
        return [b'{"error":"bad json"}']

    payload = json.dumps(_run(body)).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json")])
    return [payload]


# 本地自测: python probe/aliyun_fc_probe.py 1.1.1.1:443 8.8.8.8:443
if __name__ == "__main__":
    import sys
    out = _run({"endpoints": sys.argv[1:], "timeout": 3.0})
    print(json.dumps(out, indent=2))
