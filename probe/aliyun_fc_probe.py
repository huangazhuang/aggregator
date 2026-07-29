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

import errno
import json
import os
import socket
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

MAX_ENDPOINTS = 2000
MAX_WORKERS = 200
DEFAULT_TIMEOUT = 3.0
REACHABLE_ERRNOS = {errno.ECONNREFUSED, errno.ECONNRESET, errno.ECONNABORTED}
REACHABLE_WINERRORS = {10053, 10054, 10061}


def classify_socket_error(exc: OSError) -> tuple[bool, str]:
    """Classify whether a failed connect still proves that the endpoint was reached."""

    if isinstance(exc, socket.timeout):
        return False, "timeout"
    if isinstance(exc, socket.gaierror):
        return False, "dns_error"

    code = getattr(exc, "errno", None)
    winerror = getattr(exc, "winerror", None)
    if isinstance(exc, (ConnectionRefusedError, ConnectionResetError)):
        return True, "rejected"
    if code in REACHABLE_ERRNOS or winerror in REACHABLE_WINERRORS:
        return True, "rejected"
    if code in {errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ETIMEDOUT} or winerror in {
        10051,
        10060,
        10065,
    }:
        return False, "unreachable"
    return False, f"os_error_{code if code is not None else 'unknown'}"


def _probe_endpoint(hostport: str, timeout: float) -> dict:
    # 国内机房 -> 目标入口的 TCP 握手。成功、RST 或明确拒绝都证明路径已到达；
    # 超时、DNS、无路由和未知 OSError 不能证明可达，按失败处理。
    host, _, port = hostport.rpartition(":")
    try:
        port = int(port)
    except ValueError:
        return {"ok": False, "classification": "invalid_endpoint"}
    host = host.strip("[]")
    if not host or port <= 0 or port > 65535:
        return {"ok": False, "classification": "invalid_endpoint"}
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "classification": "connected"}
    except OSError as exc:
        ok, classification = classify_socket_error(exc)
        return {"ok": ok, "classification": classification}


def _tcp_ok(hostport: str, timeout: float) -> bool:
    """Backward-compatible boolean helper used by local callers."""

    return bool(_probe_endpoint(hostport, timeout)["ok"])


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

    details = {}
    if endpoints:
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(endpoints))) as pool:
            for ep, detail in zip(endpoints, pool.map(lambda e: _probe_endpoint(e, timeout), endpoints)):
                details[ep] = detail

    result = {endpoint: bool(detail["ok"]) for endpoint, detail in details.items()}
    classifications = Counter(str(detail["classification"]) for detail in details.values())
    return {
        "ok": result,
        "results": details,
        "classifications": dict(sorted(classifications.items())),
        "tested": len(result),
        "reachable": sum(1 for value in result.values() if value),
    }


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
