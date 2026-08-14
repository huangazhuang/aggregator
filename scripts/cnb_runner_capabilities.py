"""Emit secret-free diagnostics for CNB's managed Docker service.

The guarded GMGN V2 probe needs a child container with working Linux network
namespace primitives.  CNB's Docker API can accept ``--cap-add`` while the
runtime still removes the requested capabilities, so inspecting HostConfig is
not enough.  This module compares the requested settings with the effective
capability set and also checks whether an unprivileged user/network namespace
is available as a possible non-privileged backend.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Sequence


MODULE = "scripts.cnb_runner_capabilities"
_SAFE_TOKEN_RE = re.compile(r"^[0-9a-f]{8,16}$")
_STATUS_FIELDS = frozenset(
    {
        "CapInh",
        "CapPrm",
        "CapEff",
        "CapBnd",
        "CapAmb",
        "NoNewPrivs",
        "Seccomp",
        "Seccomp_filters",
    }
)
_FORBIDDEN_CHILD_ENV = frozenset(
    {
        "CNB_TOKEN",
        "GITHUB_TOKEN",
        "GIT_ASKPASS",
        "GMGN_IDENTITY_HMAC_KEY",
        "GMGN_IDENTITY_KEY_VERSION",
        "GMGN_IDENTITY_EPOCH",
    }
)

# Deliberately exclude --privileged, seccomp overrides and broad capability
# grants.  These cases only compare the exact capabilities required by the
# existing fail-closed Linux namespace backend.
DIAGNOSTIC_CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("default", ()),
    ("net-admin", ("--cap-add", "NET_ADMIN")),
    (
        "net-admin-sys-admin",
        ("--cap-add", "NET_ADMIN", "--cap-add", "SYS_ADMIN"),
    ),
    (
        "net-admin-sys-admin-userns-host",
        (
            "--cap-add",
            "NET_ADMIN",
            "--cap-add",
            "SYS_ADMIN",
            "--userns",
            "host",
        ),
    ),
)


def parse_proc_status(text: str) -> dict[str, str]:
    """Return only capability/sandbox fields from ``/proc/self/status``."""

    result: dict[str, str] = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key in _STATUS_FIELDS:
            result[key] = value.strip()
    return result


def _safe_text(value: str, *, limit: int = 400) -> str:
    normalized = " ".join(value.split())
    printable = "".join(character if 32 <= ord(character) < 127 else "?" for character in normalized)
    return printable[:limit]


def _read_optional_switch(path: str) -> str | None:
    try:
        value = Path(path).read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value if re.fullmatch(r"[0-9]+", value) else "unreadable"


def _run(
    command: Sequence[str],
    *,
    timeout: float = 120.0,
) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", _safe_text(str(exc))
    return completed.returncode, completed.stdout, completed.stderr


def _json_from_output(value: str) -> dict[str, Any] | None:
    for line in reversed(value.splitlines()):
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _userns_child() -> int:
    from scripts.probe_network_guard_linux import (
        effective_cap_net_admin,
        effective_cap_sys_admin,
    )

    try:
        status_text = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        status_text = ""
    link_returncode, _stdout, link_stderr = _run(
        ("ip", "link", "set", "lo", "up"), timeout=10.0
    )
    report = {
        "root_mapped": getattr(os, "geteuid", lambda: -1)() == 0,
        "status": parse_proc_status(status_text),
        "cap_net_admin": effective_cap_net_admin(status_text),
        "cap_sys_admin": effective_cap_sys_admin(status_text),
        "loopback_up": link_returncode == 0,
        "loopback_error": _safe_text(link_stderr),
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["cap_net_admin"] and report["loopback_up"] else 1


def _unprivileged_userns_probe() -> dict[str, Any]:
    executable = shutil.which("unshare")
    if executable is None:
        return {"available": False, "ok": False, "error": "unshare is unavailable"}
    returncode, stdout, stderr = _run(
        (
            executable,
            "--user",
            "--map-root-user",
            "--net",
            sys.executable,
            "-m",
            MODULE,
            "userns-child",
        ),
        timeout=20.0,
    )
    return {
        "available": True,
        "ok": returncode == 0,
        "returncode": returncode,
        "report": _json_from_output(stdout),
        "error": _safe_text(stderr),
    }


def _inside(token: str) -> int:
    from scripts.probe_network_guard_linux import (
        LinuxGuardError,
        exercise_netns_mutation,
        preflight_environment,
    )

    try:
        status_text = Path("/proc/self/status").read_text(encoding="ascii")
    except OSError:
        status_text = ""
    preflight: dict[str, Any]
    try:
        capabilities = preflight_environment()
        smoke = exercise_netns_mutation(f"gmgnv2-cap-{token}")
        preflight = {"ok": True, "capabilities": capabilities, **smoke}
    except LinuxGuardError as exc:
        preflight = {"ok": False, "error": _safe_text(str(exc))}

    forbidden = sorted(name for name in os.environ if name in _FORBIDDEN_CHILD_ENV)
    report = {
        "uid": getattr(os, "getuid", lambda: -1)(),
        "euid": getattr(os, "geteuid", lambda: -1)(),
        "status": parse_proc_status(status_text),
        "kernel_userns": {
            "unprivileged_userns_clone": _read_optional_switch(
                "/proc/sys/kernel/unprivileged_userns_clone"
            ),
            "max_user_namespaces": _read_optional_switch(
                "/proc/sys/user/max_user_namespaces"
            ),
        },
        "preflight": preflight,
        "unprivileged_userns": _unprivileged_userns_probe(),
        "forbidden_environment_names": forbidden,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


def _docker_value(template: str) -> dict[str, Any]:
    returncode, stdout, stderr = _run(("docker", "info", "--format", template))
    return {
        "ok": returncode == 0,
        "value": stdout.strip() if returncode == 0 else "",
        "error": _safe_text(stderr),
    }


def _inspect_case(container: str) -> dict[str, Any]:
    template = (
        "{{json .HostConfig.CapAdd}}\t{{.HostConfig.UsernsMode}}\t"
        "{{.HostConfig.NetworkMode}}\t{{json .HostConfig.SecurityOpt}}"
    )
    returncode, stdout, stderr = _run(
        ("docker", "inspect", "--format", template, container)
    )
    if returncode != 0:
        return {"ok": False, "error": _safe_text(stderr)}
    fields = stdout.rstrip("\r\n").split("\t")
    if len(fields) != 4:
        return {"ok": False, "error": "docker inspect returned unexpected fields"}
    return {
        "ok": True,
        "cap_add": fields[0],
        "userns_mode": fields[1],
        "network_mode": fields[2],
        "security_opt": fields[3],
    }


def _child_environment_is_clean(container: str) -> dict[str, Any]:
    returncode, stdout, stderr = _run(
        (
            "docker",
            "inspect",
            "--format",
            "{{range .Config.Env}}{{println .}}{{end}}",
            container,
        )
    )
    if returncode != 0:
        return {"ok": False, "error": _safe_text(stderr)}
    names = {
        line.partition("=")[0]
        for line in stdout.splitlines()
        if "=" in line
    }
    forbidden = sorted(names & _FORBIDDEN_CHILD_ENV)
    return {"ok": not forbidden, "forbidden_names": forbidden}


def _run_case(
    *, image: str, token: str, label: str, options: Sequence[str]
) -> dict[str, Any]:
    container = f"cnb-cap-{token}-{label}"
    create_command = [
        "docker",
        "create",
        "--name",
        container,
        *options,
        image,
        "python",
        "-m",
        MODULE,
        "inside",
        "--token",
        token,
    ]
    create_returncode, create_stdout, create_stderr = _run(create_command)
    result: dict[str, Any] = {
        "label": label,
        "requested_options": list(options),
        "create": {
            "ok": create_returncode == 0,
            "error": _safe_text(create_stderr),
        },
    }
    if create_returncode != 0:
        return result
    try:
        result["inspect"] = _inspect_case(container)
        result["environment"] = _child_environment_is_clean(container)
        start_returncode, start_stdout, start_stderr = _run(
            ("docker", "start", "--attach", container), timeout=180.0
        )
        result["start"] = {
            "ok": start_returncode == 0,
            "returncode": start_returncode,
            "error": _safe_text(start_stderr),
        }
        result["inside"] = _json_from_output(start_stdout)
        state_returncode, state_stdout, state_stderr = _run(
            (
                "docker",
                "inspect",
                "--format",
                "{{.State.ExitCode}}\t{{json .State.Error}}",
                container,
            )
        )
        result["state"] = {
            "ok": state_returncode == 0,
            "value": state_stdout.strip() if state_returncode == 0 else "",
            "error": _safe_text(state_stderr),
        }
    finally:
        cleanup_returncode, _cleanup_stdout, cleanup_stderr = _run(
            ("docker", "rm", "-f", container), timeout=30.0
        )
        result["cleanup"] = {
            "ok": cleanup_returncode == 0,
            "error": _safe_text(cleanup_stderr),
        }
    return result


def _outer(image: str, seed: str) -> int:
    token = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]
    version_returncode, version_stdout, version_stderr = _run(
        (
            "docker",
            "version",
            "--format",
            "{{.Client.Version}}\t{{.Server.Version}}\t{{.Server.Os}}\t{{.Server.Arch}}",
        )
    )
    cases = [
        _run_case(image=image, token=token, label=label, options=options)
        for label, options in DIAGNOSTIC_CASES
    ]

    exact_case = next(
        (item for item in cases if item["label"] == "net-admin-sys-admin"), None
    )
    userns_host_case = next(
        (
            item
            for item in cases
            if item["label"] == "net-admin-sys-admin-userns-host"
        ),
        None,
    )

    def exact_supported(item: dict[str, Any] | None) -> bool:
        if not isinstance(item, dict):
            return False
        inside = item.get("inside")
        if not isinstance(inside, dict):
            return False
        preflight = inside.get("preflight")
        return isinstance(preflight, dict) and preflight.get("ok") is True

    def userns_supported(item: dict[str, Any]) -> bool:
        inside = item.get("inside")
        if not isinstance(inside, dict):
            return False
        probe = inside.get("unprivileged_userns")
        return isinstance(probe, dict) and probe.get("ok") is True

    report = {
        "kind": "cnb-managed-docker-capability-diagnostic",
        "schema_version": 1,
        "docker": {
            "version": {
                "ok": version_returncode == 0,
                "value": version_stdout.strip() if version_returncode == 0 else "",
                "error": _safe_text(version_stderr),
            },
            "security_options": _docker_value("{{json .SecurityOptions}}"),
            "storage_driver": _docker_value("{{.Driver}}"),
            "cgroup_version": _docker_value("{{.CgroupVersion}}"),
            "default_runtime": _docker_value("{{.DefaultRuntime}}"),
            "runtimes": _docker_value("{{json .Runtimes}}"),
            "kernel_version": _docker_value("{{.KernelVersion}}"),
        },
        "cases": cases,
        "conclusion": {
            "exact_linux_netns_backend_supported": exact_supported(exact_case),
            "userns_host_restores_exact_backend": exact_supported(userns_host_case),
            "unprivileged_user_netns_available": any(
                userns_supported(item) for item in cases
            ),
        },
    }
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    outer = commands.add_parser("outer")
    outer.add_argument("--image", required=True)
    outer.add_argument("--seed", default=os.environ.get("CNB_BUILD_ID", "cnb-build"))

    inside = commands.add_parser("inside")
    inside.add_argument("--token", required=True)

    commands.add_parser("userns-child")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "outer":
        return _outer(args.image, args.seed)
    if args.command == "inside":
        if _SAFE_TOKEN_RE.fullmatch(args.token) is None:
            raise SystemExit("diagnostic token is invalid")
        return _inside(args.token)
    if args.command == "userns-child":
        return _userns_child()
    raise SystemExit("unsupported diagnostic command")


if __name__ == "__main__":
    raise SystemExit(main())
