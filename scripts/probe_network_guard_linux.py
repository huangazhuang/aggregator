#!/usr/bin/env python3
"""Fail-closed Linux network-namespace backend for GMGN V2 probes.

The untrusted probe process and the Mihomo process that it starts must run via
``LinuxGuardLease.wrap_command`` (or the ``launch`` CLI).  The namespace only
permits the controller loopback ports and the exact public proxy endpoints
that C2 resolved and pinned.  Everything else is rejected by both namespace
and host-forward rules.

This module deliberately keeps the detailed Linux evidence separate from the
small C2 evidence projection.  ``evidence["guard_evidence"]`` is accepted by
``scripts.probe_network_guard.validate_guard_evidence`` without relaxing that
existing cross-layer contract.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from scripts.gmgn_measurement import candidate_ids_sha256
from scripts.probe_network_guard import (
    NETWORK_GUARD_POLICY_VERSION,
    RESOLVER_POLICY_VERSION,
    validate_guard_evidence,
)


BACKEND = "netns-deny-v1"
BACKEND_VERSION = "gmgn-linux-netns-v1"
EVIDENCE_KIND = "gmgn-linux-network-guard-evidence"
EVIDENCE_SCHEMA_VERSION = 1
STATE_KIND = "gmgn-linux-network-guard-state"
STATE_SCHEMA_VERSION = 1
CAP_NET_ADMIN = 12
CAP_SYS_ADMIN = 21

_HEX_32_RE = re.compile(r"^[0-9a-f]{32}$")
_SAFE_NAMESPACE_RE = re.compile(r"^gmgnv2-s([0-3])-([0-9a-f]{8})$")
_SAFE_SMOKE_NAMESPACE_RE = re.compile(r"^gmgnv2-cap-[0-9a-f]{8,16}$")
_SAFE_VETH_RE = re.compile(r"^g2[hn][0-3][0-9a-f]{8}$")
_SAFE_CHAIN_RE = re.compile(r"^G2[FORI][0-9A-F]{8}$")

# Explicitly blocked even if a future resolver implementation accidentally
# becomes more permissive.  Metadata endpoints that sit inside these ranges
# are repeated in the policy fingerprint below via METADATA_*.
FORBIDDEN_IPV4 = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
)
FORBIDDEN_IPV6 = (
    "::/96",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/32",
    "2001:10::/28",
    "2001:20::/28",
    "2001:db8::/32",
    "2002::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)
METADATA_IPV4 = (
    "100.100.100.200/32",  # Alibaba Cloud
    "168.63.129.16/32",  # Azure WireServer
    "169.254.0.23/32",  # Tencent Cloud
    "169.254.169.254/32",  # AWS/GCP/OpenStack and compatible services
    "169.254.170.2/32",  # AWS ECS task metadata
)
METADATA_IPV6 = ("fd00:ec2::254/128",)


class LinuxGuardError(RuntimeError):
    """The Linux guard could not prove that isolation is active."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


CommandRunner = Callable[..., CommandResult | subprocess.CompletedProcess[str]]


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _default_runner(
    command: Sequence[str], *, check: bool = True, capture_output: bool = True
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        list(command),
        check=False,
        text=True,
        capture_output=capture_output,
    )
    if check and completed.returncode != 0:
        # Do not echo command arguments: firewall commands contain private
        # fixed proxy endpoints.
        raise LinuxGuardError(
            f"network-guard command failed with exit code {completed.returncode}"
        )
    return completed


def _run(
    runner: CommandRunner,
    command: Sequence[str],
    *,
    check: bool = True,
    capture_output: bool = True,
) -> CommandResult | subprocess.CompletedProcess[str]:
    try:
        result = runner(list(command), check=check, capture_output=capture_output)
    except TypeError:
        # Small mock runners may intentionally expose only ``check``.
        result = runner(list(command), check=check)
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinuxGuardError("network-guard command could not be executed") from exc
    returncode = int(getattr(result, "returncode", 0))
    if check and returncode != 0:
        raise LinuxGuardError(
            f"network-guard command failed with exit code {returncode}"
        )
    return result


def _command_available(name: str, which: Callable[[str], str | None]) -> bool:
    value = which(name)
    return isinstance(value, str) and bool(value.strip())


def _effective_capability(status_text: str, bit: int) -> bool:
    match = re.search(r"(?m)^CapEff:\s*([0-9a-fA-F]+)\s*$", status_text)
    if match is None:
        return False
    try:
        mask = int(match.group(1), 16)
    except ValueError:
        return False
    return bool(mask & (1 << bit))


def effective_cap_net_admin(status_text: str) -> bool:
    """Return whether Linux CapEff contains CAP_NET_ADMIN."""

    return _effective_capability(status_text, CAP_NET_ADMIN)


def effective_cap_sys_admin(status_text: str) -> bool:
    """Return whether Linux CapEff contains CAP_SYS_ADMIN for setns/netns."""

    return _effective_capability(status_text, CAP_SYS_ADMIN)


def _read_kernel_switch(
    path: str, *, read_text: Callable[[str], str]
) -> bool:
    try:
        value = read_text(path).strip()
    except (OSError, UnicodeError):
        return False
    return value == "1"


def preflight_linux_backend(
    *,
    runner: CommandRunner = _default_runner,
    system: Callable[[], str] = platform.system,
    geteuid: Callable[[], int] | None = getattr(os, "geteuid", None),
    which: Callable[[str], str | None] = shutil.which,
    read_text: Callable[[str], str] = _read_text,
) -> dict[str, Any]:
    """Prove the runner has the Linux isolation primitives; never degrade."""

    if system() != "Linux":
        raise LinuxGuardError("Linux network namespaces are required")
    if geteuid is None or geteuid() != 0:
        raise LinuxGuardError("Linux network guard requires root")
    try:
        status = read_text("/proc/self/status")
    except (OSError, UnicodeError) as exc:
        raise LinuxGuardError("cannot inspect Linux process capabilities") from exc
    if not effective_cap_net_admin(status):
        raise LinuxGuardError("CAP_NET_ADMIN is required")
    if not effective_cap_sys_admin(status):
        raise LinuxGuardError("CAP_SYS_ADMIN is required for network namespaces")

    required = ("ip", "iptables", "ip6tables")
    missing = [name for name in required if not _command_available(name, which)]
    if missing:
        raise LinuxGuardError("required Linux network-guard tools are unavailable")

    checks = (
        ("ip", "netns", "list"),
        ("iptables", "-w", "5", "-L"),
        ("iptables", "-w", "5", "-t", "nat", "-L"),
        ("ip6tables", "-w", "5", "-L"),
    )
    for command in checks:
        _run(runner, command)

    ipv4_forwarding = _read_kernel_switch(
        "/proc/sys/net/ipv4/ip_forward", read_text=read_text
    )
    ipv6_forwarding = _read_kernel_switch(
        "/proc/sys/net/ipv6/conf/all/forwarding", read_text=read_text
    )
    if not ipv4_forwarding:
        raise LinuxGuardError("host IPv4 forwarding is disabled")
    return {
        "linux": True,
        "root": True,
        "cap_net_admin": True,
        "cap_sys_admin": True,
        "ip_netns": True,
        "iptables": True,
        "ip6tables": True,
        "ipv4_forwarding": True,
        "ipv6_forwarding": ipv6_forwarding,
    }


def exercise_netns_mutation(
    namespace: str, *, runner: CommandRunner = _default_runner
) -> dict[str, Any]:
    """Prove the container can create and delete a uniquely scoped netns."""

    if not isinstance(namespace, str) or not _SAFE_SMOKE_NAMESPACE_RE.fullmatch(
        namespace
    ):
        raise LinuxGuardError("capability smoke namespace is unsafe")
    created = False
    try:
        _run(runner, ("ip", "netns", "add", namespace))
        created = True
    finally:
        if created:
            _run(runner, ("ip", "netns", "delete", namespace))
    return {
        "netns_mutation_smoke": True,
        "namespace_sha256": hashlib.sha256(namespace.encode("utf-8")).hexdigest(),
    }


def _normalize_networks(values: Iterable[str], *, version: int) -> tuple[str, ...]:
    networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    for original in values:
        try:
            network = ipaddress.ip_network(str(original), strict=False)
        except ValueError as exc:
            raise LinuxGuardError("runner network evidence is malformed") from exc
        if network.version != version or network.prefixlen == 0:
            continue
        networks.add(network)
    return tuple(
        str(network)
        for network in sorted(networks, key=lambda item: (int(item.network_address), item.prefixlen))
    )


def _parse_routes(raw: str, *, version: int) -> tuple[str, ...]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise LinuxGuardError("runner route evidence is not valid JSON") from exc
    if not isinstance(value, list):
        raise LinuxGuardError("runner route evidence must be a JSON list")
    networks: list[str] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise LinuxGuardError("runner route evidence entry is malformed")
        destination = item.get("dst")
        route_type = str(item.get("type", "unicast"))
        if destination in (None, "default") or route_type not in {"unicast", "local"}:
            continue
        try:
            network = ipaddress.ip_network(str(destination), strict=False)
        except ValueError:
            continue
        if network.version != version or network.prefixlen == 0:
            continue
        if network.is_loopback:
            continue
        networks.append(str(network))
    return _normalize_networks(networks, version=version)


def discover_runner_networks(
    runner: CommandRunner = _default_runner,
) -> dict[str, tuple[str, ...]]:
    """Capture non-default host routes so the namespace cannot reach CI LANs."""

    ipv4_result = _run(runner, ("ip", "-j", "route", "show", "table", "all"))
    ipv6_result = _run(
        runner, ("ip", "-j", "-6", "route", "show", "table", "all")
    )
    return {
        "ipv4": _parse_routes(str(getattr(ipv4_result, "stdout", "")), version=4),
        "ipv6": _parse_routes(str(getattr(ipv6_result, "stdout", "")), version=6),
    }


def _public_ip(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise LinuxGuardError("fixed target contains an invalid IP address") from exc
    if (
        not address.is_global
        or address.is_loopback
        or address.is_link_local
        or address.is_private
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise LinuxGuardError("fixed target contains a forbidden non-public address")
    return address


def _port(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise LinuxGuardError("fixed target port is invalid")
    return value


def normalize_pinned_targets(
    pinned: Mapping[str, Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], str, str]:
    """Validate C2 pinning output and return deterministic endpoint rules."""

    if not isinstance(pinned, Mapping) or not pinned:
        raise LinuxGuardError("pinned candidate mapping is empty")
    candidate_ids: list[str] = []
    endpoints: list[dict[str, Any]] = []
    for candidate_id, raw_record in pinned.items():
        if not isinstance(candidate_id, str) or not candidate_id.strip():
            raise LinuxGuardError("pinned candidate ID is invalid")
        if candidate_id != candidate_id.strip() or candidate_id in candidate_ids:
            raise LinuxGuardError("pinned candidate IDs are non-canonical or duplicated")
        candidate_ids.append(candidate_id)
        if not isinstance(raw_record, Mapping):
            raise LinuxGuardError("pinned target record is malformed")
        if frozenset(raw_record) != {
            "server",
            "port",
            "addresses",
            "resolver_policy_version",
        }:
            raise LinuxGuardError("pinned target record fields are incomplete or unexpected")
        if raw_record["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
            raise LinuxGuardError("pinned target resolver policy version mismatch")
        port = _port(raw_record["port"])
        addresses = raw_record["addresses"]
        if not isinstance(addresses, list) or not addresses:
            raise LinuxGuardError("pinned target address list is empty")
        normalized_addresses = sorted({_public_ip(value) for value in addresses}, key=lambda a: (a.version, int(a)))
        if len(normalized_addresses) != len(addresses):
            raise LinuxGuardError("pinned target address list is duplicated or non-canonical")
        for address in normalized_addresses:
            if str(address) not in addresses:
                raise LinuxGuardError("pinned target address list is non-canonical")
            endpoints.append(
                {
                    "candidate_id": candidate_id,
                    "address": str(address),
                    "port": port,
                    "family": address.version,
                    "protocols": ("tcp", "udp"),
                }
            )
    candidate_hash = candidate_ids_sha256(sorted(candidate_ids))
    fixed_hash = _sha256(
        [
            {
                "candidate_id": item["candidate_id"],
                "address": item["address"],
                "port": item["port"],
            }
            for item in sorted(
                endpoints,
                key=lambda item: (
                    item["candidate_id"],
                    item["family"],
                    ipaddress.ip_address(item["address"]),
                    item["port"],
                ),
            )
        ]
    )
    return endpoints, candidate_hash, fixed_hash


def normalize_auxiliary_targets(
    auxiliary_targets: Mapping[str, Mapping[str, Any]]
    | Sequence[Mapping[str, Any]]
    | None,
) -> tuple[list[dict[str, Any]], str]:
    """Validate fixed public control/canary/egress endpoints.

    Auxiliary endpoints are deliberately outside the shard candidate binding:
    adding or rotating a control endpoint must never alter
    ``candidate_ids_sha256``.  Their complete, non-public binding is covered by
    a separate hash in state and detailed guard evidence.
    """

    if auxiliary_targets is None:
        auxiliary_targets = {}
    materialized: list[Mapping[str, Any]]
    if isinstance(auxiliary_targets, Mapping):
        materialized = []
        for target_id, raw_record in auxiliary_targets.items():
            if not isinstance(raw_record, Mapping) or frozenset(raw_record) not in (
                {"server", "port", "addresses", "resolver_policy_version"},
                {
                    "server",
                    "port",
                    "addresses",
                    "resolver_policy_version",
                    "protocols",
                },
            ):
                raise LinuxGuardError(
                    "auxiliary target fields are incomplete or unexpected"
                )
            if raw_record["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
                raise LinuxGuardError(
                    "auxiliary target resolver policy version mismatch"
                )
            server = raw_record["server"]
            if not isinstance(server, str) or not server.strip() or server != server.strip():
                raise LinuxGuardError("auxiliary target server is invalid")
            item = {
                "target_id": target_id,
                "port": raw_record["port"],
                "addresses": raw_record["addresses"],
            }
            if "protocols" in raw_record:
                item["protocols"] = raw_record["protocols"]
            materialized.append(item)
    elif isinstance(auxiliary_targets, Sequence) and not isinstance(
        auxiliary_targets, (str, bytes, bytearray)
    ):
        materialized = list(auxiliary_targets)
    else:
        raise LinuxGuardError("auxiliary targets must be a mapping or sequence")
    endpoints: list[dict[str, Any]] = []
    target_ids: set[str] = set()
    for raw_record in materialized:
        if not isinstance(raw_record, Mapping) or frozenset(raw_record) not in (
            {"target_id", "port", "addresses"},
            {"target_id", "port", "addresses", "protocols"},
        ):
            raise LinuxGuardError(
                "auxiliary target fields are incomplete or unexpected"
            )
        target_id = raw_record["target_id"]
        if (
            not isinstance(target_id, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", target_id) is None
            or target_id in target_ids
        ):
            raise LinuxGuardError("auxiliary target ID is invalid or duplicated")
        target_ids.add(target_id)
        port = _port(raw_record["port"])
        protocols = raw_record.get("protocols", ["tcp"])
        if (
            not isinstance(protocols, list)
            or not protocols
            or any(protocol not in {"tcp", "udp"} for protocol in protocols)
            or protocols != sorted(set(protocols))
        ):
            raise LinuxGuardError("auxiliary target protocols are invalid")
        addresses = raw_record["addresses"]
        if not isinstance(addresses, list) or not addresses:
            raise LinuxGuardError("auxiliary target address list is empty")
        normalized_addresses = sorted(
            {_public_ip(value) for value in addresses},
            key=lambda address: (address.version, int(address)),
        )
        if len(normalized_addresses) != len(addresses) or any(
            str(address) not in addresses for address in normalized_addresses
        ):
            raise LinuxGuardError(
                "auxiliary target address list is duplicated or non-canonical"
            )
        for address in normalized_addresses:
            endpoints.append(
                {
                    "target_id": target_id,
                    "address": str(address),
                    "port": port,
                    "family": address.version,
                    "protocols": tuple(protocols),
                }
            )
    normalized_binding = [
        {
            "target_id": endpoint["target_id"],
            "address": endpoint["address"],
            "port": endpoint["port"],
            "protocols": list(endpoint["protocols"]),
        }
        for endpoint in sorted(
            endpoints,
            key=lambda item: (
                item["target_id"],
                item["family"],
                ipaddress.ip_address(item["address"]),
                item["port"],
                item["protocols"],
            ),
        )
    ]
    return endpoints, _sha256(normalized_binding)


def _lease_names(shard_index: int, lease_id: str) -> dict[str, str]:
    if isinstance(shard_index, bool) or not isinstance(shard_index, int) or not 0 <= shard_index <= 3:
        raise LinuxGuardError("shard index must be between 0 and 3")
    if not isinstance(lease_id, str) or _HEX_32_RE.fullmatch(lease_id) is None:
        raise LinuxGuardError("guard lease ID must be 128-bit lowercase hexadecimal")
    token = hashlib.sha256(lease_id.encode("ascii")).hexdigest()[:8]
    upper = token.upper()
    return {
        "namespace": f"gmgnv2-s{shard_index}-{token}",
        "host_veth": f"g2h{shard_index}{token}",
        "ns_veth": f"g2n{shard_index}{token}",
        "forward_chain": f"G2F{upper}",
        "return_chain": f"G2R{upper}",
        "output_chain": f"G2O{upper}",
        "input_chain": f"G2I{upper}",
        "marker": f"gmgn-v2-{token}",
    }


def _validate_names(state: Mapping[str, Any]) -> None:
    lease_id = state.get("lease_id")
    shard_index = state.get("shard_index")
    expected = _lease_names(shard_index, lease_id)
    names = state.get("names")
    if not isinstance(names, Mapping) or dict(names) != expected:
        raise LinuxGuardError("guard lease names do not match the owned lease")
    if _SAFE_NAMESPACE_RE.fullmatch(expected["namespace"]) is None:
        raise LinuxGuardError("guard namespace name is unsafe")
    if any(
        _SAFE_VETH_RE.fullmatch(expected[field]) is None
        for field in ("host_veth", "ns_veth")
    ):
        raise LinuxGuardError("guard veth name is unsafe")
    if any(
        _SAFE_CHAIN_RE.fullmatch(expected[field]) is None
        for field in ("forward_chain", "return_chain", "output_chain", "input_chain")
    ):
        raise LinuxGuardError("guard chain name is unsafe")


def _ipt(family: int, namespace: str | None = None) -> list[str]:
    command = ["iptables" if family == 4 else "ip6tables", "-w", "5"]
    if namespace is None:
        return command
    return ["ip", "netns", "exec", namespace, *command]


def _append_rule(
    commands: list[list[str]], prefix: Sequence[str], *arguments: str
) -> None:
    commands.append([*prefix, *arguments])


def _rule_check(command: Sequence[str]) -> list[str] | None:
    value = list(command)
    try:
        position = value.index("-A")
    except ValueError:
        try:
            position = value.index("-I")
        except ValueError:
            return None
    value[position] = "-C"
    if position + 2 < len(value) and command[position] == "-I" and value[position + 2].isdigit():
        del value[position + 2]
    return value


def _deny_networks(
    *, runner_networks: Mapping[str, Iterable[str]]
) -> dict[int, tuple[str, ...]]:
    ipv4 = _normalize_networks(
        [*FORBIDDEN_IPV4, *METADATA_IPV4, *runner_networks.get("ipv4", ())],
        version=4,
    )
    ipv6 = _normalize_networks(
        [*FORBIDDEN_IPV6, *METADATA_IPV6, *runner_networks.get("ipv6", ())],
        version=6,
    )
    return {4: ipv4, 6: ipv6}


def build_guard_plan(
    pinned: Mapping[str, Mapping[str, Any]],
    *,
    shard_index: int,
    controller_port: int,
    local_ports: Iterable[int] = (),
    auxiliary_targets: Mapping[str, Mapping[str, Any]]
    | Sequence[Mapping[str, Any]]
    | None = None,
    runner_networks: Mapping[str, Iterable[str]] | None = None,
    lease_id: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic, inspectable command plan without mutating Linux."""

    candidate_endpoints, candidate_hash, fixed_hash = normalize_pinned_targets(pinned)
    auxiliary_endpoints, auxiliary_hash = normalize_auxiliary_targets(
        auxiliary_targets
    )
    endpoints = [*candidate_endpoints, *auxiliary_endpoints]
    controller_port = _port(controller_port)
    ports = {controller_port}
    for value in local_ports:
        ports.add(_port(value))
    lease_id = lease_id or secrets.token_hex(16)
    names = _lease_names(shard_index, lease_id)
    namespace = names["namespace"]
    host_veth = names["host_veth"]
    ns_veth = names["ns_veth"]
    marker = names["marker"]

    third_octet = 240 + shard_index
    ipv4_subnet = f"172.30.{third_octet}.0/30"
    host_ipv4 = f"172.30.{third_octet}.1"
    ns_ipv4 = f"172.30.{third_octet}.2"
    ipv6_subnet = f"fd6d:676e:7632:{shard_index + 1}::/64"
    host_ipv6 = f"fd6d:676e:7632:{shard_index + 1}::1"
    ns_ipv6 = f"fd6d:676e:7632:{shard_index + 1}::2"
    has_ipv6_targets = any(item["family"] == 6 for item in endpoints)
    denied = _deny_networks(runner_networks=runner_networks or {})
    for endpoint in endpoints:
        address = ipaddress.ip_address(endpoint["address"])
        if any(address in ipaddress.ip_network(value) for value in denied[address.version]):
            raise LinuxGuardError("fixed target overlaps a runner or forbidden network")

    setup: list[list[str]] = [
        ["ip", "netns", "add", namespace],
        ["ip", "link", "add", host_veth, "type", "veth", "peer", "name", ns_veth],
        ["ip", "link", "set", ns_veth, "netns", namespace],
        ["ip", "addr", "add", f"{host_ipv4}/30", "dev", host_veth],
        ["ip", "link", "set", host_veth, "up"],
        ["ip", "-n", namespace, "addr", "add", f"{ns_ipv4}/30", "dev", ns_veth],
        ["ip", "-n", namespace, "link", "set", "lo", "up"],
        ["ip", "-n", namespace, "link", "set", ns_veth, "up"],
        ["ip", "-n", namespace, "route", "add", "default", "via", host_ipv4, "dev", ns_veth],
    ]
    if has_ipv6_targets:
        setup.extend(
            [
                ["ip", "-6", "addr", "add", f"{host_ipv6}/64", "dev", host_veth],
                ["ip", "-n", namespace, "-6", "addr", "add", f"{ns_ipv6}/64", "dev", ns_veth],
                ["ip", "-n", namespace, "-6", "route", "add", "default", "via", host_ipv6, "dev", ns_veth],
            ]
        )

    for family in (4, 6):
        host = _ipt(family)
        inside = _ipt(family, namespace)
        forward_chain = names["forward_chain"]
        return_chain = names["return_chain"]
        output_chain = names["output_chain"]
        input_chain = names["input_chain"]
        _append_rule(setup, host, "-N", forward_chain)
        _append_rule(setup, host, "-N", return_chain)
        _append_rule(
            setup,
            host,
            "-I",
            "FORWARD",
            "1",
            "-i",
            host_veth,
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            forward_chain,
        )
        _append_rule(
            setup,
            host,
            "-I",
            "FORWARD",
            "1",
            "-o",
            host_veth,
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            return_chain,
        )
        _append_rule(
            setup,
            host,
            "-A",
            return_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )
        _append_rule(setup, host, "-A", return_chain, "-j", "DROP")

        _append_rule(setup, inside, "-N", output_chain)
        _append_rule(setup, inside, "-N", input_chain)
        _append_rule(
            setup,
            inside,
            "-I",
            "OUTPUT",
            "1",
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            output_chain,
        )
        _append_rule(
            setup,
            inside,
            "-I",
            "INPUT",
            "1",
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            input_chain,
        )
        _append_rule(
            setup,
            inside,
            "-A",
            output_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )
        _append_rule(
            setup,
            inside,
            "-A",
            input_chain,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        )
        loopback = "127.0.0.1/32" if family == 4 else "::1/128"
        for port in sorted(ports):
            _append_rule(
                setup,
                inside,
                "-A",
                output_chain,
                "-o",
                "lo",
                "-d",
                loopback,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "ACCEPT",
            )
            _append_rule(
                setup,
                inside,
                "-A",
                input_chain,
                "-i",
                "lo",
                "-s",
                loopback,
                "-p",
                "tcp",
                "--dport",
                str(port),
                "-j",
                "ACCEPT",
            )

        for network in denied[family]:
            for prefix in (inside, host):
                chain = output_chain if prefix is inside else forward_chain
                _append_rule(
                    setup,
                    prefix,
                    "-A",
                    chain,
                    "-d",
                    network,
                    "-m",
                    "comment",
                    "--comment",
                    f"{marker}-deny",
                    "-j",
                    "REJECT",
                )

        for endpoint in (item for item in endpoints if item["family"] == family):
            destination = f"{endpoint['address']}/{32 if family == 4 else 128}"
            for protocol in endpoint["protocols"]:
                for prefix, chain in ((inside, output_chain), (host, forward_chain)):
                    _append_rule(
                        setup,
                        prefix,
                        "-A",
                        chain,
                        "-d",
                        destination,
                        "-p",
                        protocol,
                        "--dport",
                        str(endpoint["port"]),
                        "-m",
                        "comment",
                        "--comment",
                        f"{marker}-fixed",
                        "-j",
                        "ACCEPT",
                    )
        _append_rule(setup, inside, "-A", output_chain, "-j", "DROP")
        _append_rule(setup, inside, "-A", input_chain, "-j", "DROP")
        _append_rule(setup, host, "-A", forward_chain, "-j", "DROP")

    nat4 = ["iptables", "-w", "5", "-t", "nat"]
    _append_rule(
        setup,
        nat4,
        "-A",
        "POSTROUTING",
        "-s",
        ipv4_subnet,
        "-m",
        "comment",
        "--comment",
        marker,
        "-j",
        "MASQUERADE",
    )
    if has_ipv6_targets:
        nat6 = ["ip6tables", "-w", "5", "-t", "nat"]
        _append_rule(
            setup,
            nat6,
            "-A",
            "POSTROUTING",
            "-s",
            ipv6_subnet,
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            "MASQUERADE",
        )

    self_test: list[list[str]] = []
    # Check the hooks, the controller-only loopback rule, a representative
    # metadata denial, every fixed target allow, and the terminal drops.
    for command in setup:
        check_command = _rule_check(command)
        if check_command is None:
            continue
        if (
            "FORWARD" in command
            or "OUTPUT" in command
            or "INPUT" in command
            or "POSTROUTING" in command
            or "--dport" in command
            or "169.254.169.254/32" in command
            or "fd00:ec2::254/128" in command
            or command[-1] == "DROP"
        ):
            self_test.append(check_command)
    self_test.extend(
        [
            ["ip", "netns", "exec", namespace, "ip", "link", "show", "up", "dev", "lo"],
            ["ip", "netns", "exec", namespace, "ip", "route", "show", "default"],
        ]
    )
    if has_ipv6_targets:
        self_test.append(
            ["ip", "netns", "exec", namespace, "ip", "-6", "route", "show", "default"]
        )

    cleanup: list[list[str]] = []
    for family in (4, 6):
        host = _ipt(family)
        forward_chain = names["forward_chain"]
        return_chain = names["return_chain"]
        cleanup.extend(
            [
                [
                    *host,
                    "-D",
                    "FORWARD",
                    "-i",
                    host_veth,
                    "-m",
                    "comment",
                    "--comment",
                    marker,
                    "-j",
                    forward_chain,
                ],
                [
                    *host,
                    "-D",
                    "FORWARD",
                    "-o",
                    host_veth,
                    "-m",
                    "comment",
                    "--comment",
                    marker,
                    "-j",
                    return_chain,
                ],
                [*host, "-F", forward_chain],
                [*host, "-X", forward_chain],
                [*host, "-F", return_chain],
                [*host, "-X", return_chain],
            ]
        )
    cleanup.append(
        [
            "iptables",
            "-w",
            "5",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            ipv4_subnet,
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            "MASQUERADE",
        ]
    )
    if has_ipv6_targets:
        cleanup.append(
            [
                "ip6tables",
                "-w",
                "5",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                ipv6_subnet,
                "-m",
                "comment",
                "--comment",
                marker,
                "-j",
                "MASQUERADE",
            ]
        )
    cleanup.extend(
        [
            ["ip", "netns", "delete", namespace],
            ["ip", "link", "delete", host_veth],
        ]
    )

    rule_commands = [command for command in setup if "iptables" in command or "ip6tables" in command]
    return {
        "kind": STATE_KIND,
        "schema_version": STATE_SCHEMA_VERSION,
        "phase": "planned",
        "lease_id": lease_id,
        "lease_id_sha256": hashlib.sha256(lease_id.encode("ascii")).hexdigest(),
        "shard_index": shard_index,
        "names": names,
        "controller_ports": sorted(ports),
        "candidate_ids": sorted(pinned),
        "candidate_ids_sha256": candidate_hash,
        "fixed_targets_sha256": fixed_hash,
        "auxiliary_targets_sha256": auxiliary_hash,
        "all_fixed_targets_sha256": _sha256(
            {
                "candidate_fixed_targets_sha256": fixed_hash,
                "auxiliary_targets_sha256": auxiliary_hash,
            }
        ),
        "has_ipv6_targets": has_ipv6_targets,
        "subnets": {"ipv4": ipv4_subnet, "ipv6": ipv6_subnet},
        "runner_networks_sha256": _sha256(
            {"ipv4": list(denied[4]), "ipv6": list(denied[6])}
        ),
        "rules_sha256": _sha256(rule_commands),
        "command_plan_sha256": _sha256(
            {"setup": setup, "self_test": self_test, "cleanup": cleanup}
        ),
        "setup_commands": setup,
        "self_test_commands": self_test,
        "cleanup_commands": cleanup,
    }


def _write_json_atomic(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    temporary.write_bytes(_canonical_json(value) + b"\n")
    os.replace(temporary, path)
    try:
        path.chmod(0o600)
    except OSError as exc:
        raise LinuxGuardError("network-guard state permissions could not be secured") from exc


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LinuxGuardError("network-guard state or evidence is unreadable") from exc


def _state_hash(state: Mapping[str, Any]) -> str:
    value = dict(state)
    value.pop("state_sha256", None)
    value.pop("evidence", None)
    return _sha256(value)


def validate_linux_guard_evidence(
    evidence: Mapping[str, Any], *, candidate_ids: Iterable[str]
) -> dict[str, Any]:
    required = {
        "kind",
        "schema_version",
        "backend",
        "backend_version",
        "policy_version",
        "resolver_policy_version",
        "lease_id_sha256",
        "shard_index",
        "candidate_ids_sha256",
        "fixed_targets_sha256",
        "auxiliary_targets_sha256",
        "all_fixed_targets_sha256",
        "rules_sha256",
        "observed_rules_sha256",
        "command_plan_sha256",
        "state_sha256",
        "self_test",
        "controller_isolation",
        "capabilities",
        "guard_evidence",
    }
    if not isinstance(evidence, Mapping) or frozenset(evidence) != required:
        raise LinuxGuardError("Linux guard evidence fields are incomplete or unexpected")
    value = dict(evidence)
    if value["kind"] != EVIDENCE_KIND or value["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise LinuxGuardError("Linux guard evidence schema is unsupported")
    if value["backend"] != BACKEND or value["backend_version"] != BACKEND_VERSION:
        raise LinuxGuardError("Linux guard backend identity mismatch")
    if value["policy_version"] != NETWORK_GUARD_POLICY_VERSION:
        raise LinuxGuardError("Linux guard policy version mismatch")
    if value["resolver_policy_version"] != RESOLVER_POLICY_VERSION:
        raise LinuxGuardError("Linux guard resolver policy version mismatch")
    for field in (
        "lease_id_sha256",
        "candidate_ids_sha256",
        "fixed_targets_sha256",
        "auxiliary_targets_sha256",
        "all_fixed_targets_sha256",
        "rules_sha256",
        "observed_rules_sha256",
        "command_plan_sha256",
        "state_sha256",
    ):
        if not isinstance(value[field], str) or re.fullmatch(r"[0-9a-f]{64}", value[field]) is None:
            raise LinuxGuardError(f"Linux guard {field} is invalid")
    self_test = value["self_test"]
    if not isinstance(self_test, Mapping) or frozenset(self_test) != {
        "deny_rules",
        "allow_rules",
        "default_drop",
        "namespace_route",
    }:
        raise LinuxGuardError("Linux guard self-test evidence is malformed")
    if any(item is not True for item in self_test.values()):
        raise LinuxGuardError("Linux guard self-test did not pass")
    controller = value["controller_isolation"]
    if not isinstance(controller, Mapping) or controller != {
        "loopback_only": True,
        "host_ingress_allowed": False,
        "same_namespace_required": True,
    }:
        raise LinuxGuardError("Linux guard controller isolation is invalid")
    capabilities = value["capabilities"]
    if not isinstance(capabilities, Mapping) or not all(
        capabilities.get(field) is True
        for field in (
            "linux",
            "root",
            "cap_net_admin",
            "cap_sys_admin",
            "ip_netns",
            "iptables",
            "ip6tables",
            "ipv4_forwarding",
        )
    ):
        raise LinuxGuardError("Linux guard capability evidence is incomplete")
    validate_guard_evidence(value["guard_evidence"], candidate_ids=candidate_ids)
    if value["candidate_ids_sha256"] != value["guard_evidence"]["candidate_ids_sha256"]:
        raise LinuxGuardError("Linux and C2 candidate bindings differ")
    if value["all_fixed_targets_sha256"] != _sha256(
        {
            "candidate_fixed_targets_sha256": value["fixed_targets_sha256"],
            "auxiliary_targets_sha256": value["auxiliary_targets_sha256"],
        }
    ):
        raise LinuxGuardError("Linux guard combined fixed-target binding mismatch")
    return value


def _best_effort_cleanup(state: Mapping[str, Any], runner: CommandRunner) -> list[int]:
    _validate_names(state)
    results: list[int] = []
    commands = state.get("cleanup_commands")
    if not isinstance(commands, list):
        raise LinuxGuardError("guard cleanup plan is missing")
    names = state["names"]
    marker = names["marker"]
    subnets = state.get("subnets")
    if not isinstance(subnets, Mapping):
        raise LinuxGuardError("guard cleanup subnet binding is missing")
    allowed_exact = {
        ("ip", "netns", "delete", names["namespace"]),
        ("ip", "link", "delete", names["host_veth"]),
    }
    for family in (4, 6):
        tool = "iptables" if family == 4 else "ip6tables"
        prefix = (tool, "-w", "5")
        for direction, chain in (
            ("-i", names["forward_chain"]),
            ("-o", names["return_chain"]),
        ):
            allowed_exact.add(
                (
                    *prefix,
                    "-D",
                    "FORWARD",
                    direction,
                    names["host_veth"],
                    "-m",
                    "comment",
                    "--comment",
                    marker,
                    "-j",
                    chain,
                )
            )
        for chain in (names["forward_chain"], names["return_chain"]):
            allowed_exact.add((*prefix, "-F", chain))
            allowed_exact.add((*prefix, "-X", chain))
    allowed_exact.add(
        (
            "iptables",
            "-w",
            "5",
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            str(subnets.get("ipv4")),
            "-m",
            "comment",
            "--comment",
            marker,
            "-j",
            "MASQUERADE",
        )
    )
    if state.get("has_ipv6_targets") is True:
        allowed_exact.add(
            (
                "ip6tables",
                "-w",
                "5",
                "-t",
                "nat",
                "-D",
                "POSTROUTING",
                "-s",
                str(subnets.get("ipv6")),
                "-m",
                "comment",
                "--comment",
                marker,
                "-j",
                "MASQUERADE",
            )
        )
    for raw_command in commands:
        if not isinstance(raw_command, list) or not raw_command or not all(
            isinstance(item, str) and item for item in raw_command
        ):
            raise LinuxGuardError("guard cleanup plan contains an unsafe command")
        if tuple(raw_command) not in allowed_exact:
            raise LinuxGuardError("guard cleanup plan exceeds its owned lease")
        result = _run(runner, raw_command, check=False)
        results.append(int(getattr(result, "returncode", 0)))
    return results


@dataclass
class LinuxGuardLease:
    state: dict[str, Any]
    state_path: Path | None
    runner: CommandRunner = _default_runner

    @property
    def evidence(self) -> dict[str, Any]:
        evidence = self.state.get("evidence")
        if not isinstance(evidence, dict):
            raise LinuxGuardError("active guard evidence is missing")
        return evidence

    @property
    def c2_evidence(self) -> dict[str, Any]:
        return dict(self.evidence["guard_evidence"])

    def wrap_command(self, command: Sequence[str]) -> list[str]:
        if self.state.get("phase") != "active":
            raise LinuxGuardError("network guard is not active")
        _validate_names(self.state)
        candidate_ids = self.state.get("candidate_ids")
        if not isinstance(candidate_ids, list):
            raise LinuxGuardError("network guard candidate binding is missing")
        validate_linux_guard_evidence(self.evidence, candidate_ids=candidate_ids)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise LinuxGuardError("guarded launch command is invalid")
        for self_test in self.state.get("self_test_commands", []):
            if not isinstance(self_test, list):
                raise LinuxGuardError("network guard self-test plan is malformed")
            _run(self.runner, self_test)
        return ["ip", "netns", "exec", self.state["names"]["namespace"], *command]

    def launch(self, command: Sequence[str]) -> int:
        wrapped = self.wrap_command(command)
        result = _run(self.runner, wrapped, check=False, capture_output=False)
        return int(getattr(result, "returncode", 0))

    def cleanup(self) -> None:
        if self.state.get("phase") == "cleaned":
            return
        results = _best_effort_cleanup(self.state, self.runner)
        self.state["phase"] = "cleaned"
        self.state["cleanup_returncodes"] = results
        if self.state_path is not None:
            self.state["state_sha256"] = _state_hash(self.state)
            _write_json_atomic(self.state_path, self.state)
        if any(result not in (0, 1) for result in results):
            raise LinuxGuardError("one or more owned guard resources could not be cleaned")


def provision_guard(
    pinned: Mapping[str, Mapping[str, Any]],
    *,
    shard_index: int,
    controller_port: int,
    local_ports: Iterable[int] = (),
    auxiliary_targets: Mapping[str, Mapping[str, Any]]
    | Sequence[Mapping[str, Any]]
    | None = None,
    state_path: str | os.PathLike[str] | None = None,
    runner: CommandRunner = _default_runner,
    capabilities: Mapping[str, Any] | None = None,
    runner_networks: Mapping[str, Iterable[str]] | None = None,
    lease_id: str | None = None,
) -> LinuxGuardLease:
    """Create, self-test and return an active namespace lease."""

    capability_evidence = dict(capabilities or preflight_linux_backend(runner=runner))
    networks = dict(runner_networks or discover_runner_networks(runner))
    plan = build_guard_plan(
        pinned,
        shard_index=shard_index,
        controller_port=controller_port,
        local_ports=local_ports,
        auxiliary_targets=auxiliary_targets,
        runner_networks=networks,
        lease_id=lease_id,
    )
    if plan["has_ipv6_targets"] and capability_evidence.get("ipv6_forwarding") is not True:
        raise LinuxGuardError("host IPv6 forwarding is required for fixed IPv6 targets")
    destination = Path(state_path) if state_path is not None else None
    if destination is not None:
        plan["state_sha256"] = _state_hash(plan)
        _write_json_atomic(destination, plan)

    try:
        for command in plan["setup_commands"]:
            _run(runner, command)
        for command in plan["self_test_commands"]:
            _run(runner, command)
        observed_outputs: list[str] = []
        namespace = plan["names"]["namespace"]
        for family in (4, 6):
            tool = "iptables" if family == 4 else "ip6tables"
            for command in (
                [tool, "-w", "5", "-S", plan["names"]["forward_chain"]],
                [tool, "-w", "5", "-S", plan["names"]["return_chain"]],
                ["ip", "netns", "exec", namespace, tool, "-w", "5", "-S", plan["names"]["output_chain"]],
                ["ip", "netns", "exec", namespace, tool, "-w", "5", "-S", plan["names"]["input_chain"]],
            ):
                result = _run(runner, command)
                observed_outputs.append(str(getattr(result, "stdout", "")))
    except Exception:
        _best_effort_cleanup(plan, runner)
        plan["phase"] = "failed"
        if destination is not None:
            plan["state_sha256"] = _state_hash(plan)
            _write_json_atomic(destination, plan)
        raise

    try:
        guard_evidence = {
            "backend": BACKEND,
            "backend_version": BACKEND_VERSION,
            "policy_version": NETWORK_GUARD_POLICY_VERSION,
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
            "available": True,
            "deny_self_test_passed": True,
            "controller_isolated": True,
            "fixed_resolution_enforced": True,
            "candidate_ids_sha256": plan["candidate_ids_sha256"],
        }
        validate_guard_evidence(guard_evidence, candidate_ids=pinned.keys())
        plan["phase"] = "active"
        plan["state_sha256"] = _state_hash(plan)
        evidence = {
            "kind": EVIDENCE_KIND,
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "backend": BACKEND,
            "backend_version": BACKEND_VERSION,
            "policy_version": NETWORK_GUARD_POLICY_VERSION,
            "resolver_policy_version": RESOLVER_POLICY_VERSION,
            "lease_id_sha256": plan["lease_id_sha256"],
            "shard_index": shard_index,
            "candidate_ids_sha256": plan["candidate_ids_sha256"],
            "fixed_targets_sha256": plan["fixed_targets_sha256"],
            "auxiliary_targets_sha256": plan["auxiliary_targets_sha256"],
            "all_fixed_targets_sha256": plan["all_fixed_targets_sha256"],
            "rules_sha256": plan["rules_sha256"],
            "observed_rules_sha256": _sha256(observed_outputs),
            "command_plan_sha256": plan["command_plan_sha256"],
            "state_sha256": plan["state_sha256"],
            "self_test": {
                "deny_rules": True,
                "allow_rules": True,
                "default_drop": True,
                "namespace_route": True,
            },
            "controller_isolation": {
                "loopback_only": True,
                "host_ingress_allowed": False,
                "same_namespace_required": True,
            },
            "capabilities": capability_evidence,
            "guard_evidence": guard_evidence,
        }
        validate_linux_guard_evidence(evidence, candidate_ids=pinned.keys())
    except Exception:
        _best_effort_cleanup(plan, runner)
        plan["phase"] = "failed"
        if destination is not None:
            plan["state_sha256"] = _state_hash(plan)
            _write_json_atomic(destination, plan)
        raise
    plan["evidence"] = evidence
    if destination is not None:
        _write_json_atomic(destination, plan)
    return LinuxGuardLease(plan, destination, runner)


def load_guard_lease(
    state_path: str | os.PathLike[str], *, runner: CommandRunner = _default_runner
) -> LinuxGuardLease:
    path = Path(state_path)
    state = _load_json(path)
    if not isinstance(state, dict) or state.get("kind") != STATE_KIND:
        raise LinuxGuardError("guard lease state schema is invalid")
    if state.get("schema_version") != STATE_SCHEMA_VERSION:
        raise LinuxGuardError("guard lease state version is unsupported")
    _validate_names(state)
    if state.get("state_sha256") != _state_hash(state):
        raise LinuxGuardError("guard lease state hash mismatch")
    return LinuxGuardLease(state, path, runner)


def _load_pinned(path: Path) -> Mapping[str, Mapping[str, Any]]:
    value = _load_json(path)
    if isinstance(value, Mapping) and frozenset(value) == {"pinned"}:
        value = value["pinned"]
    if not isinstance(value, Mapping):
        raise LinuxGuardError("pinned target file must contain an object")
    return value  # validated by provision_guard


def _load_auxiliary_targets(path: Path | None) -> Mapping[str, Mapping[str, Any]]:
    if path is None:
        return {}
    value = _load_json(path)
    if isinstance(value, Mapping) and frozenset(value) == {"auxiliary_targets"}:
        value = value["auxiliary_targets"]
    if not isinstance(value, Mapping):
        raise LinuxGuardError("auxiliary target file must contain an object")
    return value  # validated by provision_guard


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision and launch a fail-closed GMGN Linux network namespace"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--output")
    preflight_parser.add_argument("--exercise-netns", default="")

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--pinned", required=True)
    prepare.add_argument("--shard-index", type=int, required=True)
    prepare.add_argument("--controller-port", type=int, required=True)
    prepare.add_argument("--local-port", action="append", type=int, default=[])
    prepare.add_argument("--auxiliary-targets")
    prepare.add_argument("--state", required=True)
    prepare.add_argument("--evidence", required=True)

    launch = commands.add_parser("launch")
    launch.add_argument("--state", required=True)
    launch.add_argument("launch_command", nargs=argparse.REMAINDER)

    cleanup = commands.add_parser("cleanup")
    cleanup.add_argument("--state", required=True)
    args = parser.parse_args(argv)

    if args.command == "preflight":
        evidence = preflight_linux_backend()
        if args.exercise_netns:
            evidence.update(exercise_netns_mutation(args.exercise_netns))
        if args.output:
            _write_json_atomic(Path(args.output), evidence)
        else:
            print(json.dumps(evidence, sort_keys=True))
        return 0
    if args.command == "prepare":
        pinned = _load_pinned(Path(args.pinned))
        auxiliary_targets = _load_auxiliary_targets(
            Path(args.auxiliary_targets) if args.auxiliary_targets else None
        )
        lease = provision_guard(
            pinned,
            shard_index=args.shard_index,
            controller_port=args.controller_port,
            local_ports=args.local_port,
            auxiliary_targets=auxiliary_targets,
            state_path=args.state,
        )
        _write_json_atomic(Path(args.evidence), lease.evidence)
        return 0
    if args.command == "cleanup":
        load_guard_lease(args.state).cleanup()
        return 0
    command = list(args.launch_command)
    if command and command[0] == "--":
        command.pop(0)
    lease = load_guard_lease(args.state)
    try:
        return lease.launch(command)
    finally:
        lease.cleanup()


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except LinuxGuardError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


__all__ = [
    "BACKEND",
    "BACKEND_VERSION",
    "CommandResult",
    "EVIDENCE_KIND",
    "FORBIDDEN_IPV4",
    "FORBIDDEN_IPV6",
    "LinuxGuardError",
    "LinuxGuardLease",
    "build_guard_plan",
    "discover_runner_networks",
    "effective_cap_net_admin",
    "effective_cap_sys_admin",
    "exercise_netns_mutation",
    "load_guard_lease",
    "normalize_auxiliary_targets",
    "normalize_pinned_targets",
    "preflight_linux_backend",
    "provision_guard",
    "validate_linux_guard_evidence",
]
