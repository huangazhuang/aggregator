#!/usr/bin/env python3
"""Strict Candidate V2 proxy schema validation.

Mihomo accepts configuration through a weakly typed decoder.  That is useful
for user-authored configuration, but it is not a sufficient trust boundary for
untrusted subscription data: unknown keys can be ignored and ``dialer-proxy``
is meaningful outside the proxy itself.  This module owns the narrower set of
protocols and fields that the aggregator deliberately publishes.

Validation is fail-closed.  Known compatibility aliases are normalized, while
unknown top-level fields, cross-protocol fields, and unknown nested option keys
raise :class:`ProxySchemaError`.  The returned mapping is a deep copy and keeps
all connection fields, including Mihomo's top-level TLS ``fingerprint`` field.
"""

from __future__ import annotations

import copy
import math
import re
from collections.abc import Mapping
from typing import Any


PROXY_SCHEMA_POLICY_VERSION = "candidate-proxy-schema-v1"
SUPPORTED_PROXY_TYPES = frozenset(
    {
        "ss",
        "ssr",
        "vmess",
        "vless",
        "trojan",
        "snell",
        "http",
        "socks5",
        "tuic",
        "hysteria",
        "hysteria2",
        "anytls",
    }
)

_COMMON_FIELDS = frozenset(
    {
        "name",
        "type",
        "server",
        "port",
        "tfo",
        "mptcp",
        "interface-name",
        "routing-mark",
        "ip-version",
        "smux",
    }
)
_PROTOCOL_FIELDS: dict[str, frozenset[str]] = {
    "ss": frozenset(
        {
            "password",
            "cipher",
            "udp",
            "plugin",
            "plugin-opts",
            "udp-over-tcp",
            "udp-over-tcp-version",
            "client-fingerprint",
        }
    ),
    "ssr": frozenset(
        {
            "password",
            "cipher",
            "obfs",
            "obfs-param",
            "protocol",
            "protocol-param",
            "udp",
        }
    ),
    "vmess": frozenset(
        {
            "uuid",
            "alterId",
            "cipher",
            "udp",
            "network",
            "tls",
            "alpn",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "servername",
            "client-fingerprint",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "tlsmirror-opts",
            "http-opts",
            "h2-opts",
            "grpc-opts",
            "ws-opts",
            "packet-addr",
            "xudp",
            "packet-encoding",
            "global-padding",
            "authenticated-length",
        }
    ),
    "vless": frozenset(
        {
            "uuid",
            "flow",
            "tls",
            "alpn",
            "udp",
            "packet-addr",
            "xudp",
            "packet-encoding",
            "encryption",
            "network",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "http-opts",
            "h2-opts",
            "grpc-opts",
            "ws-opts",
            "xhttp-opts",
            "ws-headers",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "servername",
            "client-fingerprint",
        }
    ),
    "trojan": frozenset(
        {
            "password",
            "alpn",
            "sni",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "udp",
            "network",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "reality-opts",
            "grpc-opts",
            "ws-opts",
            "ss-opts",
            "client-fingerprint",
        }
    ),
    "snell": frozenset(
        {
            "psk",
            "udp",
            "version",
            "reuse",
            "obfs-opts",
            "client-fingerprint",
        }
    ),
    "http": frozenset(
        {
            "username",
            "password",
            "tls",
            "sni",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "headers",
        }
    ),
    "socks5": frozenset(
        {
            "username",
            "password",
            "tls",
            "udp",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
        }
    ),
    "tuic": frozenset(
        {
            "token",
            "uuid",
            "password",
            "ip",
            "heartbeat-interval",
            "alpn",
            "reduce-rtt",
            "request-timeout",
            "udp-relay-mode",
            "congestion-controller",
            "disable-sni",
            "max-udp-relay-packet-size",
            "fast-open",
            "max-open-streams",
            "cwnd",
            "bbr-profile",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "max-datagram-frame-size",
            "sni",
            "ech-opts",
            "udp-over-stream",
            "udp-over-stream-version",
        }
    ),
    "hysteria": frozenset(
        {
            "ports",
            "protocol",
            "obfs-protocol",
            "up",
            "up-speed",
            "down",
            "down-speed",
            "auth",
            "auth-str",
            "obfs",
            "sni",
            "ech-opts",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "recv-window-conn",
            "recv-window",
            "disable-mtu-discovery",
            "fast-open",
            "hop-interval",
            # The protocol is intrinsically UDP-capable, but the existing
            # collector intentionally emits this compatibility flag.
            "udp",
        }
    ),
    "hysteria2": frozenset(
        {
            "ports",
            "hop-interval",
            "up",
            "down",
            "password",
            "obfs",
            "obfs-password",
            "obfs-min-packet-size",
            "obfs-max-packet-size",
            "sni",
            "ech-opts",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "alpn",
            "cwnd",
            "bbr-profile",
            "udp-mtu",
            "initial-stream-receive-window",
            "max-stream-receive-window",
            "initial-connection-receive-window",
            "max-connection-receive-window",
            # See the Hysteria compatibility note above.
            "udp",
        }
    ),
    "anytls": frozenset(
        {
            "password",
            "alpn",
            "sni",
            "ech-opts",
            "shadow-tls-opts",
            "restls-opts",
            "jls-opts",
            "client-fingerprint",
            "skip-cert-verify",
            "name-cert-verify",
            "fingerprint",
            "certificate",
            "private-key",
            "udp",
            "idle-session-check-interval",
            "idle-session-timeout",
            "min-idle-session",
            "disable-reuse",
        }
    ),
}
_REQUIRED_FIELDS: dict[str, frozenset[str]] = {
    "ss": frozenset({"password", "cipher"}),
    "ssr": frozenset({"password", "cipher", "obfs", "protocol"}),
    "vmess": frozenset({"uuid", "alterId", "cipher"}),
    "vless": frozenset({"uuid"}),
    "trojan": frozenset({"password"}),
    "snell": frozenset({"psk"}),
    "http": frozenset(),
    "socks5": frozenset(),
    "tuic": frozenset(),
    "hysteria": frozenset({"up", "down"}),
    "hysteria2": frozenset({"password"}),
    "anytls": frozenset({"password"}),
}

_COMPATIBILITY_ALIASES: dict[str, dict[str, str]] = {
    "hysteria": {
        "auth_str": "auth-str",
        "recv_window_conn": "recv-window-conn",
        "recv_window": "recv-window",
        "disable_mtu_discovery": "disable-mtu-discovery",
    },
    # Older converters commonly emit both auth and password with the same
    # value.  Mihomo's Hysteria2 outbound consumes password.
    "hysteria2": {"auth": "password"},
}

_BOOL_FIELDS = frozenset(
    {
        "tfo",
        "mptcp",
        "udp",
        "tls",
        "skip-cert-verify",
        "udp-over-tcp",
        "packet-addr",
        "xudp",
        "global-padding",
        "authenticated-length",
        "reuse",
        "reduce-rtt",
        "disable-sni",
        "fast-open",
        "disable-mtu-discovery",
        "udp-over-stream",
        "disable-reuse",
    }
)
_INT_FIELDS = frozenset(
    {
        "routing-mark",
        "alterId",
        "udp-over-tcp-version",
        "version",
        "heartbeat-interval",
        "request-timeout",
        "max-udp-relay-packet-size",
        "max-open-streams",
        "cwnd",
        "recv-window-conn",
        "recv-window",
        "max-datagram-frame-size",
        "udp-over-stream-version",
        "up-speed",
        "down-speed",
        "obfs-min-packet-size",
        "obfs-max-packet-size",
        "udp-mtu",
        "initial-stream-receive-window",
        "max-stream-receive-window",
        "initial-connection-receive-window",
        "max-connection-receive-window",
        "idle-session-check-interval",
        "idle-session-timeout",
        "min-idle-session",
    }
)
_MAPPING_FIELDS = frozenset(
    {
        "smux",
        "plugin-opts",
        "ech-opts",
        "shadow-tls-opts",
        "restls-opts",
        "jls-opts",
        "reality-opts",
        "tlsmirror-opts",
        "http-opts",
        "h2-opts",
        "grpc-opts",
        "ws-opts",
        "xhttp-opts",
        "ss-opts",
        "obfs-opts",
        "headers",
        "ws-headers",
    }
)
_TEXT_LIST_FIELDS = frozenset({"alpn"})
_IP_VERSIONS = frozenset({"dual", "ipv4", "ipv6", "ipv4-prefer", "ipv6-prefer"})
_TCP_SMUX_PROTOCOLS = frozenset(
    {"ss", "ssr", "vmess", "vless", "trojan", "snell", "http", "socks5", "anytls"}
)
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}$")
_INTEGER_RE = re.compile(r"^-?[0-9]+$")
_REALITY_SHORT_ID_RE = re.compile(r"^[0-9A-Fa-f]{0,16}$")
_PRIVATE_KEY_LABELS = frozenset(
    {"PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"}
)


class ProxySchemaError(ValueError):
    """Raised when an untrusted proxy does not match the published schema."""


def _mapping(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ProxySchemaError(f"{path} must be a mapping")
    if any(not isinstance(key, str) for key in value):
        raise ProxySchemaError(f"{path} contains a non-string field")
    return copy.deepcopy(dict(value))


def _exact_mapping(
    value: Any,
    path: str,
    *,
    allowed: frozenset[str],
    required: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    result = _mapping(value, path)
    unknown = sorted(set(result) - allowed)
    if unknown:
        raise ProxySchemaError(f"{path} contains unsupported fields: {', '.join(unknown)}")
    missing = sorted(required - set(result))
    if missing:
        raise ProxySchemaError(f"{path} is missing required fields: {', '.join(missing)}")
    return result


def _text(
    value: Any,
    path: str,
    *,
    allow_empty: bool = True,
    max_length: int = 65_536,
) -> str:
    if not isinstance(value, str):
        raise ProxySchemaError(f"{path} must be text")
    if len(value) > max_length or "\x00" in value:
        raise ProxySchemaError(f"{path} is unsafe")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ProxySchemaError(f"{path} contains control characters")
    if not allow_empty and not value:
        raise ProxySchemaError(f"{path} must not be empty")
    return value


def _integer(value: Any, path: str, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ProxySchemaError(f"{path} must be an integer")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and _INTEGER_RE.fullmatch(value):
        parsed = int(value)
    else:
        raise ProxySchemaError(f"{path} must be an integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise ProxySchemaError(f"{path} is outside the supported range")
    return parsed


def _boolean(value: Any, path: str) -> bool:
    if type(value) is not bool:
        raise ProxySchemaError(f"{path} must be boolean")
    return value


def _text_list(value: Any, path: str, *, max_items: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > max_items:
        raise ProxySchemaError(f"{path} must be a bounded text list")
    return [_text(item, f"{path}[{index}]", max_length=16_384) for index, item in enumerate(value)]


def _header_map(value: Any, path: str, *, list_values: bool) -> dict[str, Any]:
    headers = _mapping(value, path)
    if len(headers) > 128:
        raise ProxySchemaError(f"{path} contains too many headers")
    normalized: dict[str, Any] = {}
    for name, raw in headers.items():
        if _HEADER_NAME_RE.fullmatch(name) is None:
            raise ProxySchemaError(f"{path} contains an invalid header name")
        if list_values:
            normalized[name] = _text_list(raw, f"{path}.{name}", max_items=64)
        else:
            normalized[name] = _text(raw, f"{path}.{name}", max_length=16_384)
    return normalized


def _normalize_aliases(proxy: dict[str, Any], protocol: str) -> None:
    for alias, canonical in _COMPATIBILITY_ALIASES.get(protocol, {}).items():
        if alias not in proxy:
            continue
        value = proxy.pop(alias)
        if canonical in proxy and proxy[canonical] != value:
            raise ProxySchemaError(
                f"proxy fields {alias} and {canonical} contain conflicting values"
            )
        proxy[canonical] = value


def _validate_inline_pem(value: Any, path: str, labels: frozenset[str]) -> str:
    if not isinstance(value, str) or not value or len(value) > 262_144 or "\x00" in value:
        raise ProxySchemaError(f"{path} must be bounded inline PEM")
    text = value.strip()
    matched = next(
        (
            label
            for label in labels
            if text.startswith(f"-----BEGIN {label}-----")
            and text.endswith(f"-----END {label}-----")
        ),
        "",
    )
    if not matched:
        raise ProxySchemaError(f"{path} must be inline PEM, not a filesystem path")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in text):
        raise ProxySchemaError(f"{path} contains unsafe PEM data")
    return value


def _validate_tls_material(mapping: dict[str, Any], path: str) -> None:
    has_certificate = "certificate" in mapping
    has_private_key = "private-key" in mapping
    if has_certificate != has_private_key:
        raise ProxySchemaError(f"{path} certificate and private-key must be provided together")
    if has_certificate:
        mapping["certificate"] = _validate_inline_pem(
            mapping["certificate"], f"{path}.certificate", frozenset({"CERTIFICATE"})
        )
        mapping["private-key"] = _validate_inline_pem(
            mapping["private-key"], f"{path}.private-key", _PRIVATE_KEY_LABELS
        )


def _validate_ech(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"enable", "config", "query-server-name"}),
    )
    if "enable" in result:
        result["enable"] = _boolean(result["enable"], f"{path}.enable")
    for field in ("config", "query-server-name"):
        if field in result:
            result[field] = _text(result[field], f"{path}.{field}")
    return result


def _validate_reality(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"public-key", "short-id", "support-x25519mlkem768"}),
        required=frozenset({"public-key"}),
    )
    result["public-key"] = _text(result["public-key"], f"{path}.public-key", allow_empty=False)
    if "short-id" in result:
        short_id = _text(result["short-id"], f"{path}.short-id")
        if len(short_id) % 2 or _REALITY_SHORT_ID_RE.fullmatch(short_id) is None:
            raise ProxySchemaError(f"{path}.short-id must be even-length hexadecimal")
        result["short-id"] = short_id
    if "support-x25519mlkem768" in result:
        result["support-x25519mlkem768"] = _boolean(
            result["support-x25519mlkem768"],
            f"{path}.support-x25519mlkem768",
        )
    return result


def _validate_shadow_tls(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"password", "version"}),
    )
    if "password" in result:
        result["password"] = _text(result["password"], f"{path}.password")
    if "version" in result:
        result["version"] = _integer(result["version"], f"{path}.version", maximum=3)
    return result


def _validate_restls(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"password", "version-hint", "restls-script"}),
    )
    for field in result:
        result[field] = _text(result[field], f"{path}.{field}")
    if result.get("version-hint") not in {None, "", "tls12", "tls13"}:
        raise ProxySchemaError(f"{path}.version-hint is unsupported")
    return result


def _validate_jls(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"username", "password"}),
        required=frozenset({"username", "password"}),
    )
    for field in result:
        result[field] = _text(result[field], f"{path}.{field}", allow_empty=False)
    return result


def _validate_ws(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {
                "path",
                "headers",
                "max-early-data",
                "early-data-header-name",
                "v2ray-http-upgrade",
                "v2ray-http-upgrade-fast-open",
            }
        ),
    )
    if "path" in result:
        result["path"] = _text(result["path"], f"{path}.path")
    if "headers" in result:
        result["headers"] = _header_map(result["headers"], f"{path}.headers", list_values=False)
    if "max-early-data" in result:
        result["max-early-data"] = _integer(
            result["max-early-data"], f"{path}.max-early-data"
        )
    if "early-data-header-name" in result:
        result["early-data-header-name"] = _text(
            result["early-data-header-name"], f"{path}.early-data-header-name"
        )
    for field in ("v2ray-http-upgrade", "v2ray-http-upgrade-fast-open"):
        if field in result:
            result[field] = _boolean(result[field], f"{path}.{field}")
    return result


def _validate_http_transport(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"method", "path", "headers"}),
    )
    if "method" in result:
        result["method"] = _text(result["method"], f"{path}.method")
    if "path" in result:
        result["path"] = _text_list(result["path"], f"{path}.path")
    if "headers" in result:
        result["headers"] = _header_map(result["headers"], f"{path}.headers", list_values=True)
    return result


def _validate_h2(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(value, path, allowed=frozenset({"host", "path"}))
    if "host" in result:
        result["host"] = _text_list(result["host"], f"{path}.host")
    if "path" in result:
        result["path"] = _text(result["path"], f"{path}.path")
    return result


def _validate_grpc(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {
                "grpc-service-name",
                "grpc-user-agent",
                "ping-interval",
                "max-connections",
                "min-streams",
                "max-streams",
            }
        ),
        required=frozenset({"grpc-service-name"}),
    )
    for field in ("grpc-service-name", "grpc-user-agent"):
        if field in result:
            result[field] = _text(result[field], f"{path}.{field}")
    for field in ("ping-interval", "max-connections", "min-streams", "max-streams"):
        if field in result:
            result[field] = _integer(result[field], f"{path}.{field}")
    return result


def _validate_smux(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {
                "enabled",
                "protocol",
                "max-connections",
                "min-streams",
                "max-streams",
                "padding",
                "statistic",
                "only-tcp",
                "brutal-opts",
            }
        ),
    )
    for field in ("enabled", "padding", "statistic", "only-tcp"):
        if field in result:
            result[field] = _boolean(result[field], f"{path}.{field}")
    if "protocol" in result:
        result["protocol"] = _text(result["protocol"], f"{path}.protocol")
        if result["protocol"] not in {"", "smux", "yamux", "h2mux"}:
            raise ProxySchemaError(f"{path}.protocol is unsupported")
    for field in ("max-connections", "min-streams", "max-streams"):
        if field in result:
            result[field] = _integer(result[field], f"{path}.{field}")
    if "brutal-opts" in result:
        brutal = _exact_mapping(
            result["brutal-opts"],
            f"{path}.brutal-opts",
            allowed=frozenset({"enabled", "up", "down"}),
        )
        if "enabled" in brutal:
            brutal["enabled"] = _boolean(
                brutal["enabled"], f"{path}.brutal-opts.enabled"
            )
        for field in ("up", "down"):
            if field in brutal:
                brutal[field] = _text(brutal[field], f"{path}.brutal-opts.{field}")
        result["brutal-opts"] = brutal
    return result


def _validate_ss_plugin(proxy: dict[str, Any]) -> None:
    plugin = proxy.get("plugin", "")
    if not isinstance(plugin, str):
        raise ProxySchemaError("proxy.plugin must be text")
    if not plugin:
        if "plugin-opts" in proxy:
            raise ProxySchemaError("proxy.plugin-opts requires proxy.plugin")
        return
    if "plugin-opts" not in proxy:
        raise ProxySchemaError("proxy.plugin requires proxy.plugin-opts")
    path = "proxy.plugin-opts"
    if plugin == "obfs":
        opts = _exact_mapping(
            proxy["plugin-opts"],
            path,
            allowed=frozenset({"mode", "host"}),
            required=frozenset({"mode"}),
        )
        for field in opts:
            opts[field] = _text(opts[field], f"{path}.{field}")
        if opts["mode"] not in {"http", "tls"}:
            raise ProxySchemaError(f"{path}.mode is unsupported")
    elif plugin == "v2ray-plugin":
        opts = _exact_mapping(
            proxy["plugin-opts"],
            path,
            allowed=frozenset(
                {
                    "mode",
                    "host",
                    "path",
                    "tls",
                    "ech-opts",
                    "fingerprint",
                    "certificate",
                    "private-key",
                    "headers",
                    "skip-cert-verify",
                    "name-cert-verify",
                    "mux",
                    "v2ray-http-upgrade",
                    "v2ray-http-upgrade-fast-open",
                }
            ),
            required=frozenset({"mode"}),
        )
        for field in ("mode", "host", "path", "fingerprint", "name-cert-verify"):
            if field in opts:
                opts[field] = _text(opts[field], f"{path}.{field}")
        if opts["mode"] != "websocket":
            raise ProxySchemaError(f"{path}.mode is unsupported")
        for field in (
            "tls",
            "skip-cert-verify",
            "mux",
            "v2ray-http-upgrade",
            "v2ray-http-upgrade-fast-open",
        ):
            if field in opts:
                opts[field] = _boolean(opts[field], f"{path}.{field}")
        if "ech-opts" in opts:
            opts["ech-opts"] = _validate_ech(opts["ech-opts"], f"{path}.ech-opts")
        if "headers" in opts:
            opts["headers"] = _header_map(opts["headers"], f"{path}.headers", list_values=False)
        _validate_tls_material(opts, path)
    elif plugin == "shadow-tls":
        opts = _exact_mapping(
            proxy["plugin-opts"],
            path,
            allowed=frozenset(
                {
                    "password",
                    "host",
                    "fingerprint",
                    "certificate",
                    "private-key",
                    "skip-cert-verify",
                    "name-cert-verify",
                    "version",
                    "alpn",
                }
            ),
            required=frozenset({"host"}),
        )
        for field in ("password", "host", "fingerprint", "name-cert-verify"):
            if field in opts:
                opts[field] = _text(opts[field], f"{path}.{field}")
        for field in ("skip-cert-verify",):
            if field in opts:
                opts[field] = _boolean(opts[field], f"{path}.{field}")
        if "version" in opts:
            opts["version"] = _integer(opts["version"], f"{path}.version", maximum=3)
        if "alpn" in opts:
            opts["alpn"] = _text_list(opts["alpn"], f"{path}.alpn")
        _validate_tls_material(opts, path)
    elif plugin == "restls":
        opts = _exact_mapping(
            proxy["plugin-opts"],
            path,
            allowed=frozenset(
                {
                    "password",
                    "host",
                    "version-hint",
                    "restls-script",
                    "fingerprint",
                    "skip-cert-verify",
                    "name-cert-verify",
                }
            ),
            required=frozenset({"password", "host", "version-hint"}),
        )
        for field in opts:
            if field == "skip-cert-verify":
                opts[field] = _boolean(opts[field], f"{path}.{field}")
            else:
                opts[field] = _text(opts[field], f"{path}.{field}")
        if opts["version-hint"] not in {"tls12", "tls13"}:
            raise ProxySchemaError(f"{path}.version-hint is unsupported")
    else:
        raise ProxySchemaError("proxy.plugin is unsupported")
    proxy["plugin-opts"] = opts


def _validate_snell_obfs(value: Any, path: str) -> dict[str, Any]:
    raw = _mapping(value, path)
    mode = raw.get("mode", "")
    if not isinstance(mode, str) or not mode:
        raise ProxySchemaError(f"{path}.mode is required")
    if mode in {"http", "tls"}:
        allowed = frozenset({"mode", "host"})
        required = frozenset({"mode"})
    elif mode == "shadow-tls":
        allowed = frozenset(
            {
                "mode",
                "host",
                "password",
                "fingerprint",
                "certificate",
                "private-key",
                "skip-cert-verify",
                "name-cert-verify",
                "version",
                "alpn",
            }
        )
        required = frozenset({"mode", "host"})
    elif mode == "restls":
        allowed = frozenset(
            {
                "mode",
                "host",
                "password",
                "version-hint",
                "restls-script",
                "fingerprint",
                "skip-cert-verify",
                "name-cert-verify",
            }
        )
        required = frozenset({"mode", "host", "password", "version-hint"})
    elif mode == "jls":
        allowed = frozenset({"mode", "host", "username", "password", "alpn"})
        required = frozenset({"mode", "host", "username", "password"})
    else:
        raise ProxySchemaError(f"{path}.mode is unsupported")
    result = _exact_mapping(raw, path, allowed=allowed, required=required)
    for field in result:
        if field in {"skip-cert-verify"}:
            result[field] = _boolean(result[field], f"{path}.{field}")
        elif field == "version":
            result[field] = _integer(result[field], f"{path}.{field}", maximum=3)
        elif field == "alpn":
            result[field] = _text_list(result[field], f"{path}.{field}")
        elif field not in {"certificate", "private-key"}:
            result[field] = _text(result[field], f"{path}.{field}")
    _validate_tls_material(result, path)
    if result.get("version-hint") not in {None, "tls12", "tls13"}:
        raise ProxySchemaError(f"{path}.version-hint is unsupported")
    return result


def _validate_trojan_ss(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset({"enabled", "method", "password"}),
    )
    if "enabled" in result:
        result["enabled"] = _boolean(result["enabled"], f"{path}.enabled")
    for field in ("method", "password"):
        if field in result:
            result[field] = _text(result[field], f"{path}.{field}")
    return result


def _validate_xhttp_reuse(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {
                "max-concurrency",
                "max-connections",
                "c-max-reuse-times",
                "h-max-request-times",
                "h-max-reusable-secs",
                "h-keep-alive-period",
            }
        ),
    )
    for field in result:
        if field == "h-keep-alive-period":
            result[field] = _integer(result[field], f"{path}.{field}")
        else:
            result[field] = _text(result[field], f"{path}.{field}")
    return result


def _validate_xhttp(value: Any, path: str) -> dict[str, Any]:
    raw = _mapping(value, path)
    if "download-settings" in raw:
        raise ProxySchemaError(
            f"{path}.download-settings is unsupported because it embeds another endpoint"
        )
    allowed = frozenset(
        {
            "path",
            "host",
            "mode",
            "headers",
            "no-grpc-header",
            "x-padding-bytes",
            "x-padding-obfs-mode",
            "x-padding-key",
            "x-padding-header",
            "x-padding-placement",
            "x-padding-method",
            "uplink-http-method",
            "session-placement",
            "session-key",
            "session-table",
            "session-length",
            "seq-placement",
            "seq-key",
            "uplink-data-placement",
            "uplink-data-key",
            "uplink-chunk-size",
            "sc-max-each-post-bytes",
            "sc-min-posts-interval-ms",
            "reuse-settings",
        }
    )
    result = _exact_mapping(raw, path, allowed=allowed)
    for field in result:
        if field == "headers":
            result[field] = _header_map(result[field], f"{path}.headers", list_values=False)
        elif field == "reuse-settings":
            result[field] = _validate_xhttp_reuse(result[field], f"{path}.reuse-settings")
        elif field in {"no-grpc-header", "x-padding-obfs-mode"}:
            result[field] = _boolean(result[field], f"{path}.{field}")
        else:
            result[field] = _text(result[field], f"{path}.{field}")
    if result.get("mode") not in {None, "", "stream-one", "stream-up", "packet-up"}:
        raise ProxySchemaError(f"{path}.mode is unsupported")
    return result


def _validate_tlsmirror_time(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {"base-nanoseconds", "uniform-random-multiplier-nanoseconds"}
        ),
    )
    for field in result:
        result[field] = _integer(result[field], f"{path}.{field}")
    return result


def _validate_tlsmirror(value: Any, path: str) -> dict[str, Any]:
    result = _exact_mapping(
        value,
        path,
        allowed=frozenset(
            {
                "primary-key",
                "explicit-nonce-ciphersuites",
                "defer-instance-derived-write-time",
                "transport-layer-padding",
                "connection-enrolment",
                "embedded-traffic-generator",
                "sequence-watermarking-enabled",
            }
        ),
        required=frozenset({"primary-key"}),
    )
    result["primary-key"] = _text(
        result["primary-key"], f"{path}.primary-key", allow_empty=False
    )
    if "explicit-nonce-ciphersuites" in result:
        raw = result["explicit-nonce-ciphersuites"]
        if not isinstance(raw, list) or len(raw) > 512:
            raise ProxySchemaError(f"{path}.explicit-nonce-ciphersuites must be a bounded list")
        result["explicit-nonce-ciphersuites"] = [
            _integer(item, f"{path}.explicit-nonce-ciphersuites[{index}]", maximum=65_535)
            for index, item in enumerate(raw)
        ]
    if "defer-instance-derived-write-time" in result:
        result["defer-instance-derived-write-time"] = _validate_tlsmirror_time(
            result["defer-instance-derived-write-time"],
            f"{path}.defer-instance-derived-write-time",
        )
    if "transport-layer-padding" in result:
        padding = _exact_mapping(
            result["transport-layer-padding"],
            f"{path}.transport-layer-padding",
            allowed=frozenset({"enabled"}),
        )
        if "enabled" in padding:
            padding["enabled"] = _boolean(
                padding["enabled"], f"{path}.transport-layer-padding.enabled"
            )
        result["transport-layer-padding"] = padding
    if "connection-enrolment" in result:
        enrolment = _exact_mapping(
            result["connection-enrolment"],
            f"{path}.connection-enrolment",
            allowed=frozenset({"primary-ingress-outbound", "primary-egress-outbound"}),
        )
        for field in enrolment:
            enrolment[field] = _text(
                enrolment[field], f"{path}.connection-enrolment.{field}"
            )
        result["connection-enrolment"] = enrolment
    if "sequence-watermarking-enabled" in result:
        result["sequence-watermarking-enabled"] = _boolean(
            result["sequence-watermarking-enabled"],
            f"{path}.sequence-watermarking-enabled",
        )
    if "embedded-traffic-generator" in result:
        generator = _exact_mapping(
            result["embedded-traffic-generator"],
            f"{path}.embedded-traffic-generator",
            allowed=frozenset({"steps"}),
        )
        if "steps" in generator:
            raw_steps = generator["steps"]
            if not isinstance(raw_steps, list) or len(raw_steps) > 128:
                raise ProxySchemaError(f"{path}.embedded-traffic-generator.steps is invalid")
            steps: list[dict[str, Any]] = []
            for index, raw_step in enumerate(raw_steps):
                step_path = f"{path}.embedded-traffic-generator.steps[{index}]"
                step = _exact_mapping(
                    raw_step,
                    step_path,
                    allowed=frozenset(
                        {
                            "name",
                            "host",
                            "path",
                            "method",
                            "headers",
                            "next-step",
                            "connection-ready",
                            "connection-recall-exit",
                            "wait-time",
                            "h2-do-not-wait-for-download-finish",
                        }
                    ),
                )
                for field in ("name", "host", "path", "method"):
                    if field in step:
                        step[field] = _text(step[field], f"{step_path}.{field}")
                for field in (
                    "connection-ready",
                    "connection-recall-exit",
                    "h2-do-not-wait-for-download-finish",
                ):
                    if field in step:
                        step[field] = _boolean(step[field], f"{step_path}.{field}")
                if "wait-time" in step:
                    step["wait-time"] = _validate_tlsmirror_time(
                        step["wait-time"], f"{step_path}.wait-time"
                    )
                if "headers" in step:
                    raw_headers = step["headers"]
                    if not isinstance(raw_headers, list) or len(raw_headers) > 128:
                        raise ProxySchemaError(f"{step_path}.headers is invalid")
                    headers: list[dict[str, Any]] = []
                    for header_index, raw_header in enumerate(raw_headers):
                        header_path = f"{step_path}.headers[{header_index}]"
                        header = _exact_mapping(
                            raw_header,
                            header_path,
                            allowed=frozenset({"name", "value", "values"}),
                            required=frozenset({"name"}),
                        )
                        header["name"] = _text(
                            header["name"], header_path + ".name", allow_empty=False
                        )
                        if _HEADER_NAME_RE.fullmatch(header["name"]) is None:
                            raise ProxySchemaError(f"{header_path}.name is invalid")
                        if "value" in header and "values" in header:
                            raise ProxySchemaError(
                                f"{header_path} cannot contain both value and values"
                            )
                        if "value" in header:
                            header["value"] = _text(
                                header["value"], header_path + ".value", max_length=16_384
                            )
                        if "values" in header:
                            header["values"] = _text_list(
                                header["values"], header_path + ".values"
                            )
                        headers.append(header)
                    step["headers"] = headers
                if "next-step" in step:
                    raw_next = step["next-step"]
                    if not isinstance(raw_next, list) or len(raw_next) > 128:
                        raise ProxySchemaError(f"{step_path}.next-step is invalid")
                    next_steps: list[dict[str, Any]] = []
                    for next_index, raw_candidate in enumerate(raw_next):
                        candidate_path = f"{step_path}.next-step[{next_index}]"
                        candidate = _exact_mapping(
                            raw_candidate,
                            candidate_path,
                            allowed=frozenset({"weight", "goto-location"}),
                        )
                        for field in candidate:
                            candidate[field] = _integer(
                                candidate[field], candidate_path + f".{field}"
                            )
                        next_steps.append(candidate)
                    step["next-step"] = next_steps
                steps.append(step)
            generator["steps"] = steps
        result["embedded-traffic-generator"] = generator
    return result


def _validate_nested_fields(proxy: dict[str, Any], protocol: str) -> None:
    if "smux" in proxy:
        if protocol not in _TCP_SMUX_PROTOCOLS:
            raise ProxySchemaError(f"proxy.smux is unsupported for {protocol}")
        proxy["smux"] = _validate_smux(proxy["smux"], "proxy.smux")
    if protocol == "ss":
        _validate_ss_plugin(proxy)
    if "ech-opts" in proxy:
        proxy["ech-opts"] = _validate_ech(proxy["ech-opts"], "proxy.ech-opts")
    if "shadow-tls-opts" in proxy:
        proxy["shadow-tls-opts"] = _validate_shadow_tls(
            proxy["shadow-tls-opts"], "proxy.shadow-tls-opts"
        )
    if "restls-opts" in proxy:
        proxy["restls-opts"] = _validate_restls(proxy["restls-opts"], "proxy.restls-opts")
    if "jls-opts" in proxy:
        proxy["jls-opts"] = _validate_jls(proxy["jls-opts"], "proxy.jls-opts")
    if "reality-opts" in proxy:
        proxy["reality-opts"] = _validate_reality(proxy["reality-opts"], "proxy.reality-opts")
    if "ws-opts" in proxy:
        proxy["ws-opts"] = _validate_ws(proxy["ws-opts"], "proxy.ws-opts")
    if "http-opts" in proxy:
        proxy["http-opts"] = _validate_http_transport(proxy["http-opts"], "proxy.http-opts")
    if "h2-opts" in proxy:
        proxy["h2-opts"] = _validate_h2(proxy["h2-opts"], "proxy.h2-opts")
    if "grpc-opts" in proxy:
        proxy["grpc-opts"] = _validate_grpc(proxy["grpc-opts"], "proxy.grpc-opts")
    if "xhttp-opts" in proxy:
        proxy["xhttp-opts"] = _validate_xhttp(proxy["xhttp-opts"], "proxy.xhttp-opts")
    if "ss-opts" in proxy:
        proxy["ss-opts"] = _validate_trojan_ss(proxy["ss-opts"], "proxy.ss-opts")
    if "obfs-opts" in proxy:
        proxy["obfs-opts"] = _validate_snell_obfs(proxy["obfs-opts"], "proxy.obfs-opts")
    if "headers" in proxy:
        proxy["headers"] = _header_map(proxy["headers"], "proxy.headers", list_values=False)
    if "ws-headers" in proxy:
        proxy["ws-headers"] = _header_map(
            proxy["ws-headers"], "proxy.ws-headers", list_values=False
        )
    if "tlsmirror-opts" in proxy:
        proxy["tlsmirror-opts"] = _validate_tlsmirror(
            proxy["tlsmirror-opts"], "proxy.tlsmirror-opts"
        )


def _validate_transport_binding(proxy: Mapping[str, Any], protocol: str) -> None:
    network = proxy.get("network")
    allowed_networks: dict[str, frozenset[str]] = {
        "vmess": frozenset({"ws", "h2", "http", "grpc", "httpupgrade"}),
        "vless": frozenset({"ws", "tcp", "grpc", "http", "h2", "xhttp"}),
        "trojan": frozenset({"tcp", "ws", "grpc"}),
    }
    if network is not None:
        if not isinstance(network, str) or network not in allowed_networks[protocol]:
            raise ProxySchemaError(f"proxy.network is unsupported for {protocol}")
    bindings = {
        "ws-opts": frozenset({"ws", "httpupgrade"}),
        "http-opts": frozenset({"http"}),
        "h2-opts": frozenset({"h2"}),
        "grpc-opts": frozenset({"grpc"}),
        "xhttp-opts": frozenset({"xhttp"}),
        "ws-headers": frozenset({"ws"}),
    }
    for field, networks in bindings.items():
        if field in proxy and network not in networks:
            raise ProxySchemaError(f"proxy.{field} does not match proxy.network")


def _validate_protocol_semantics(proxy: dict[str, Any], protocol: str) -> None:
    if protocol in {"vmess", "vless", "trojan"}:
        _validate_transport_binding(proxy, protocol)
    if protocol == "tuic":
        token = proxy.get("token")
        uuid = proxy.get("uuid")
        password = proxy.get("password")
        if token:
            if uuid or password:
                raise ProxySchemaError("TUIC token authentication cannot include UUID credentials")
        elif not uuid or not password:
            raise ProxySchemaError("TUIC requires token or UUID plus password")
    if protocol == "hysteria" and not proxy.get("auth") and not proxy.get("auth-str"):
        raise ProxySchemaError("Hysteria requires auth or auth-str")
    if protocol == "hysteria2" and "realm-opts" in proxy:
        # Kept explicit even though realm-opts is outside the allowlist: it
        # embeds a second URL and therefore needs its own endpoint policy.
        raise ProxySchemaError("Hysteria2 realm-opts is unsupported")
    if protocol == "hysteria2" and proxy.get("obfs") not in {None, "", "salamander", "gecko"}:
        raise ProxySchemaError("Hysteria2 obfs is unsupported")
    if protocol == "hysteria2" and proxy.get("obfs") and not proxy.get("obfs-password"):
        raise ProxySchemaError("Hysteria2 obfs requires obfs-password")
    if protocol == "hysteria" and proxy.get("protocol") not in {
        None,
        "",
        "udp",
        "wechat-video",
        "faketcp",
    }:
        raise ProxySchemaError("Hysteria protocol is unsupported")
    if protocol == "tuic":
        if proxy.get("udp-relay-mode") not in {None, "", "native", "quic"}:
            raise ProxySchemaError("TUIC udp-relay-mode is unsupported")
        if proxy.get("congestion-controller") not in {None, "", "cubic", "bbr", "new_reno"}:
            raise ProxySchemaError("TUIC congestion-controller is unsupported")
    if proxy.get("ip-version") not in {None, "", *_IP_VERSIONS}:
        raise ProxySchemaError("proxy.ip-version is unsupported")
    if proxy.get("packet-encoding") not in {None, "", "packetaddr", "xudp"}:
        raise ProxySchemaError("proxy.packet-encoding is unsupported")
    if protocol == "vless" and proxy.get("flow") not in {None, "", "xtls-rprx-vision"}:
        raise ProxySchemaError("VLESS flow is unsupported")


def validate_proxy_schema(
    proxy: Mapping[str, Any],
    *,
    require_name: bool = True,
) -> dict[str, Any]:
    """Return a normalized deep copy after strict protocol/schema validation.

    ``require_name=False`` is intended only for already-extracted connection
    projections.  A normal Clash proxy should always use the default.
    """

    result = _mapping(proxy, "proxy")
    if "dialer-proxy" in result:
        raise ProxySchemaError("proxy.dialer-proxy is unsupported")
    protocol = result.get("type")
    if not isinstance(protocol, str) or protocol not in SUPPORTED_PROXY_TYPES:
        raise ProxySchemaError("proxy.type is unsupported")
    _normalize_aliases(result, protocol)

    allowed = _COMMON_FIELDS | _PROTOCOL_FIELDS[protocol]
    if not require_name:
        allowed = allowed - {"name"}
    unknown = sorted(set(result) - allowed)
    if "realm-opts" in unknown and protocol == "hysteria2":
        raise ProxySchemaError("Hysteria2 realm-opts is unsupported")
    if unknown:
        raise ProxySchemaError(
            f"proxy contains unsupported fields for {protocol}: {', '.join(unknown)}"
        )

    required = {"type", "server", "port", *_REQUIRED_FIELDS[protocol]}
    if require_name:
        required.add("name")
    missing = sorted(required - set(result))
    if missing:
        raise ProxySchemaError(f"proxy is missing required fields: {', '.join(missing)}")

    for field, value in list(result.items()):
        path = f"proxy.{field}"
        if field in {"certificate", "private-key"}:
            # Inline PEM intentionally contains line breaks, so it cannot use
            # the generic single-line text validator.  Pairing, size, labels,
            # and unsafe bytes are checked together below.
            continue
        if field == "port":
            result[field] = _integer(value, path, minimum=1, maximum=65_535)
        elif field in _BOOL_FIELDS:
            result[field] = _boolean(value, path)
        elif field in _INT_FIELDS:
            result[field] = _integer(value, path)
        elif field in _TEXT_LIST_FIELDS:
            result[field] = _text_list(value, path)
        elif field in _MAPPING_FIELDS:
            if not isinstance(value, Mapping):
                raise ProxySchemaError(f"{path} must be a mapping")
        else:
            result[field] = _text(
                value,
                path,
                allow_empty=field not in required,
            )

    _validate_nested_fields(result, protocol)
    _validate_tls_material(result, "proxy")
    _validate_protocol_semantics(result, protocol)
    return result


def connection_proxy_projection(proxy: Mapping[str, Any]) -> dict[str, Any]:
    """Return the strict connection mapping used for identity and deduplication."""

    validated = validate_proxy_schema(proxy, require_name="name" in proxy)
    validated.pop("name", None)
    return validated


__all__ = [
    "PROXY_SCHEMA_POLICY_VERSION",
    "SUPPORTED_PROXY_TYPES",
    "ProxySchemaError",
    "connection_proxy_projection",
    "validate_proxy_schema",
]
