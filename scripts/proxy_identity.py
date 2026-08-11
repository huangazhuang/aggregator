#!/usr/bin/env python3
"""Shared canonical proxy identity and public HMAC identifiers for GMGN V2.

The full SHA-256 proxy fingerprint is an internal value.  Public artifacts must
use the domain-separated HMAC identifiers returned by this module instead.
This module deliberately performs no DNS, HTTP, Mihomo, or publication I/O.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


IdentityKind = Literal["candidate", "server", "endpoint", "exit", "asn"]

IDENTITY_VECTOR_KIND = "gmgn-identity-test-vector"
IDENTITY_VECTOR_SCHEMA_VERSION = 1
IDENTITY_KEY_ENV = "GMGN_IDENTITY_HMAC_KEY"
IDENTITY_KEY_VERSION_ENV = "GMGN_IDENTITY_KEY_VERSION"
IDENTITY_EPOCH_ENV = "GMGN_IDENTITY_EPOCH"
PUBLIC_ID_HEX_LENGTH = 24
VERSION_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

PUBLIC_ID_PREFIXES: dict[IdentityKind, str] = {
    "candidate": "c1_",
    "server": "srv1_",
    "endpoint": "ep1_",
    "exit": "exit1_",
    "asn": "asn1_",
}

# These top-level fields describe collection, measurement, display, or derived
# state rather than the connection identity.  All other validated proxy fields
# are retained, including protocol, credentials, transport, TLS, and REALITY.
NON_CONNECTION_PROXY_FIELDS = frozenset(
    {
        "name",
        "sub",
        "source",
        "source_id",
        "source_ids",
        "provenance",
        "liveness",
        "chatgpt",
        "country",
        "region",
        "location",
        "region_hints",
        "region_evidence",
        "protected_asia",
        "github_tested",
        "github_test_result",
        "first_seen_at",
        "last_seen_at",
        "candidate_id",
        "server_id",
        "endpoint_id",
        "exit_id",
        "output_name",
        "fingerprint",
        "selection_tier",
        "tier",
        "summary",
        "metrics",
        "delay",
        "delay_ms",
        "latency",
        "gmgn",
    }
)


class IdentityError(ValueError):
    """Raised when an identity input or version contract is invalid."""


class IdentityCollisionError(IdentityError):
    """Raised when a truncated public identifier maps to two private values."""


@dataclass(frozen=True)
class IdentitySettings:
    """Required identity inputs kept distinct for migration and key rotation."""

    key: bytes
    identity_key_version: str
    identity_epoch: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "key", _normalize_key(self.key))
        object.__setattr__(
            self,
            "identity_key_version",
            _version_token(self.identity_key_version, "identity_key_version"),
        )
        object.__setattr__(
            self,
            "identity_epoch",
            _version_token(self.identity_epoch, "identity_epoch"),
        )

    @classmethod
    def from_environment(
        cls,
        environment: Mapping[str, str] | None = None,
    ) -> "IdentitySettings":
        env = os.environ if environment is None else environment
        key = env.get(IDENTITY_KEY_ENV, "")
        key_version = env.get(IDENTITY_KEY_VERSION_ENV, "")
        epoch = env.get(IDENTITY_EPOCH_ENV, "")
        if not key:
            raise IdentityError(f"{IDENTITY_KEY_ENV} is required")
        return cls(
            key=_normalize_key(key),
            identity_key_version=_version_token(
                key_version, IDENTITY_KEY_VERSION_ENV
            ),
            identity_epoch=_version_token(epoch, IDENTITY_EPOCH_ENV),
        )


def _version_token(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise IdentityError(f"{label} must be a non-empty version token")
    token = value
    if not VERSION_TOKEN_RE.fullmatch(token):
        raise IdentityError(f"{label} must be a non-empty version token")
    return token


def validate_identity_version(value: Any, label: str = "identity version") -> str:
    """Validate a public identity key-version or epoch token."""

    return _version_token(value, label)


def _normalize_key(key: bytes | bytearray | str) -> bytes:
    if isinstance(key, str):
        normalized = key.encode("utf-8")
    elif isinstance(key, (bytes, bytearray)):
        normalized = bytes(key)
    else:
        raise IdentityError("identity HMAC key must be bytes or text")
    if not normalized:
        raise IdentityError("identity HMAC key is required")
    return normalized


def _canonical_json_value(value: Any, path: str) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        if any(not isinstance(key, str) for key in value):
            raise IdentityError(f"{path} contains a non-string mapping key")
        for key in sorted(value):
            normalized[key] = _canonical_json_value(value[key], f"{path}.{key}")
        return normalized
    if isinstance(value, list):
        return [
            _canonical_json_value(item, f"{path}[{index}]")
            for index, item in enumerate(value)
        ]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise IdentityError(f"{path} contains a non-finite number")
        return value
    raise IdentityError(f"{path} contains an unsupported value type")


def canonical_proxy_projection(proxy: Mapping[str, Any]) -> dict[str, Any]:
    """Return connection-only proxy fields in a JSON-canonicalizable mapping."""

    if not isinstance(proxy, Mapping):
        raise IdentityError("proxy must be a mapping")
    if any(not isinstance(key, str) for key in proxy):
        raise IdentityError("proxy contains a non-string mapping key")
    projected = {
        key: value
        for key, value in proxy.items()
        if key not in NON_CONNECTION_PROXY_FIELDS
        and not key.startswith("_")
    }
    if not projected:
        raise IdentityError("proxy contains no connection identity fields")
    return _canonical_json_value(projected, "proxy")


def canonical_proxy_bytes(proxy: Mapping[str, Any]) -> bytes:
    """Serialize the connection identity using stable UTF-8 compact JSON."""

    try:
        serialized = json.dumps(
            canonical_proxy_projection(proxy),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise IdentityError("proxy cannot be encoded canonically") from exc
    return serialized.encode("utf-8")


def canonical_proxy_fingerprint(proxy: Mapping[str, Any]) -> str:
    """Return the private full SHA-256 fingerprint of a validated proxy."""

    return hashlib.sha256(canonical_proxy_bytes(proxy)).hexdigest()


def canonical_server(server: Any) -> str:
    """Normalize an already validated public server host or IP."""

    if not isinstance(server, str) or server != server.strip():
        raise IdentityError("server must be a non-empty public host")
    value = server
    if not value or "\x00" in value or any(ord(char) < 32 for char in value):
        raise IdentityError("server must be a non-empty public host")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        hostname = value.rstrip(".")
        if not hostname:
            raise IdentityError("server must be a non-empty public host")
        try:
            ascii_hostname = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise IdentityError("server hostname cannot be canonicalized") from exc
        if len(ascii_hostname) > 253 or any(
            not label or len(label) > 63 for label in ascii_hostname.split(".")
        ):
            raise IdentityError("server hostname is malformed")
        return ascii_hostname


def canonical_port(port: Any) -> int:
    if isinstance(port, bool):
        raise IdentityError("port must be an integer from 1 to 65535")
    try:
        value = int(port)
    except (TypeError, ValueError) as exc:
        raise IdentityError("port must be an integer from 1 to 65535") from exc
    if value < 1 or value > 65535 or (
        isinstance(port, float) and not port.is_integer()
    ):
        raise IdentityError("port must be an integer from 1 to 65535")
    return value


def canonical_endpoint(server: Any, port: Any) -> str:
    """Return the stable server/port material used by the endpoint domain."""

    return f"{canonical_server(server)}\0{canonical_port(port)}"


def canonical_public_ip(public_ip: Any) -> str:
    """Normalize a globally routable public IP for the exit identity domain."""

    if not isinstance(public_ip, str):
        raise IdentityError("exit IP is invalid")
    value = public_ip.strip()
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise IdentityError("exit IP is invalid") from exc
    if (
        not address.is_global
        or address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise IdentityError("exit IP must be globally routable")
    return address.compressed.lower()


def canonical_asn(asn: Any) -> str:
    """Normalize an autonomous-system number without exposing provider text."""

    if isinstance(asn, bool):
        raise IdentityError("ASN is invalid")
    if isinstance(asn, int):
        number = asn
    elif isinstance(asn, str) and asn == asn.strip():
        match = re.fullmatch(r"(?:AS)?([1-9][0-9]*)", asn, flags=re.IGNORECASE)
        if match is None:
            raise IdentityError("ASN is invalid")
        number = int(match.group(1))
    else:
        raise IdentityError("ASN is invalid")
    if not 1 <= number <= 4_294_967_295:
        raise IdentityError("ASN is invalid")
    return f"AS{number}"


def _identity_digest(
    kind: IdentityKind,
    material: bytes,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> bytes:
    if kind not in PUBLIC_ID_PREFIXES:
        raise IdentityError("unsupported public identity domain")
    normalized_key = _normalize_key(key)
    key_version = _version_token(identity_key_version, "identity_key_version")
    epoch = _version_token(identity_epoch, "identity_epoch")
    message = b"\0".join(
        (kind.encode("ascii"), epoch.encode("utf-8"), key_version.encode("utf-8"), material)
    )
    return hmac.new(normalized_key, message, hashlib.sha256).digest()


def _public_identity(
    kind: IdentityKind,
    material: bytes,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    digest = _identity_digest(
        kind,
        material,
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )
    return f"{PUBLIC_ID_PREFIXES[kind]}{digest[:12].hex()}"


def candidate_id(
    proxy_or_fingerprint: Mapping[str, Any] | str,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    """Return the public candidate ID for a proxy or private fingerprint."""

    if isinstance(proxy_or_fingerprint, Mapping):
        fingerprint = canonical_proxy_fingerprint(proxy_or_fingerprint)
    else:
        fingerprint = validate_proxy_fingerprint(proxy_or_fingerprint)
    return _public_identity(
        "candidate",
        bytes.fromhex(fingerprint),
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )


def server_id(
    server: Any,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    return _public_identity(
        "server",
        canonical_server(server).encode("ascii"),
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )


def endpoint_id(
    server: Any,
    port: Any,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    material = canonical_endpoint(server, port).encode("ascii")
    return _public_identity(
        "endpoint",
        material,
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )


def exit_id(
    public_ip: Any,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    return _public_identity(
        "exit",
        canonical_public_ip(public_ip).encode("ascii"),
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )


def asn_id(
    asn: Any,
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
) -> str:
    return _public_identity(
        "asn",
        canonical_asn(asn).encode("ascii"),
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
    )


def validate_public_id(value: Any, kind: IdentityKind | None = None) -> str:
    if not isinstance(value, str) or value != value.strip():
        raise IdentityError("public identity has an invalid format")
    candidate = value
    if kind is not None and kind not in PUBLIC_ID_PREFIXES:
        raise IdentityError("unsupported public identity domain")
    kinds = (kind,) if kind is not None else tuple(PUBLIC_ID_PREFIXES)
    if not any(
        re.fullmatch(
            re.escape(PUBLIC_ID_PREFIXES[item]) + rf"[0-9a-f]{{{PUBLIC_ID_HEX_LENGTH}}}",
            candidate,
        )
        for item in kinds
    ):
        raise IdentityError("public identity has an invalid format")
    return candidate


def validate_proxy_fingerprint(value: Any) -> str:
    """Validate an internal full SHA-256 fingerprint without normalizing it."""

    if not isinstance(value, str) or not FINGERPRINT_RE.fullmatch(value):
        raise IdentityError("candidate fingerprint must be a full SHA-256 hex value")
    return value


def compute_public_ids(
    proxy: Mapping[str, Any],
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
    public_ip: Any | None = None,
) -> dict[str, str]:
    """Compute the public IDs shared by GitHub and CNB identity preflight."""

    if "server" not in proxy or "port" not in proxy:
        raise IdentityError("proxy must contain server and port")
    result = {
        "candidate_id": candidate_id(
            proxy,
            key=key,
            identity_key_version=identity_key_version,
            identity_epoch=identity_epoch,
        ),
        "server_id": server_id(
            proxy["server"],
            key=key,
            identity_key_version=identity_key_version,
            identity_epoch=identity_epoch,
        ),
        "endpoint_id": endpoint_id(
            proxy["server"],
            proxy["port"],
            key=key,
            identity_key_version=identity_key_version,
            identity_epoch=identity_epoch,
        ),
    }
    if public_ip is not None:
        result["exit_id"] = exit_id(
            public_ip,
            key=key,
            identity_key_version=identity_key_version,
            identity_epoch=identity_epoch,
        )
    return result


def verify_identity_preflight(
    proxy: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    key: bytes | bytearray | str,
    identity_key_version: str,
    identity_epoch: str,
    public_ip: Any | None = None,
) -> dict[str, str]:
    """Recompute and compare exact public IDs without exposing private inputs."""

    actual = compute_public_ids(
        proxy,
        key=key,
        identity_key_version=identity_key_version,
        identity_epoch=identity_epoch,
        public_ip=public_ip,
    )
    normalized_expected = {name: str(value) for name, value in expected.items()}
    if normalized_expected != actual:
        raise IdentityError("identity preflight mismatch")
    return actual


def assert_unique_public_id_bindings(
    bindings: Iterable[tuple[str, str]],
) -> None:
    """Fail closed if one public ID is bound to distinct private material."""

    seen: dict[str, str] = {}
    for public_id, private_binding in bindings:
        normalized_id = validate_public_id(public_id)
        private_value = str(private_binding)
        previous = seen.get(normalized_id)
        if previous is not None and not hmac.compare_digest(previous, private_value):
            raise IdentityCollisionError("public identity collision detected")
        seen[normalized_id] = private_value


def load_identity_test_vector(path: str | Path) -> dict[str, Any]:
    """Load and strictly validate the public non-production identity fixture."""

    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IdentityError("identity test vector is invalid JSON") from exc
    required = {
        "kind",
        "schema_version",
        "identity_key_version",
        "identity_epoch",
        "test_hmac_key_hex",
        "proxy",
        "public_ipv4",
        "public_ipv6",
        "expected",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise IdentityError("identity test vector fields are incomplete or unexpected")
    if payload["kind"] != IDENTITY_VECTOR_KIND:
        raise IdentityError("unsupported identity test vector kind")
    if payload["schema_version"] != IDENTITY_VECTOR_SCHEMA_VERSION:
        raise IdentityError("unsupported identity test vector schema")
    if not isinstance(payload["proxy"], dict) or not isinstance(payload["expected"], dict):
        raise IdentityError("identity test vector payload is malformed")
    try:
        key = bytes.fromhex(str(payload["test_hmac_key_hex"]))
    except ValueError as exc:
        raise IdentityError("identity test vector key is malformed") from exc
    if not key:
        raise IdentityError("identity test vector key is empty")
    payload["_test_key"] = key
    return payload


def verify_identity_test_vector(path: str | Path) -> dict[str, str]:
    """Verify the fixed cross-platform candidate/server/endpoint/exit vector."""

    payload = load_identity_test_vector(path)
    expected = dict(payload["expected"])
    ipv4_expected = {key: value for key, value in expected.items() if key != "exit_id_ipv6"}
    actual = verify_identity_preflight(
        payload["proxy"],
        ipv4_expected,
        key=payload["_test_key"],
        identity_key_version=str(payload["identity_key_version"]),
        identity_epoch=str(payload["identity_epoch"]),
        public_ip=payload["public_ipv4"],
    )
    ipv6 = exit_id(
        payload["public_ipv6"],
        key=payload["_test_key"],
        identity_key_version=str(payload["identity_key_version"]),
        identity_epoch=str(payload["identity_epoch"]),
    )
    if ipv6 != str(expected.get("exit_id_ipv6") or ""):
        raise IdentityError("identity test vector mismatch")
    return {**actual, "exit_id_ipv6": ipv6}


__all__ = [
    "IDENTITY_EPOCH_ENV",
    "IDENTITY_KEY_ENV",
    "IDENTITY_KEY_VERSION_ENV",
    "IdentityCollisionError",
    "IdentityError",
    "IdentitySettings",
    "asn_id",
    "assert_unique_public_id_bindings",
    "candidate_id",
    "canonical_endpoint",
    "canonical_port",
    "canonical_proxy_bytes",
    "canonical_proxy_fingerprint",
    "canonical_proxy_projection",
    "canonical_public_ip",
    "canonical_asn",
    "canonical_server",
    "compute_public_ids",
    "endpoint_id",
    "exit_id",
    "load_identity_test_vector",
    "server_id",
    "validate_public_id",
    "validate_identity_version",
    "validate_proxy_fingerprint",
    "verify_identity_preflight",
    "verify_identity_test_vector",
]
