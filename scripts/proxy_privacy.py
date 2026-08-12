"""Shared privacy helpers for public proxy aliases and display-name fallbacks.

Raw proxy names are useful inside private provenance staging, but they are not
safe public metadata by default.  This module owns the conservative, pure
projection used at that boundary: aliases containing endpoints or credentials
are rejected as a whole, while stable human labels such as ``JP 01`` remain
available.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import Any


PUBLIC_ALIAS_MAX_LENGTH = 96
REGION_ORDER = ("HK", "JP", "KR", "SG", "TW")

CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
WHITESPACE_RE = re.compile(r"\s+")
URL_RE = re.compile(
    r"(?:\b[a-z][a-z0-9+.-]{1,31}://|\bwww\.)",
    flags=re.IGNORECASE,
)
IPV4_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
IPV6_CHUNK_RE = re.compile(r"[0-9A-Za-z_.%\[\]-]*:[0-9A-Za-z_.:%\[\]-]*")
HOSTNAME_CANDIDATE_RE = re.compile(
    r"(?<![\w-])(?:[^\W_](?:[\w-]{0,61}[^\W_])?\.)+"
    r"[^\W_](?:[\w-]{0,61}[^\W_])?\.?(?![\w-])",
    flags=re.UNICODE,
)
EXPLICIT_COLON_PORT_RE = re.compile(r"(?<!:):\s*(\d{1,5})(?!\d)")
EXPLICIT_NAMED_PORT_RE = re.compile(
    r"(?i)(?<![\w-])(?:proxy[ _-]*port|server[ _-]*port|port|端口)"
    r"\s*(?:[:=]\s*)?(\d{1,5})(?!\d)"
)
DECIMAL_TOKEN_RE = re.compile(r"(?<!\d)(\d{1,5})(?!\d)")
DYNAMIC_ALIAS_SUFFIX_RE = re.compile(
    r"(?:\s*[-|·/]\s*)?(?:"
    r"\d+(?:\.\d+)?\s*ms|timeout|\d+(?:\.\d+)?\s*%|"
    r"delay\s*[:=].*|rank\s*#?\d+"
    r")\s*$",
    flags=re.IGNORECASE,
)
EXPLICIT_SECRET_RE = re.compile(
    r"(?i)(?<![\w-])(?:"
    r"password|passwd|passphrase|token|access[ _-]*token|refresh[ _-]*token|"
    r"secret|api[ _-]*key|private[ _-]*key|client[ _-]*key|psk|uuid|"
    r"auth(?:[ _-]*str)?|authorization|proxy[ _-]*authorization|cookie"
    r")\s*(?:[:=]|\bis\b)\s*\S+"
)

SENSITIVE_KEY_EXACT = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "obfs-password",
        "token",
        "access-token",
        "refresh-token",
        "api-token",
        "uuid",
        "psk",
        "pre-shared-key",
        "auth",
        "auth-str",
        "authorization",
        "proxy-authorization",
        "username",
        "private-key",
        "primary-key",
        "client-key",
        "seq-key",
        "session-key",
        "uplink-data-key",
        "x-padding-key",
        "cookie",
        "set-cookie",
        "secret",
        "api-key",
    }
)
SENSITIVE_KEY_SUFFIXES = (
    "-password",
    "-passwd",
    "-passphrase",
    "-token",
    "-secret",
    "-psk",
    "-uuid",
    "-auth",
    "-username",
    "-private-key",
    "-api-key",
    "-authorization",
    "-cookie",
)
NON_SECRET_KEY_EXACT = frozenset(
    {
        # REALITY public material and Mihomo's TLS client fingerprint affect
        # connection identity but are not credentials.
        "public-key",
        "fingerprint",
    }
)
AUTH_SCHEME_RE = re.compile(r"(?i)^(bearer|basic|token|digest)\s+(.+)$")
PEM_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN\s+(?P<label>[A-Z0-9 ]*PRIVATE KEY)-----"
    r"(?P<body>.*?)"
    r"-----END\s+(?P=label)-----",
    flags=re.IGNORECASE | re.DOTALL,
)
PEM_BODY_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{6,}(?![A-Za-z0-9+/=])")
SAFE_PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,31}$", flags=re.IGNORECASE)
VLESS_KEY_ENCRYPTION_PREFIX = "mlkem768x25519plus"
VLESS_KEY_ENCRYPTION_PADDING_LIMIT = 20
VLESS_KEY_ENCRYPTION_KEY_SIZES = frozenset({32, 1184})
HEADER_CONTAINER_KEYS = frozenset({"header", "headers", "ws-headers"})
PEM_FRAGMENT_LENGTH = 12


def _normalize_alias_unbounded(value: Any, *, strip_dynamic: bool) -> str:
    alias = CONTROL_RE.sub(" ", str(value or ""))
    alias = WHITESPACE_RE.sub(" ", alias).strip(" -|·/[]()")
    if strip_dynamic:
        previous = None
        while alias and alias != previous:
            previous = alias
            alias = DYNAMIC_ALIAS_SUFFIX_RE.sub("", alias).strip(" -|·/")
    return alias


def normalize_public_alias(
    value: Any,
    *,
    strip_dynamic: bool = True,
    max_length: int = PUBLIC_ALIAS_MAX_LENGTH,
) -> str:
    """Normalize a display alias without deciding whether it is private.

    Security checks must inspect the untruncated value.  Callers publishing a
    proxy-derived alias should therefore use :func:`sanitize_public_proxy_alias`
    rather than treating this formatting helper as a privacy validator.
    """

    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1:
        raise ValueError("max_length must be a positive integer")
    alias = _normalize_alias_unbounded(value, strip_dynamic=strip_dynamic)
    return alias[:max_length].rstrip()


def _valid_port(value: str) -> bool:
    try:
        port = int(value, 10)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def _canonical_actual_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    if isinstance(value, str) and value == value.strip() and value.isdecimal():
        parsed = int(value, 10)
        return parsed if 1 <= parsed <= 65535 else None
    return None


def _contains_ipv4(text: str) -> bool:
    for match in IPV4_CANDIDATE_RE.finditer(text):
        try:
            ipaddress.IPv4Address(match.group(0))
            return True
        except ipaddress.AddressValueError:
            continue
    return False


def _ipv6_candidate_variants(chunk: str) -> Iterator[str]:
    candidate = chunk.strip("[](){}<>,;|\"'")
    if not candidate or candidate.count(":") < 2:
        return
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]

    # Most aliases contain a delimited address and succeed immediately.  The
    # suffix scan also catches a value joined to a non-hex word, without using
    # one giant IPv6 regular expression that is easy to get subtly wrong.
    yielded: set[str] = set()
    for start in range(len(candidate)):
        if candidate[start] not in "0123456789abcdefABCDEF:":
            continue
        value = candidate[start:]
        if value.count(":") < 2:
            continue
        for end in range(len(value), 1, -1):
            item = value[:end].rstrip(".-")
            if item.count(":") < 2 or item in yielded:
                continue
            yielded.add(item)
            yield item


def _contains_ipv6(text: str) -> bool:
    for match in IPV6_CHUNK_RE.finditer(text):
        for candidate in _ipv6_candidate_variants(match.group(0)):
            address = candidate.split("%", 1)[0]
            try:
                if isinstance(ipaddress.ip_address(address), ipaddress.IPv6Address):
                    return True
            except ValueError:
                continue
    return False


def _is_valid_hostname(candidate: str) -> bool:
    hostname = candidate.rstrip(".")
    labels = hostname.split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return False
    encoded_labels: list[str] = []
    try:
        for label in labels:
            encoded = label.encode("idna").decode("ascii")
            if len(encoded) > 63 or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
                encoded,
            ):
                return False
            encoded_labels.append(encoded)
    except UnicodeError:
        return False
    if len(".".join(encoded_labels)) > 253:
        return False
    # Avoid treating version labels such as TLS1.3 as hostnames.  Punycode and
    # conventional alphabetic TLDs remain accepted.
    tld = encoded_labels[-1]
    return tld.lower().startswith("xn--") or any(character.isalpha() for character in tld)


def _contains_hostname(text: str) -> bool:
    return any(_is_valid_hostname(match.group(0)) for match in HOSTNAME_CANDIDATE_RE.finditer(text))


def contains_endpoint_material(
    value: Any,
    *,
    actual_server: Any = None,
    actual_port: Any = None,
) -> bool:
    """Return whether text exposes an IP, hostname, URL, or proxy port.

    A bare number is only considered connection material when it equals the
    supplied proxy port.  This deliberately keeps common labels such as
    ``JP 01`` and ``NRT-02`` while rejecting ``JP 443`` for a port-443 node.
    """

    text = _normalize_alias_unbounded(value, strip_dynamic=False)
    if not text:
        return False
    if URL_RE.search(text) or _contains_ipv4(text) or _contains_ipv6(text):
        return True
    if _contains_hostname(text):
        return True

    server = str(actual_server or "").strip().strip("[]").rstrip(".")
    if server:
        text_folded = text.casefold()
        server_folded = server.casefold()
        if text_folded == server_folded:
            return True
        if len(server_folded) >= 4 and re.search(
            rf"(?<![\w-]){re.escape(server_folded)}(?![\w-])",
            text_folded,
        ):
            return True
    if any(_valid_port(match.group(1)) for match in EXPLICIT_COLON_PORT_RE.finditer(text)):
        return True
    if any(_valid_port(match.group(1)) for match in EXPLICIT_NAMED_PORT_RE.finditer(text)):
        return True

    port = _canonical_actual_port(actual_port)
    if port is not None:
        for match in DECIMAL_TOKEN_RE.finditer(text):
            if int(match.group(1), 10) == port:
                return True
    return False


def _normalize_sensitive_key(value: Any) -> str:
    key = str(value or "").strip()
    key = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", key)
    key = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", key)
    key = re.sub(r"[\s_]+", "-", key.casefold())
    return re.sub(r"-+", "-", key).strip("-")


def _is_sensitive_key(value: Any) -> bool:
    key = _normalize_sensitive_key(value)
    if not key or key in NON_SECRET_KEY_EXACT:
        return False
    return key in SENSITIVE_KEY_EXACT or any(
        key.endswith(suffix) for suffix in SENSITIVE_KEY_SUFFIXES
    )


def _strip_wrapping_quotes(value: str) -> str:
    result = value.strip()
    while len(result) >= 2 and (result[0], result[-1]) in {
        ('"', '"'),
        ("'", "'"),
    }:
        result = result[1:-1].strip()
    return result


def _scalar_secret_variants(value: Any) -> set[str]:
    if value is None or isinstance(value, bool):
        return set()
    if isinstance(value, (str, int, float)):
        scalar = str(value).strip()
    else:
        return set()
    if not scalar:
        return set()

    variants = {scalar}
    unquoted_scalar = _strip_wrapping_quotes(scalar)
    if unquoted_scalar and unquoted_scalar != scalar:
        variants.add(unquoted_scalar)
    auth_match = AUTH_SCHEME_RE.fullmatch(unquoted_scalar)
    if auth_match:
        scheme = auth_match.group(1).casefold()
        credential = auth_match.group(2).strip()
        if credential:
            variants.add(credential)
            if scheme == "basic":
                try:
                    decoded_bytes = base64.b64decode(
                        credential + "=" * (-len(credential) % 4),
                        validate=True,
                    )
                    try:
                        decoded = decoded_bytes.decode("utf-8")
                    except UnicodeDecodeError:
                        decoded = decoded_bytes.decode("latin-1")
                except (binascii.Error, ValueError):
                    decoded = ""
                if ":" in decoded and not CONTROL_RE.search(decoded):
                    username, password = decoded.split(":", 1)
                    variants.add(decoded)
                    if username:
                        variants.add(username)
                    if password:
                        variants.add(password)
    for component in re.split(r"[;,&]", unquoted_scalar):
        component = _strip_wrapping_quotes(component)
        if not component:
            continue
        if component != unquoted_scalar:
            variants.add(component)
        if "=" in component:
            _, secret = component.split("=", 1)
            secret = _strip_wrapping_quotes(secret)
            if secret:
                variants.add(secret)
    for pem_match in PEM_PRIVATE_KEY_BLOCK_RE.finditer(scalar):
        body = pem_match.group("body")
        body_lines = [line.strip() for line in body.splitlines() if line.strip()]
        variants.update(line for line in body_lines if len(line) >= 6)
        body_tokens = PEM_BODY_TOKEN_RE.findall(body)
        variants.update(body_tokens)
        for token in body_tokens:
            if len(token) < PEM_FRAGMENT_LENGTH:
                continue
            variants.update(
                token[index : index + PEM_FRAGMENT_LENGTH]
                for index in range(len(token) - PEM_FRAGMENT_LENGTH + 1)
            )
        encoded_body = "".join(
            line for line in body_lines if re.fullmatch(r"[A-Za-z0-9+/=]+", line)
        )
        if len(encoded_body) >= 6:
            variants.add(encoded_body)
    return variants


def _nested_scalar_secret_variants(value: Any) -> set[str]:
    if isinstance(value, Mapping):
        return {
            secret
            for nested in value.values()
            for secret in _nested_scalar_secret_variants(nested)
        }
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return {
            secret
            for nested in value
            for secret in _nested_scalar_secret_variants(nested)
        }
    return _scalar_secret_variants(value)


def _authorization_secret_variants(value: Any) -> set[str]:
    variants: set[str] = set()
    if isinstance(value, Mapping):
        for nested in value.values():
            variants.update(_authorization_secret_variants(nested))
        return variants
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        for nested in value:
            variants.update(_authorization_secret_variants(nested))
        return variants
    if value is None or isinstance(value, bool):
        return variants
    scalar = _strip_wrapping_quotes(str(value))
    if AUTH_SCHEME_RE.fullmatch(scalar):
        variants.update(_scalar_secret_variants(scalar))
    return variants


def _header_value_secret_variants(name: Any, value: Any) -> set[str]:
    if _is_sensitive_key(name):
        return _nested_scalar_secret_variants(value)
    return _authorization_secret_variants(value)


def _header_block_secret_variants(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    variants: set[str] = set()
    for line in re.split(r"(?:\r?\n|\\r?\\n)", value):
        if ":" not in line:
            continue
        name, header_value = line.split(":", 1)
        variants.update(_header_value_secret_variants(name, header_value))
    return variants


def _protocol_specific_secret_variants(proxy: Mapping[Any, Any]) -> set[str]:
    proxy_type = str(proxy.get("type") or "").strip().casefold()
    if proxy_type == "hysteria":
        return _scalar_secret_variants(proxy.get("obfs"))
    if proxy_type != "ssr":
        return set()

    variants: set[str] = set()
    protocol = str(proxy.get("protocol") or "").strip().casefold()
    if protocol.startswith(("auth_aes128_", "auth_chain_")):
        protocol_param = proxy.get("protocol-param")
        variants.update(_scalar_secret_variants(protocol_param))
        if isinstance(protocol_param, (str, int, float)) and not isinstance(
            protocol_param, bool
        ):
            scalar = str(protocol_param).strip()
            if ":" in scalar:
                user_id, user_key = scalar.split(":", 1)
                if user_id.strip():
                    variants.add(user_id.strip())
                if user_key.strip():
                    variants.add(user_key.strip())

    obfs = str(proxy.get("obfs") or "").strip().casefold()
    obfs_param = proxy.get("obfs-param")
    if obfs in {"http_simple", "http_post"} and isinstance(obfs_param, str):
        _, separator, header_block = obfs_param.partition("#")
        if separator:
            variants.update(_header_block_secret_variants(header_block))
    return variants


def _vless_encryption_secret_variants(value: Any) -> set[str]:
    if not isinstance(value, str) or not value.startswith(
        VLESS_KEY_ENCRYPTION_PREFIX + "."
    ):
        return set()
    parts = value.split(".")
    if len(parts) < 4:
        return set()
    secrets = {value}
    for key in parts[3:]:
        if len(key) < VLESS_KEY_ENCRYPTION_PADDING_LIMIT or not re.fullmatch(
            r"[A-Za-z0-9_-]+", key
        ):
            continue
        try:
            decoded = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        except (binascii.Error, ValueError):
            continue
        if len(decoded) in VLESS_KEY_ENCRYPTION_KEY_SIZES:
            secrets.add(key)
    return secrets


def iter_sensitive_proxy_scalars(proxy: Any) -> Iterator[str]:
    """Yield deterministic credential-like scalar values from a proxy tree.

    Sensitive parents make their complete nested value sensitive, so mappings
    and lists under ``auth`` or ``authorization`` cannot evade the scan.  Keys
    such as ``public-key`` and top-level TLS ``fingerprint`` are explicitly
    non-secret and are not yielded.
    """

    values: set[str] = set()
    active_containers: set[int] = set()
    if isinstance(proxy, Mapping):
        values.update(_protocol_specific_secret_variants(proxy))

    def visit(
        value: Any,
        *,
        inherited_sensitive: bool = False,
        in_headers: bool = False,
    ) -> None:
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in active_containers:
                return
            active_containers.add(identity)
            try:
                header_name = next(
                    (
                        item
                        for key, item in value.items()
                        if _normalize_sensitive_key(key) == "name"
                    ),
                    "",
                )
                for key in sorted(value, key=lambda item: str(item)):
                    normalized_key = _normalize_sensitive_key(key)
                    if normalized_key == "encryption":
                        values.update(_vless_encryption_secret_variants(value[key]))
                    header_variants: set[str] = set()
                    if in_headers:
                        if header_name and normalized_key in {"value", "values"}:
                            header_variants = _header_value_secret_variants(
                                header_name, value[key]
                            )
                        elif not header_name:
                            header_variants = _header_value_secret_variants(
                                key, value[key]
                            )
                        values.update(header_variants)
                    child_in_headers = (
                        in_headers
                        or normalized_key in HEADER_CONTAINER_KEYS
                        or normalized_key.endswith("-headers")
                    )
                    visit(
                        value[key],
                        inherited_sensitive=(
                            inherited_sensitive
                            or _is_sensitive_key(key)
                            or bool(header_variants)
                        ),
                        in_headers=child_in_headers,
                    )
            finally:
                active_containers.remove(identity)
            return
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            identity = id(value)
            if identity in active_containers:
                return
            active_containers.add(identity)
            try:
                for item in value:
                    visit(
                        item,
                        inherited_sensitive=inherited_sensitive,
                        in_headers=in_headers,
                    )
            finally:
                active_containers.remove(identity)
            return
        if inherited_sensitive:
            values.update(_scalar_secret_variants(value))

    visit(proxy)
    yield from sorted(values, key=lambda item: (item.casefold(), item))


def _alias_repeats_secret(alias: str, secret: str) -> bool:
    normalized_secret = WHITESPACE_RE.sub(" ", secret).strip()
    if not normalized_secret:
        return False
    folded_alias = alias.casefold()
    folded_secret = normalized_secret.casefold()
    if folded_alias == folded_secret:
        return True
    # Short credentials are only rejected on exact equality.  This avoids a
    # password such as "KR" suppressing every legitimate Korean label.
    return len(normalized_secret) >= 6 and folded_secret in folded_alias


def contains_sensitive_scalar_material(
    value: Any,
    sensitive_scalars: Iterable[Any],
) -> bool:
    """Return whether an alias repeats any supplied private scalar value."""

    alias = _normalize_alias_unbounded(value, strip_dynamic=True)
    if not alias:
        return False
    return any(
        _alias_repeats_secret(alias, str(secret))
        for secret in sensitive_scalars
        if secret is not None
    )


def sanitize_public_proxy_alias(
    value: Any,
    proxy: Mapping[str, Any] | None,
    *,
    max_length: int = PUBLIC_ALIAS_MAX_LENGTH,
) -> str:
    """Return a public-safe proxy alias, or ``""`` when any leak is detected."""

    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1:
        raise ValueError("max_length must be a positive integer")
    alias = _normalize_alias_unbounded(value, strip_dynamic=True)
    if not alias:
        return ""
    proxy_value: Mapping[str, Any] = proxy if isinstance(proxy, Mapping) else {}
    if contains_endpoint_material(
        alias,
        actual_server=proxy_value.get("server"),
        actual_port=proxy_value.get("port"),
    ):
        return ""
    if EXPLICIT_SECRET_RE.search(alias):
        return ""
    if contains_sensitive_scalar_material(
        alias, iter_sensitive_proxy_scalars(proxy_value)
    ):
        return ""
    return alias[:max_length].rstrip()


def is_public_proxy_alias(value: Any, proxy: Mapping[str, Any] | None) -> bool:
    """Return whether a stored alias is already in canonical public-safe form."""

    return isinstance(value, str) and bool(value) and sanitize_public_proxy_alias(value, proxy) == value


def structured_proxy_name(
    *,
    region_hints: Iterable[Any] = (),
    protocol: Any = "",
    protected_asia: bool = False,
    max_length: int = PUBLIC_ALIAS_MAX_LENGTH,
) -> str:
    """Build a safe profile-name fallback from trusted structured fields.

    This output is intended for the Clash node name when every raw alias was
    rejected.  It must not be inserted into metadata's observed ``aliases``.
    """

    if isinstance(max_length, bool) or not isinstance(max_length, int) or max_length < 1:
        raise ValueError("max_length must be a positive integer")
    supplied = {str(region).upper() for region in region_hints}
    regions = [region for region in REGION_ORDER if region in supplied]
    protocol_value = str(protocol or "").strip()
    if not SAFE_PROTOCOL_RE.fullmatch(protocol_value):
        protocol_value = "NODE"
    protocol_label = protocol_value.upper()
    if regions or protected_asia:
        prefix = "ASIA-KEEP"
        if regions:
            prefix = f"{prefix} {'-'.join(regions)}"
    else:
        prefix = "CANDIDATE"
    return f"{prefix} {protocol_label}"[:max_length].rstrip()


__all__ = [
    "PUBLIC_ALIAS_MAX_LENGTH",
    "REGION_ORDER",
    "contains_endpoint_material",
    "contains_sensitive_scalar_material",
    "is_public_proxy_alias",
    "iter_sensitive_proxy_scalars",
    "normalize_public_alias",
    "sanitize_public_proxy_alias",
    "structured_proxy_name",
]
