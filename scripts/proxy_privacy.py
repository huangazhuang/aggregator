"""Shared privacy helpers for public proxy aliases and display-name fallbacks.

Raw proxy names are useful inside private provenance staging, but they are not
safe public metadata by default.  This module owns the conservative, pure
projection used at that boundary: aliases containing endpoints or credentials
are rejected as a whole, while stable human labels such as ``JP 01`` remain
available.
"""

from __future__ import annotations

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
AUTH_SCHEME_RE = re.compile(r"(?i)^(?:bearer|basic|token|digest)\s+(.+)$")
SAFE_PROTOCOL_RE = re.compile(r"^[a-z0-9][a-z0-9+._-]{0,31}$", flags=re.IGNORECASE)


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
    auth_match = AUTH_SCHEME_RE.fullmatch(scalar)
    if auth_match:
        credential = auth_match.group(1).strip()
        if credential:
            variants.add(credential)
    for component in re.split(r"[;,&]", scalar):
        component = component.strip()
        if not component:
            continue
        if component != scalar:
            variants.add(component)
        if "=" in component:
            _, secret = component.split("=", 1)
            secret = secret.strip()
            if secret:
                variants.add(secret)
    return variants


def iter_sensitive_proxy_scalars(proxy: Any) -> Iterator[str]:
    """Yield deterministic credential-like scalar values from a proxy tree.

    Sensitive parents make their complete nested value sensitive, so mappings
    and lists under ``auth`` or ``authorization`` cannot evade the scan.  Keys
    such as ``public-key`` and top-level TLS ``fingerprint`` are explicitly
    non-secret and are not yielded.
    """

    values: set[str] = set()
    active_containers: set[int] = set()

    def visit(value: Any, *, inherited_sensitive: bool = False) -> None:
        if isinstance(value, Mapping):
            identity = id(value)
            if identity in active_containers:
                return
            active_containers.add(identity)
            try:
                sensitive_header = any(
                    _normalize_sensitive_key(key) == "name"
                    and _is_sensitive_key(item)
                    for key, item in value.items()
                )
                for key in sorted(value, key=lambda item: str(item)):
                    normalized_key = _normalize_sensitive_key(key)
                    visit(
                        value[key],
                        inherited_sensitive=(
                            inherited_sensitive
                            or _is_sensitive_key(key)
                            or (
                                sensitive_header
                                and normalized_key in {"value", "values"}
                            )
                        ),
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
                    visit(item, inherited_sensitive=inherited_sensitive)
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
    if alias == normalized_secret:
        return True
    # Short credentials are only rejected on exact equality.  This avoids a
    # password such as "KR" suppressing every legitimate Korean label.
    return len(normalized_secret) >= 6 and normalized_secret in alias


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
    if any(
        _alias_repeats_secret(alias, secret)
        for secret in iter_sensitive_proxy_scalars(proxy_value)
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
    "is_public_proxy_alias",
    "iter_sensitive_proxy_scalars",
    "normalize_public_alias",
    "sanitize_public_proxy_alias",
    "structured_proxy_name",
]
