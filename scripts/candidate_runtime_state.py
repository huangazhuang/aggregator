#!/usr/bin/env python3
"""Encrypt the private collection state kept between Candidate V2 runs."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import hashlib
import hmac
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from scripts.candidate_handoff import (
    HANDOFF_ALGORITHM,
    HANDOFF_NONCE_BYTES,
    HANDOFF_TAG_BYTES,
    CandidateHandoffError,
    REPOSITORY_RE,
    load_handoff_key,
    write_private_bytes_atomic,
)


RUNTIME_STATE_KIND = "github-candidate-runtime-state"
RUNTIME_STATE_SCHEMA_VERSION = 2
RUNTIME_SUBKEY_PURPOSE = b"aggregator/github-candidate-runtime-state/aes-256-gcm/v1"
RUNTIME_STATE_FIELDS = {"kind", "schema_version", "files"}
RUNTIME_ENVELOPE_FIELDS = {"version", "algorithm", "key_epoch", "nonce", "ciphertext"}
RUNTIME_KEY_EPOCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RUNTIME_STATE_FILES = (
    "subscribes.txt",
    "domains.txt",
    "valid-domains.txt",
    "crawler-subs.json",
    "crawler-proxies.txt",
    "crawler-gitfork-subs.txt",
    "source-health.json",
    "domain-health.json",
    "crawler-v2rayse.txt",
    "crawler-v2rayse-modified.json",
    "cn-fc-check.json",
)


class CandidateRuntimeStateError(ValueError):
    """Raised when encrypted collection state is invalid or unavailable."""


def _key_epoch(value: str) -> str:
    epoch = str(value or "")
    if not RUNTIME_KEY_EPOCH_RE.fullmatch(epoch):
        raise CandidateRuntimeStateError("runtime state key epoch is invalid")
    return epoch


def derive_runtime_state_key(base_key: bytes, *, key_epoch: str) -> bytes:
    """Domain-separate runtime cache encryption from the handoff AES key."""

    if not isinstance(base_key, bytes) or len(base_key) != 32:
        raise CandidateRuntimeStateError("runtime state base key must contain 32 bytes")
    epoch = _key_epoch(key_epoch)
    salt = b"aggregator/candidate-key-derivation/v1"
    pseudorandom_key = hmac.new(salt, base_key, hashlib.sha256).digest()
    return hmac.new(
        pseudorandom_key,
        RUNTIME_SUBKEY_PURPOSE + b"\0" + epoch.encode("ascii") + b"\x01",
        hashlib.sha256,
    ).digest()


def _aad(repository: str, *, key_epoch: str) -> bytes:
    if not REPOSITORY_RE.fullmatch(str(repository)):
        raise CandidateRuntimeStateError("runtime state repository context is invalid")
    epoch = _key_epoch(key_epoch)
    return json.dumps(
        {
            "purpose": RUNTIME_STATE_KIND,
            "version": RUNTIME_STATE_SCHEMA_VERSION,
            "repository": str(repository),
            "key_epoch": epoch,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateRuntimeStateError("runtime state contains duplicate fields")
        result[key] = value
    return result


def _encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode(value: Any) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CandidateRuntimeStateError("runtime state contains invalid base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise CandidateRuntimeStateError("runtime state contains invalid base64") from None
    if _encode(decoded) != value:
        raise CandidateRuntimeStateError("runtime state contains invalid base64")
    return decoded


def build_runtime_state(input_dir: str | Path) -> bytes:
    root = Path(input_dir)
    files: dict[str, str] = {}
    for name in RUNTIME_STATE_FILES:
        path = root / name
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file():
            raise CandidateRuntimeStateError("runtime state input is invalid")
        try:
            files[name] = _encode(path.read_bytes())
        except OSError:
            raise CandidateRuntimeStateError("unable to read runtime state") from None
    if not files:
        raise CandidateRuntimeStateError("runtime state input is empty")
    payload = {
        "kind": RUNTIME_STATE_KIND,
        "schema_version": RUNTIME_STATE_SCHEMA_VERSION,
        "files": files,
    }
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return gzip.compress(serialized, compresslevel=9, mtime=0)


def encrypt_runtime_state(
    plaintext: bytes,
    *,
    key: bytes,
    repository: str,
    key_epoch: str,
    nonce: bytes | None = None,
) -> bytes:
    epoch = _key_epoch(key_epoch)
    runtime_key = derive_runtime_state_key(key, key_epoch=epoch)
    if not isinstance(plaintext, bytes) or not plaintext:
        raise CandidateRuntimeStateError("runtime state input is empty")
    actual_nonce = get_random_bytes(HANDOFF_NONCE_BYTES) if nonce is None else nonce
    if not isinstance(actual_nonce, bytes) or len(actual_nonce) != HANDOFF_NONCE_BYTES:
        raise CandidateRuntimeStateError("runtime state nonce is invalid")
    cipher = AES.new(runtime_key, AES.MODE_GCM, nonce=actual_nonce, mac_len=HANDOFF_TAG_BYTES)
    cipher.update(_aad(repository, key_epoch=epoch))
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    envelope = {
        "version": RUNTIME_STATE_SCHEMA_VERSION,
        "algorithm": HANDOFF_ALGORITHM,
        "key_epoch": epoch,
        "nonce": _encode(actual_nonce),
        "ciphertext": _encode(ciphertext + tag),
    }
    return (
        json.dumps(
            envelope,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def decrypt_runtime_state(
    envelope_bytes: bytes,
    *,
    key: bytes,
    repository: str,
    key_epoch: str,
) -> dict[str, bytes]:
    epoch = _key_epoch(key_epoch)
    runtime_key = derive_runtime_state_key(key, key_epoch=epoch)
    try:
        envelope = json.loads(
            envelope_bytes.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except CandidateRuntimeStateError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise CandidateRuntimeStateError("runtime state envelope is invalid") from None
    if not isinstance(envelope, dict) or set(envelope) != RUNTIME_ENVELOPE_FIELDS:
        raise CandidateRuntimeStateError("runtime state envelope fields are invalid")
    if type(envelope["version"]) is not int or envelope["version"] != RUNTIME_STATE_SCHEMA_VERSION:
        raise CandidateRuntimeStateError("runtime state version is unsupported")
    if envelope["algorithm"] != HANDOFF_ALGORITHM:
        raise CandidateRuntimeStateError("runtime state algorithm is unsupported")
    if envelope["key_epoch"] != epoch:
        raise CandidateRuntimeStateError("runtime state key epoch mismatch")
    nonce = _decode(envelope["nonce"])
    sealed = _decode(envelope["ciphertext"])
    if len(nonce) != HANDOFF_NONCE_BYTES or len(sealed) <= HANDOFF_TAG_BYTES:
        raise CandidateRuntimeStateError("runtime state envelope is invalid")
    cipher = AES.new(runtime_key, AES.MODE_GCM, nonce=nonce, mac_len=HANDOFF_TAG_BYTES)
    cipher.update(_aad(repository, key_epoch=epoch))
    try:
        compressed = cipher.decrypt_and_verify(
            sealed[:-HANDOFF_TAG_BYTES],
            sealed[-HANDOFF_TAG_BYTES:],
        )
    except ValueError:
        raise CandidateRuntimeStateError("runtime state authentication failed") from None
    try:
        raw = gzip.decompress(compressed)
        state = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
    except CandidateRuntimeStateError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise CandidateRuntimeStateError("runtime state payload is invalid") from None
    if not isinstance(state, dict) or set(state) != RUNTIME_STATE_FIELDS:
        raise CandidateRuntimeStateError("runtime state payload fields are invalid")
    if state["kind"] != RUNTIME_STATE_KIND or state["schema_version"] != RUNTIME_STATE_SCHEMA_VERSION:
        raise CandidateRuntimeStateError("runtime state payload contract is unsupported")
    encoded_files = state["files"]
    if not isinstance(encoded_files, Mapping) or not encoded_files:
        raise CandidateRuntimeStateError("runtime state file set is invalid")
    if not set(encoded_files).issubset(RUNTIME_STATE_FILES):
        raise CandidateRuntimeStateError("runtime state file set is invalid")
    return {name: _decode(value) for name, value in encoded_files.items()}


def encrypt_directory(
    input_dir: str | Path,
    output: str | Path,
    *,
    key: bytes,
    repository: str,
    key_epoch: str,
) -> Path:
    envelope = encrypt_runtime_state(
        build_runtime_state(input_dir),
        key=key,
        repository=repository,
        key_epoch=key_epoch,
    )
    try:
        return write_private_bytes_atomic(output, envelope)
    except CandidateHandoffError:
        raise CandidateRuntimeStateError("unable to write encrypted runtime state") from None


def decrypt_directory(
    input_file: str | Path,
    output_dir: str | Path,
    *,
    key: bytes,
    repository: str,
    key_epoch: str,
) -> tuple[Path, ...]:
    try:
        envelope = Path(input_file).read_bytes()
    except OSError:
        raise CandidateRuntimeStateError("unable to read encrypted runtime state") from None
    files = decrypt_runtime_state(
        envelope,
        key=key,
        repository=repository,
        key_epoch=key_epoch,
    )
    root = Path(output_dir)
    outputs: list[Path] = []
    for name in RUNTIME_STATE_FILES:
        if name not in files:
            continue
        destination = root / name
        if destination.is_symlink():
            raise CandidateRuntimeStateError("runtime state destination is invalid")
        try:
            write_private_bytes_atomic(destination, files[name])
        except CandidateHandoffError:
            raise CandidateRuntimeStateError("unable to restore runtime state") from None
        outputs.append(destination)
    return tuple(outputs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    encrypt = commands.add_parser("encrypt")
    encrypt.add_argument("--input-dir", required=True)
    encrypt.add_argument("--output", required=True)
    encrypt.add_argument("--repository", required=True)
    encrypt.add_argument("--key-epoch", required=True)
    decrypt = commands.add_parser("decrypt")
    decrypt.add_argument("--input", required=True)
    decrypt.add_argument("--output-dir", required=True)
    decrypt.add_argument("--repository", required=True)
    decrypt.add_argument("--key-epoch", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        key = load_handoff_key()
        if args.command == "encrypt":
            encrypt_directory(
                args.input_dir,
                args.output,
                key=key,
                repository=args.repository,
                key_epoch=args.key_epoch,
            )
        else:
            decrypt_directory(
                args.input,
                args.output_dir,
                key=key,
                repository=args.repository,
                key_epoch=args.key_epoch,
            )
    except (CandidateRuntimeStateError, CandidateHandoffError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CandidateRuntimeStateError",
    "RUNTIME_KEY_EPOCH_RE",
    "RUNTIME_STATE_FILES",
    "build_runtime_state",
    "derive_runtime_state_key",
    "decrypt_directory",
    "decrypt_runtime_state",
    "encrypt_directory",
    "encrypt_runtime_state",
]
