from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes


HANDOFF_KEY_ENV = "CANDIDATE_HANDOFF_AES_KEY"
HANDOFF_VERSION = 1
HANDOFF_ALGORITHM = "AES-256-GCM"
HANDOFF_NONCE_BYTES = 12
HANDOFF_TAG_BYTES = 16
HANDOFF_FIELDS = {"version", "algorithm", "nonce", "ciphertext"}
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
TRIGGER_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")


class CandidateHandoffError(ValueError):
    """Raised when the private Candidate V2 handoff cannot be authenticated."""


def decode_handoff_key(encoded: str) -> bytes:
    if not encoded:
        raise CandidateHandoffError(
            f"{HANDOFF_KEY_ENV} is required when Candidate V2 is enabled"
        )
    if encoded != encoded.strip():
        raise CandidateHandoffError(f"{HANDOFF_KEY_ENV} must be strict base64")
    try:
        key = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CandidateHandoffError(
            f"{HANDOFF_KEY_ENV} must be strict base64"
        ) from exc
    if _encode_base64(key) != encoded:
        raise CandidateHandoffError(f"{HANDOFF_KEY_ENV} must be strict base64")
    if len(key) != 32:
        raise CandidateHandoffError(
            f"{HANDOFF_KEY_ENV} must decode to exactly 32 bytes"
        )
    return key


def load_handoff_key(environment: Mapping[str, str] | None = None) -> bytes:
    values = os.environ if environment is None else environment
    return decode_handoff_key(str(values.get(HANDOFF_KEY_ENV, "")))


def _validated_context(
    *,
    repository: str,
    run_id: str,
    trigger_sha: str,
) -> dict[str, Any]:
    normalized_repository = str(repository)
    if not REPOSITORY_RE.fullmatch(normalized_repository):
        raise CandidateHandoffError("handoff repository context is invalid")

    normalized_run_id = str(run_id)
    if (
        not normalized_run_id.isascii()
        or not normalized_run_id.isdecimal()
        or int(normalized_run_id) < 1
    ):
        raise CandidateHandoffError("handoff run_id context is invalid")
    normalized_run_id = str(int(normalized_run_id))

    normalized_sha = str(trigger_sha).lower()
    if not TRIGGER_SHA_RE.fullmatch(normalized_sha):
        raise CandidateHandoffError("handoff trigger SHA context is invalid")

    return {
        "purpose": "github-candidate-identity-handoff",
        "version": HANDOFF_VERSION,
        "repository": normalized_repository,
        "run_id": normalized_run_id,
        "trigger_sha": normalized_sha,
    }


def build_handoff_aad(
    *,
    repository: str,
    run_id: str,
    trigger_sha: str,
) -> bytes:
    context = _validated_context(
        repository=repository,
        run_id=run_id,
        trigger_sha=trigger_sha,
    )
    return json.dumps(
        context,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_key_bytes(key: bytes) -> bytes:
    if not isinstance(key, bytes) or len(key) != 32:
        raise CandidateHandoffError("candidate handoff key must contain 32 bytes")
    return key


def _encode_base64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_base64(value: Any, *, field: str) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CandidateHandoffError(f"candidate handoff {field} is invalid")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CandidateHandoffError(
            f"candidate handoff {field} is invalid"
        ) from exc


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateHandoffError("candidate handoff contains duplicate fields")
        result[key] = value
    return result


def encrypt_handoff(
    plaintext: bytes,
    *,
    key: bytes,
    repository: str,
    run_id: str,
    trigger_sha: str,
    nonce: bytes | None = None,
) -> bytes:
    secret = _validate_key_bytes(key)
    if not isinstance(plaintext, bytes) or not plaintext:
        raise CandidateHandoffError("candidate identity handoff input is empty")
    actual_nonce = get_random_bytes(HANDOFF_NONCE_BYTES) if nonce is None else nonce
    if not isinstance(actual_nonce, bytes) or len(actual_nonce) != HANDOFF_NONCE_BYTES:
        raise CandidateHandoffError(
            f"candidate handoff nonce must contain {HANDOFF_NONCE_BYTES} bytes"
        )

    cipher = AES.new(
        secret,
        AES.MODE_GCM,
        nonce=actual_nonce,
        mac_len=HANDOFF_TAG_BYTES,
    )
    cipher.update(
        build_handoff_aad(
            repository=repository,
            run_id=run_id,
            trigger_sha=trigger_sha,
        )
    )
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    envelope = {
        "version": HANDOFF_VERSION,
        "algorithm": HANDOFF_ALGORITHM,
        "nonce": _encode_base64(actual_nonce),
        "ciphertext": _encode_base64(ciphertext + tag),
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


def decrypt_handoff(
    encoded_envelope: bytes,
    *,
    key: bytes,
    repository: str,
    run_id: str,
    trigger_sha: str,
) -> bytes:
    secret = _validate_key_bytes(key)
    try:
        envelope = json.loads(
            encoded_envelope.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_fields,
        )
    except CandidateHandoffError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CandidateHandoffError("candidate handoff envelope is invalid JSON") from exc
    if not isinstance(envelope, dict) or set(envelope) != HANDOFF_FIELDS:
        raise CandidateHandoffError(
            "candidate handoff envelope fields are incomplete or unexpected"
        )
    if type(envelope["version"]) is not int or envelope["version"] != HANDOFF_VERSION:
        raise CandidateHandoffError("candidate handoff version is unsupported")
    if envelope["algorithm"] != HANDOFF_ALGORITHM:
        raise CandidateHandoffError("candidate handoff algorithm is unsupported")

    nonce = _decode_base64(envelope["nonce"], field="nonce")
    sealed = _decode_base64(envelope["ciphertext"], field="ciphertext")
    if len(nonce) != HANDOFF_NONCE_BYTES:
        raise CandidateHandoffError("candidate handoff nonce is invalid")
    if len(sealed) <= HANDOFF_TAG_BYTES:
        raise CandidateHandoffError("candidate handoff ciphertext is invalid")
    ciphertext = sealed[:-HANDOFF_TAG_BYTES]
    tag = sealed[-HANDOFF_TAG_BYTES:]

    cipher = AES.new(
        secret,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=HANDOFF_TAG_BYTES,
    )
    cipher.update(
        build_handoff_aad(
            repository=repository,
            run_id=run_id,
            trigger_sha=trigger_sha,
        )
    )
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise CandidateHandoffError(
            "candidate identity handoff authentication failed"
        ) from exc


def write_private_bytes_atomic(path: str | Path, content: bytes) -> Path:
    """Create or replace a private file atomically with mode 0600 from birth."""

    destination = Path(path)
    if not isinstance(content, bytes):
        raise CandidateHandoffError("candidate private output must be bytes")
    _write_bytes_atomic(destination, content, mode=0o600)
    return destination


def _write_bytes_atomic(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            mode,
        )
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as exc:
        raise CandidateHandoffError("unable to write candidate handoff output") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def encrypt_file(
    source: str | Path,
    destination: str | Path,
    *,
    key: bytes,
    repository: str,
    run_id: str,
    trigger_sha: str,
) -> Path:
    try:
        plaintext = Path(source).read_bytes()
    except OSError as exc:
        raise CandidateHandoffError(
            "unable to read candidate identity handoff input"
        ) from exc
    output = Path(destination)
    encrypted = encrypt_handoff(
        plaintext,
        key=key,
        repository=repository,
        run_id=run_id,
        trigger_sha=trigger_sha,
    )
    write_private_bytes_atomic(output, encrypted)
    return output


def decrypt_file(
    source: str | Path,
    destination: str | Path,
    *,
    key: bytes,
    repository: str,
    run_id: str,
    trigger_sha: str,
) -> Path:
    try:
        envelope = Path(source).read_bytes()
    except OSError as exc:
        raise CandidateHandoffError("unable to read encrypted candidate handoff") from exc
    plaintext = decrypt_handoff(
        envelope,
        key=key,
        repository=repository,
        run_id=run_id,
        trigger_sha=trigger_sha,
    )
    output = Path(destination)
    write_private_bytes_atomic(output, plaintext)
    return output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("encrypt", "decrypt"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--input", required=True)
        subparser.add_argument("--output", required=True)
        subparser.add_argument("--repository", required=True)
        subparser.add_argument("--run-id", required=True)
        subparser.add_argument("--trigger-sha", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        key = load_handoff_key()
        operation = encrypt_file if args.command == "encrypt" else decrypt_file
        operation(
            args.input,
            args.output,
            key=key,
            repository=args.repository,
            run_id=args.run_id,
            trigger_sha=args.trigger_sha,
        )
    except CandidateHandoffError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
