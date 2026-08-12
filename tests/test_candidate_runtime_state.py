from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Cryptodome.Cipher import AES

from scripts.candidate_runtime_state import (
    CandidateRuntimeStateError,
    RUNTIME_STATE_FILES,
    build_runtime_state,
    decrypt_directory,
    decrypt_runtime_state,
    derive_runtime_state_key,
    encrypt_directory,
    encrypt_runtime_state,
)


KEY = bytes(range(32))
REPOSITORY = "owner/aggregator"
KEY_EPOCH = "runtime-key-v1"


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(
        dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
    )


class CandidateRuntimeStateTests(unittest.TestCase):
    def test_explicit_private_state_allowlist_round_trips_encrypted(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            restored = root / "restored"
            encrypted = root / "cache" / "runtime-state.enc"
            source.mkdir()
            fixtures = {
                "subscribes.txt": b"https://private.invalid/sub?token=credential-sentinel\n",
                "crawler-subs.json": b'{"private":"credential-sentinel"}\n',
                "source-health.json": b'{"healthy":1}\n',
            }
            for name, content in fixtures.items():
                (source / name).write_bytes(content)
            (source / "clash.yaml").write_text("must-not-be-cached\n", encoding="utf-8")

            encrypt_directory(
                source,
                encrypted,
                key=KEY,
                repository=REPOSITORY,
                key_epoch=KEY_EPOCH,
            )
            serialized = encrypted.read_bytes()
            self.assertNotIn(b"private.invalid", serialized)
            self.assertNotIn(b"credential-sentinel", serialized)
            self.assertNotIn(b"must-not-be-cached", serialized)

            outputs = decrypt_directory(
                encrypted,
                restored,
                key=KEY,
                repository=REPOSITORY,
                key_epoch=KEY_EPOCH,
            )
            self.assertEqual({path.name for path in outputs}, set(fixtures))
            for name, content in fixtures.items():
                self.assertEqual((restored / name).read_bytes(), content)
            self.assertFalse((restored / "clash.yaml").exists())

    def test_runtime_state_allowlist_includes_all_former_public_state(self) -> None:
        self.assertEqual(
            set(RUNTIME_STATE_FILES),
            {
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
            },
        )

    def test_runtime_cache_uses_a_domain_separated_subkey(self) -> None:
        self.assertNotEqual(
            derive_runtime_state_key(KEY, key_epoch=KEY_EPOCH),
            KEY,
        )
        envelope = json.loads(
            encrypt_runtime_state(
                b"private runtime payload",
                key=KEY,
                repository=REPOSITORY,
                key_epoch=KEY_EPOCH,
                nonce=b"n" * 12,
            )
        )
        sealed = base64.b64decode(envelope["ciphertext"])
        raw_key_cipher = AES.new(KEY, AES.MODE_GCM, nonce=b"n" * 12, mac_len=16)
        raw_key_cipher.update(
            b'{"key_epoch":"runtime-key-v1","purpose":"github-candidate-runtime-state","repository":"owner/aggregator","version":2}'
        )
        with self.assertRaises(ValueError):
            raw_key_cipher.decrypt_and_verify(sealed[:-16], sealed[-16:])

        self.assertNotEqual(
            derive_runtime_state_key(KEY, key_epoch=KEY_EPOCH),
            derive_runtime_state_key(b"x" * 32, key_epoch=KEY_EPOCH),
        )
        self.assertNotEqual(
            derive_runtime_state_key(KEY, key_epoch=KEY_EPOCH),
            derive_runtime_state_key(KEY, key_epoch="runtime-key-v2"),
        )

    def test_tampered_state_fails_before_creating_outputs(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            output = root / "restored"
            source.mkdir()
            (source / "crawler-subs.json").write_text(
                '{"token":"credential-sentinel"}\n', encoding="utf-8"
            )
            envelope = bytearray(
                encrypt_runtime_state(
                    build_runtime_state(source),
                    key=KEY,
                    repository=REPOSITORY,
                    key_epoch=KEY_EPOCH,
                    nonce=b"n" * 12,
                )
            )
            envelope[-10] ^= 1
            encrypted = root / "runtime-state.enc"
            encrypted.write_bytes(envelope)

            with self.assertRaises(CandidateRuntimeStateError) as raised:
                decrypt_directory(
                    encrypted,
                    output,
                    key=KEY,
                    repository=REPOSITORY,
                    key_epoch=KEY_EPOCH,
                )

            self.assertNotIn("credential-sentinel", str(raised.exception))
            self.assertFalse(output.exists())

    def test_payload_rejects_unapproved_file_names(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "crawler-subs.json").write_text("{}\n", encoding="utf-8")
            compressed = build_runtime_state(source)
            envelope = encrypt_runtime_state(
                compressed,
                key=KEY,
                repository=REPOSITORY,
                key_epoch=KEY_EPOCH,
                nonce=b"x" * 12,
            )
            self.assertEqual(
                set(
                    decrypt_runtime_state(
                        envelope,
                        key=KEY,
                        repository=REPOSITORY,
                        key_epoch=KEY_EPOCH,
                    )
                ),
                {"crawler-subs.json"},
            )

    def test_key_epoch_mismatch_is_rejected_before_creating_outputs(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            encrypted = root / "runtime-state.enc"
            output = root / "restored"
            source.mkdir()
            (source / "crawler-subs.json").write_text("{}\n", encoding="utf-8")
            encrypt_directory(
                source,
                encrypted,
                key=KEY,
                repository=REPOSITORY,
                key_epoch=KEY_EPOCH,
            )

            with self.assertRaisesRegex(CandidateRuntimeStateError, "epoch mismatch"):
                decrypt_directory(
                    encrypted,
                    output,
                    key=KEY,
                    repository=REPOSITORY,
                    key_epoch="runtime-key-v2",
                )
            self.assertFalse(output.exists())

    def test_write_failure_is_sanitized(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "crawler-subs.json").write_text(
                '{"token":"credential-sentinel"}\n', encoding="utf-8"
            )

            with (
                patch(
                    "scripts.candidate_handoff.os.open",
                    side_effect=OSError("sensitive-runner-path"),
                ),
                self.assertRaises(CandidateRuntimeStateError) as raised,
            ):
                encrypt_directory(
                    source,
                    root / "cache" / "runtime-state.enc",
                    key=KEY,
                    repository=REPOSITORY,
                    key_epoch=KEY_EPOCH,
                )

            message = str(raised.exception)
            self.assertNotIn("sensitive-runner-path", message)
            self.assertNotIn("credential-sentinel", message)


if __name__ == "__main__":
    unittest.main()
