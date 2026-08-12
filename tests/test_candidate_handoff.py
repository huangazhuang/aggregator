from __future__ import annotations

import base64
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.candidate_handoff import (
    HANDOFF_ALGORITHM,
    HANDOFF_FIELDS,
    HANDOFF_KEY_ENV,
    HANDOFF_VERSION,
    CandidateHandoffError,
    decode_handoff_key,
    decrypt_file,
    decrypt_handoff,
    encrypt_file,
    encrypt_handoff,
    load_handoff_key,
)


KEY = bytes(range(32))
KEY_BASE64 = base64.b64encode(KEY).decode("ascii")
CONTEXT = {
    "repository": "owner/aggregator",
    "run_id": "123456789",
    "trigger_sha": "a" * 40,
}
PLAINTEXT = json.dumps(
    {
        "proxy": {
            "name": "KR-private-node",
            "server": "secret.example.invalid",
            "port": 443,
            "uuid": "00000000-0000-4000-8000-000000000001",
            "password": "credential-sentinel",
        },
        "fingerprint": "f" * 64,
        "previous_profile": "previous-profile-sentinel",
    },
    sort_keys=True,
).encode("utf-8")


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    root = os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
    return tempfile.TemporaryDirectory(dir=root)


class CandidateHandoffTests(unittest.TestCase):
    def test_aes_gcm_round_trip_and_minimal_envelope(self) -> None:
        envelope_bytes = encrypt_handoff(
            PLAINTEXT,
            key=KEY,
            nonce=b"n" * 12,
            **CONTEXT,
        )
        envelope = json.loads(envelope_bytes)

        self.assertEqual(set(envelope), HANDOFF_FIELDS)
        self.assertEqual(envelope["version"], HANDOFF_VERSION)
        self.assertEqual(envelope["algorithm"], HANDOFF_ALGORITHM)
        serialized = envelope_bytes.decode("utf-8")
        for sensitive in (
            "KR-private-node",
            "secret.example.invalid",
            "00000000-0000-4000-8000-000000000001",
            "credential-sentinel",
            "f" * 64,
            "previous-profile-sentinel",
        ):
            self.assertNotIn(sensitive, serialized)

        self.assertEqual(
            decrypt_handoff(envelope_bytes, key=KEY, **CONTEXT),
            PLAINTEXT,
        )

    def test_file_round_trip_writes_only_ciphertext_to_handoff_path(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            plaintext = root / "private" / "identity-input.json"
            ciphertext = root / "handoff" / "identity-input.enc"
            restored = root / "identity" / "identity-input.json"
            plaintext.parent.mkdir(parents=True)
            plaintext.write_bytes(PLAINTEXT)

            encrypt_file(plaintext, ciphertext, key=KEY, **CONTEXT)
            self.assertTrue(ciphertext.is_file())
            self.assertNotIn("secret.example.invalid", ciphertext.read_text("utf-8"))

            decrypt_file(ciphertext, restored, key=KEY, **CONTEXT)
            self.assertEqual(restored.read_bytes(), PLAINTEXT)

    def test_missing_invalid_and_wrong_length_keys_fail_closed(self) -> None:
        with self.assertRaisesRegex(CandidateHandoffError, "is required"):
            load_handoff_key({})
        with self.assertRaisesRegex(CandidateHandoffError, "strict base64"):
            decode_handoff_key("%%%not-base64%%")
        with self.assertRaisesRegex(CandidateHandoffError, "strict base64"):
            decode_handoff_key(f" {KEY_BASE64}")
        with self.assertRaisesRegex(CandidateHandoffError, "strict base64"):
            decode_handoff_key(f"{KEY_BASE64}=")
        with self.assertRaisesRegex(CandidateHandoffError, "exactly 32 bytes"):
            decode_handoff_key(base64.b64encode(b"short").decode("ascii"))
        self.assertEqual(load_handoff_key({HANDOFF_KEY_ENV: KEY_BASE64}), KEY)

    def test_tampered_nonce_ciphertext_and_aad_are_rejected(self) -> None:
        envelope_bytes = encrypt_handoff(PLAINTEXT, key=KEY, **CONTEXT)
        original = json.loads(envelope_bytes)

        tampered_nonce = dict(original)
        nonce = bytearray(base64.b64decode(tampered_nonce["nonce"]))
        nonce[0] ^= 1
        tampered_nonce["nonce"] = base64.b64encode(nonce).decode("ascii")
        with self.assertRaises(CandidateHandoffError):
            decrypt_handoff(
                json.dumps(tampered_nonce).encode("utf-8"),
                key=KEY,
                **CONTEXT,
            )

        tampered_ciphertext = dict(original)
        sealed = bytearray(base64.b64decode(tampered_ciphertext["ciphertext"]))
        sealed[0] ^= 1
        tampered_ciphertext["ciphertext"] = base64.b64encode(sealed).decode(
            "ascii"
        )
        with self.assertRaisesRegex(CandidateHandoffError, "authentication failed"):
            decrypt_handoff(
                json.dumps(tampered_ciphertext).encode("utf-8"),
                key=KEY,
                **CONTEXT,
            )

        altered_context = dict(CONTEXT, run_id="123456790")
        with self.assertRaisesRegex(CandidateHandoffError, "authentication failed"):
            decrypt_handoff(envelope_bytes, key=KEY, **altered_context)

    def test_same_run_can_authenticate_after_a_github_rerun_attempt(self) -> None:
        envelope_bytes = encrypt_handoff(PLAINTEXT, key=KEY, **CONTEXT)

        self.assertEqual(
            decrypt_handoff(envelope_bytes, key=KEY, **CONTEXT),
            PLAINTEXT,
        )

    def test_wrong_key_and_unexpected_envelope_fields_are_rejected(self) -> None:
        envelope_bytes = encrypt_handoff(PLAINTEXT, key=KEY, **CONTEXT)
        with self.assertRaisesRegex(CandidateHandoffError, "authentication failed"):
            decrypt_handoff(envelope_bytes, key=b"x" * 32, **CONTEXT)

        envelope = json.loads(envelope_bytes)
        envelope["repository"] = "owner/aggregator"
        with self.assertRaisesRegex(CandidateHandoffError, "unexpected"):
            decrypt_handoff(
                json.dumps(envelope).encode("utf-8"),
                key=KEY,
                **CONTEXT,
            )

    def test_invalid_envelope_base64_is_rejected(self) -> None:
        envelope = json.loads(encrypt_handoff(PLAINTEXT, key=KEY, **CONTEXT))
        for field in ("nonce", "ciphertext"):
            invalid = dict(envelope)
            invalid[field] = "%%%not-base64%%%"
            with self.subTest(field=field), self.assertRaisesRegex(
                CandidateHandoffError,
                field,
            ):
                decrypt_handoff(
                    json.dumps(invalid).encode("utf-8"),
                    key=KEY,
                    **CONTEXT,
                )

    def test_failed_authentication_does_not_create_plaintext_output(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            encrypted = root / "identity-input.enc"
            output = root / "identity-input.json"
            encrypted.write_bytes(encrypt_handoff(PLAINTEXT, key=KEY, **CONTEXT))

            with self.assertRaises(CandidateHandoffError):
                decrypt_file(encrypted, output, key=b"z" * 32, **CONTEXT)

            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "POSIX permission contract")
    def test_private_output_is_mode_0600_from_creation(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            plaintext = root / "identity-input.json"
            output = root / "identity-input.enc"
            plaintext.write_bytes(PLAINTEXT)
            observed_modes: list[int] = []
            real_fdopen = os.fdopen

            def inspect_fd(descriptor: int, *args: object, **kwargs: object):
                observed_modes.append(stat.S_IMODE(os.fstat(descriptor).st_mode))
                return real_fdopen(descriptor, *args, **kwargs)

            with patch("scripts.candidate_handoff.os.fdopen", side_effect=inspect_fd):
                encrypt_file(plaintext, output, key=KEY, **CONTEXT)

            self.assertEqual(observed_modes, [0o600])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_cli_style_file_write_failure_is_sanitized(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            plaintext = root / "identity-input.json"
            output = root / "identity-input.enc"
            plaintext.write_bytes(PLAINTEXT)

            with (
                patch(
                    "scripts.candidate_handoff.os.open",
                    side_effect=OSError("sensitive-runner-path"),
                ),
                self.assertRaisesRegex(
                    CandidateHandoffError,
                    "unable to write candidate handoff output",
                ) as raised,
            ):
                encrypt_file(plaintext, output, key=KEY, **CONTEXT)

            self.assertNotIn("sensitive-runner-path", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
