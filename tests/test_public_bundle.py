from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from scripts.public_bundle import (
    CANDIDATE_PUBLIC_FILES,
    LEGACY_PUBLIC_FILES,
    PublicBundleError,
    copy_public_bundle,
    validate_public_bundle,
)


def temporary_directory() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(
        dir=os.environ.get("AGGREGATOR_TEST_TMPDIR") or None
    )


def write_bundle(root: Path, names: tuple[str, ...]) -> None:
    root.mkdir(parents=True)
    for name in names:
        (root / name).write_text(f"fixture:{name}\n", encoding="utf-8")


class PublicBundleTests(unittest.TestCase):
    def test_legacy_and_candidate_allowlists_are_exact(self) -> None:
        self.assertEqual(
            LEGACY_PUBLIC_FILES,
            ("README.md", "clash.yaml", "last-run.txt", "status.json"),
        )
        self.assertEqual(
            CANDIDATE_PUBLIC_FILES,
            (*LEGACY_PUBLIC_FILES, "candidate-metadata.json"),
        )

        with temporary_directory() as directory:
            root = Path(directory)
            legacy = root / "legacy"
            candidate = root / "candidate"
            write_bundle(legacy, LEGACY_PUBLIC_FILES)
            write_bundle(candidate, CANDIDATE_PUBLIC_FILES)

            self.assertEqual(
                tuple(path.name for path in validate_public_bundle(legacy, kind="legacy")),
                LEGACY_PUBLIC_FILES,
            )
            self.assertEqual(
                tuple(
                    path.name
                    for path in validate_public_bundle(candidate, kind="candidate")
                ),
                CANDIDATE_PUBLIC_FILES,
            )

    def test_private_runtime_state_is_rejected_without_echoing_its_name_or_content(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "destination"
            write_bundle(source, LEGACY_PUBLIC_FILES)
            sensitive_name = "crawler-subs.json"
            sensitive_value = "https://private.invalid/sub?token=credential-sentinel"
            (source / sensitive_name).write_text(sensitive_value, encoding="utf-8")

            with self.assertRaises(PublicBundleError) as raised:
                copy_public_bundle(source, destination, kind="legacy")

            message = str(raised.exception)
            self.assertNotIn(sensitive_name, message)
            self.assertNotIn("private.invalid", message)
            self.assertNotIn("credential-sentinel", message)
            self.assertFalse(destination.exists())

    def test_candidate_sidecar_cannot_enter_a_legacy_bundle(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            write_bundle(root / "bundle", CANDIDATE_PUBLIC_FILES)

            with self.assertRaisesRegex(PublicBundleError, "incomplete or unexpected"):
                validate_public_bundle(root / "bundle", kind="legacy")

    def test_copy_uses_only_the_validated_candidate_allowlist(self) -> None:
        with temporary_directory() as directory:
            root = Path(directory)
            source = root / "source"
            destination = root / "worktree"
            write_bundle(source, CANDIDATE_PUBLIC_FILES)
            destination.mkdir()
            (destination / ".git").write_text("gitdir: fixture\n", encoding="utf-8")

            copied = copy_public_bundle(source, destination, kind="candidate")

            self.assertEqual(tuple(path.name for path in copied), CANDIDATE_PUBLIC_FILES)
            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {".git", *CANDIDATE_PUBLIC_FILES},
            )


if __name__ == "__main__":
    unittest.main()
