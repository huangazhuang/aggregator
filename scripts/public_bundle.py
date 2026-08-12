#!/usr/bin/env python3
"""Validate and copy the exact files allowed in public subscription bundles."""

from __future__ import annotations

import argparse
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path


LEGACY_PUBLIC_FILES = (
    "README.md",
    "clash.yaml",
    "last-run.txt",
    "status.json",
)
CANDIDATE_PUBLIC_FILES = (*LEGACY_PUBLIC_FILES, "candidate-metadata.json")
PUBLIC_BUNDLE_KINDS = {
    "legacy": LEGACY_PUBLIC_FILES,
    "candidate": CANDIDATE_PUBLIC_FILES,
}


class PublicBundleError(ValueError):
    """Raised when a public bundle is incomplete or contains extra state."""


def public_bundle_files(kind: str) -> tuple[str, ...]:
    try:
        return PUBLIC_BUNDLE_KINDS[kind]
    except KeyError:
        raise PublicBundleError("public bundle kind is unsupported") from None


def validate_public_bundle(directory: str | Path, *, kind: str) -> tuple[Path, ...]:
    """Fail closed unless ``directory`` contains exactly the public allowlist."""

    root = Path(directory)
    if root.is_symlink() or not root.is_dir():
        raise PublicBundleError("public bundle directory is invalid")
    expected = public_bundle_files(kind)
    try:
        entries = tuple(root.iterdir())
    except OSError:
        raise PublicBundleError("unable to inspect public bundle") from None
    if {entry.name for entry in entries} != set(expected):
        raise PublicBundleError("public bundle file set is incomplete or unexpected")
    ordered = tuple(root / name for name in expected)
    if any(path.is_symlink() or not path.is_file() for path in ordered):
        raise PublicBundleError("public bundle contains a non-regular file")
    return ordered


def copy_public_bundle(
    source: str | Path,
    destination: str | Path,
    *,
    kind: str,
) -> tuple[Path, ...]:
    """Copy only a validated public allowlist into a publication worktree."""

    source_files = validate_public_bundle(source, kind=kind)
    target = Path(destination)
    if target.is_symlink():
        raise PublicBundleError("public bundle destination is invalid")
    try:
        target.mkdir(parents=True, exist_ok=True)
        copied: list[Path] = []
        for source_file in source_files:
            destination_file = target / source_file.name
            if destination_file.is_symlink():
                raise PublicBundleError("public bundle destination is invalid")
            shutil.copyfile(source_file, destination_file)
            copied.append(destination_file)
    except PublicBundleError:
        raise
    except OSError:
        raise PublicBundleError("unable to copy public bundle") from None
    return tuple(copied)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--directory", required=True)
    validate.add_argument("--kind", choices=tuple(PUBLIC_BUNDLE_KINDS), required=True)
    copy = commands.add_parser("copy")
    copy.add_argument("--source", required=True)
    copy.add_argument("--destination", required=True)
    copy.add_argument("--kind", choices=tuple(PUBLIC_BUNDLE_KINDS), required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate":
            validate_public_bundle(args.directory, kind=args.kind)
        else:
            copy_public_bundle(args.source, args.destination, kind=args.kind)
    except PublicBundleError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CANDIDATE_PUBLIC_FILES",
    "LEGACY_PUBLIC_FILES",
    "PublicBundleError",
    "copy_public_bundle",
    "public_bundle_files",
    "validate_public_bundle",
]
