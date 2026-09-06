#!/usr/bin/env python3
"""Fast, deterministic repository-integrity policy checks."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

TEXT_SUFFIXES = {".py", ".md", ".rst", ".toml", ".yml", ".yaml", ".json", ".txt", ".sh"}
MAX_BYTES = 5 * 1024 * 1024
LEGACY_HARNESS_REFERENCE = "/".join(("examples", "agent-action-monitor"))
APPROVED_LEGACY_ARCHIVE_PATHS = frozenset(
    {
        "docs/superpowers/plans/2026-08-28-main-mantle-validation.md",
        "docs/superpowers/plans/2026-08-28-multi-model-dev-validation.md",
        "docs/superpowers/plans/2026-08-31-production-agent-harness.md",
        "docs/superpowers/specs/2026-08-31-production-agent-harness-design.md",
    }
)
APPROVED_UPSTREAM_EXAMPLE_URL = (
    "https://github.com/superlinked/sie/tree/main/" + LEGACY_HARNESS_REFERENCE
)
APPROVED_UPSTREAM_EXAMPLE_PATTERN = re.compile(
    rf"{re.escape(APPROVED_UPSTREAM_EXAMPLE_URL)}"
    rf"(?=$|[\s`)\]>]|[.,!;:'\"]+(?=$|\s|[`)\]>]))"
)


def tracked_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"])  # noqa: S607
    return [Path(item.decode()) for item in output.split(b"\0") if item]


def has_active_legacy_harness_reference(path: Path, text: str) -> bool:
    """Return whether a tracked file points at the removed local harness root."""
    repository_path = path.as_posix()
    if repository_path in APPROVED_LEGACY_ARCHIVE_PATHS:
        return False
    active_text = APPROVED_UPSTREAM_EXAMPLE_PATTERN.sub("", text)
    return LEGACY_HARNESS_REFERENCE in active_text


def check() -> list[str]:  # noqa: C901
    errors: list[str] = []
    files = tracked_files()
    folded: dict[str, Path] = {}
    for path in files:
        key = str(path).casefold()
        if key in folded and folded[key] != path:
            errors.append(f"case-insensitive collision: {folded[key]} and {path}")
        folded[key] = path
        if path.is_symlink():
            target = os.readlink(path)
            resolved = (path.parent / target).resolve()
            if target.startswith("/") or not resolved.is_relative_to(Path.cwd().resolve()):
                errors.append(f"unsafe symlink: {path} -> {target}")
        if path.exists():
            if path.stat().st_size > MAX_BYTES:
                errors.append(f"oversized tracked file: {path}")
                continue
            raw = path.read_bytes()
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                if path.suffix in TEXT_SUFFIXES:
                    errors.append(f"not UTF-8: {path}")
                continue
            if path.suffix in TEXT_SUFFIXES:
                if b"\r\n" in raw:
                    errors.append(f"CRLF line endings: {path}")
                if re.search(r"^(<<<<<<<|=======|>>>>>>>)", text, re.MULTILINE):
                    errors.append(f"merge conflict marker: {path}")
            if has_active_legacy_harness_reference(path, text):
                errors.append(f"legacy harness reference in active file: {path}")
    metadata = Path("pyproject.toml").read_text(encoding="utf-8")
    if 'license = "Apache-2.0"' not in metadata or not Path("LICENSE").exists():
        errors.append("Apache-2.0 package metadata and LICENSE are required")
    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    errors = check()
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()
