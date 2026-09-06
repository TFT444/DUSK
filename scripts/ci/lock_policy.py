#!/usr/bin/env python3
"""Require every direct dependency to be represented in a hash-locked input."""

import re
from pathlib import Path

ENTRY = re.compile(r"(?m)^[A-Za-z0-9_.-]+==[^\s\\]+")


def main() -> None:
    for lock in (Path("ci/requirements.lock"), Path("ci/example-requirements.lock")):
        text = lock.read_text(encoding="utf-8")
        matches = list(ENTRY.finditer(text))
        blocks = [
            text[match.start() : matches[index + 1].start() if index + 1 < len(matches) else None]
            for index, match in enumerate(matches)
        ]
        if not blocks or any("--hash=sha256:" not in block for block in blocks):
            raise SystemExit(f"{lock} must contain pinned, hashed requirements")


if __name__ == "__main__":
    main()
