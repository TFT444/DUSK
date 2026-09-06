#!/usr/bin/env python3
"""Enforce immutable actions, explicit timeouts, and least privilege."""

import re
from pathlib import Path

import yaml


def main() -> None:
    errors: list[str] = []
    for path in sorted(Path(".github/workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
        if data.get("permissions") != {"contents": "read"}:
            errors.append(f"{path}: top-level permissions must be contents: read")
        for name, job in data.get("jobs", {}).items():
            if "timeout-minutes" not in job:
                errors.append(f"{path}:{name}: missing timeout-minutes")
        for action in re.findall(r"uses:\s*([^\s#]+)", text):
            if not re.fullmatch(r"[^@]+@[0-9a-f]{40}", action):
                errors.append(f"{path}: action is not pinned to a full SHA: {action}")
        if "pull_request_target" in text:
            errors.append(f"{path}: pull_request_target is prohibited")
    if errors:
        raise SystemExit("\n".join(errors))


if __name__ == "__main__":
    main()
