#!/usr/bin/env python3
"""Reject undocumented or expired scanner suppressions."""

from datetime import date
from pathlib import Path

import yaml


def main() -> None:
    path = Path("ci/suppressions.yml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    for item in data.get("suppressions", []):
        if not all(item.get(key) for key in ("control", "finding", "reason", "owner", "expires")):
            raise SystemExit("every suppression needs control, reason, owner, and expiry")
        if date.fromisoformat(str(item["expires"])) < date.today():
            raise SystemExit(f"expired suppression: {item['control']}")


if __name__ == "__main__":
    main()
