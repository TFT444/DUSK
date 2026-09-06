"""Check that package and runtime versions remain synchronized."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION_RE = re.compile(r'^__version__ = "([^"]+)"$', re.MULTILINE)


def _project_version(path: Path) -> str:
    """Read the PEP 621 project version from a pyproject file."""
    with path.open("rb") as handle:
        return str(tomllib.load(handle)["project"]["version"])


def _runtime_version(path: Path) -> str:
    """Read a runtime version without importing the target package."""
    match = VERSION_RE.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"No __version__ assignment found in {path}")
    return match.group(1)


def main() -> int:
    """Return nonzero when package versions or an optional expected version differ."""
    versions = {
        "root project": _project_version(ROOT / "pyproject.toml"),
        "root runtime": _runtime_version(ROOT / "src/dusk/__init__.py"),
        "production harness project": _project_version(ROOT / "dusk-agent-harness/pyproject.toml"),
        "production harness gate": _runtime_version(
            ROOT / "dusk-agent-harness/src/dusk/__init__.py"
        ),
    }
    expected = sys.argv[1].removeprefix("v") if len(sys.argv) == 2 else None
    canonical = next(iter(versions.values()))
    failures = {name: version for name, version in versions.items() if version != canonical}
    if expected is not None and canonical != expected:
        failures["release tag"] = expected

    if failures:
        print(f"Canonical version: {canonical}", file=sys.stderr)
        for name, version in failures.items():
            print(f"Version mismatch: {name}={version}", file=sys.stderr)
        return 1

    print(f"All package versions match {canonical}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
