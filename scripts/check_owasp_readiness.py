"""Validate the repository-backed evidence for DUSK's OWASP application."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = Path("docs/owasp-technical-evidence.json")

REQUIRED_WORKFLOW_COMMANDS = (
    "run_owasp_demo.sh --no-build watch",
    "run_owasp_demo.sh --no-build enforce",
)
REQUIRED_HARNESS_MARKERS = (
    'if [ "${1:-}" = "--no-build" ]',
    "$COMPOSE build dusk-gate mock-prod runtime",
    "up --detach --no-build --wait",
    "run --rm --pull never runtime",
    "trap cleanup EXIT",
)


def _load_manifest(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("the evidence manifest must be a JSON object")
    return data


def _validate_evidence(root: Path, manifest: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        return ["evidence manifest must contain a non-empty evidence list"]
    for item in evidence:
        if not isinstance(item, dict) or not isinstance(item.get("paths"), list):
            failures.append("every evidence item must contain a paths list")
            continue
        for relative_path in item["paths"]:
            if not isinstance(relative_path, str) or not (root / relative_path).is_file():
                failures.append(f"missing evidence path: {relative_path}")
    return failures


def _missing_markers(content: str, markers: tuple[str, ...], message: str) -> list[str]:
    return [f"{message}: {marker}" for marker in markers if marker not in content]


def validate(root: Path) -> list[str]:
    """Return actionable failures for repository-backed OWASP evidence."""
    manifest_path = root / MANIFEST
    if not manifest_path.is_file():
        return [f"missing evidence manifest: {MANIFEST.as_posix()}"]
    try:
        manifest = _load_manifest(manifest_path)
    except (json.JSONDecodeError, OSError, ValueError) as error:
        return [f"invalid evidence manifest: {error}"]

    failures = _validate_evidence(root, manifest)

    workflow = (root / ".github/workflows/dusk.yml").read_text(encoding="utf-8")
    failures.extend(
        _missing_markers(
            workflow,
            REQUIRED_WORKFLOW_COMMANDS,
            "CI does not run the scanned production harness image",
        )
    )

    harness_script = (root / "dusk-agent-harness/scripts/run_owasp_demo.sh").read_text(
        encoding="utf-8"
    )
    failures.extend(
        _missing_markers(
            harness_script,
            REQUIRED_HARNESS_MARKERS,
            "OWASP harness validation is missing required behavior",
        )
    )

    return failures


def main() -> int:
    """Exit nonzero when OWASP technical evidence is missing or overstated."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    failures = validate(args.root.resolve())
    if failures:
        for failure in failures:
            print(f"OWASP readiness failure: {failure}")
        return 1
    print("OWASP technical readiness checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
