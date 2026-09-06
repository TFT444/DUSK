"""Tests for the OWASP technical-evidence validator."""

import importlib.util
import json
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_owasp_readiness.py"
SPEC = importlib.util.spec_from_file_location("check_owasp_readiness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)
MANIFEST = CHECK.MANIFEST
ROOT = CHECK.ROOT
validate = CHECK.validate


def test_repository_owasp_evidence_is_consistent() -> None:
    assert validate(ROOT) == []


def test_missing_manifest_is_reported(tmp_path: Path) -> None:
    assert validate(tmp_path) == [f"missing evidence manifest: {MANIFEST.as_posix()}"]


def test_missing_manifest_evidence_path_is_reported(tmp_path: Path) -> None:
    manifest = tmp_path / MANIFEST
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps({"evidence": [{"id": "missing", "paths": ["not-present.md"]}]}),
        encoding="utf-8",
    )
    (tmp_path / "docs/owasp-application.md").write_text("", encoding="utf-8")
    workflow = tmp_path / ".github/workflows/dusk.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("\n".join(REQUIRED_COMMANDS), encoding="utf-8")
    harness = tmp_path / "dusk-agent-harness/scripts/run_owasp_demo.sh"
    harness.parent.mkdir(parents=True)
    harness.write_text("\n".join(REQUIRED_MARKERS), encoding="utf-8")

    assert "missing evidence path: not-present.md" in validate(tmp_path)


REQUIRED_COMMANDS = (
    "run_owasp_demo.sh --no-build watch",
    "run_owasp_demo.sh --no-build enforce",
)
REQUIRED_MARKERS = (
    'if [ "${1:-}" = "--no-build" ]',
    "$COMPOSE build dusk-gate mock-prod runtime",
    "up --detach --no-build --wait",
    "run --rm --pull never runtime",
    "trap cleanup EXIT",
)
