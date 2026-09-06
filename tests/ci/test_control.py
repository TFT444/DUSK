from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from scripts.ci.control import aggregate, load_catalogue, record

CATALOGUE = Path(__file__).parents[2] / "ci" / "controls.yml"


def test_catalogue_has_exactly_100_unique_controls() -> None:
    assert len(load_catalogue(CATALOGUE)) == 100


def test_record_rejects_unauthorized_not_applicable(tmp_path: Path) -> None:
    controls = load_catalogue(CATALOGUE)
    args = argparse.Namespace(
        control="PR-001",
        status="NOT_APPLICABLE",
        output=tmp_path / "x.json",
        details="",
        changed_file=["README.md"],
    )
    with pytest.raises(ValueError, match="unauthorized"):
        record(args, controls)


def test_aggregate_fails_for_missing_duplicate_failure_and_malformed(tmp_path: Path) -> None:
    controls = load_catalogue(CATALOGUE)
    failure = {"schema_version": 1, "control_id": "REL-001", "status": "FAIL"}
    success = {"schema_version": 1, "control_id": "REL-001", "status": "PASS"}
    (tmp_path / "one.json").write_text(json.dumps(failure))
    (tmp_path / "two.json").write_text(json.dumps(success))
    (tmp_path / "bad.json").write_text("{")
    args = argparse.Namespace(lane="release", results=str(tmp_path))
    with pytest.raises(SystemExit):
        aggregate(args, controls)


def test_release_aggregation_passes_with_complete_evidence(tmp_path: Path) -> None:
    controls = load_catalogue(CATALOGUE)
    for control_id, item in controls.items():
        if item["lane"] == "release":
            (tmp_path / f"{control_id}.json").write_text(
                json.dumps({"schema_version": 1, "control_id": control_id, "status": "PASS"})
            )
    aggregate(argparse.Namespace(lane="release", results=str(tmp_path)), controls)
