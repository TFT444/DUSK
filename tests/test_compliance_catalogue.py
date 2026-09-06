from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE_PATH = ROOT / "src" / "dusk" / "policies" / "compliance-v1.yaml"
VALID_STATUSES = {"implemented", "partial", "planned", "blocked", "unverified"}
ALLOWED_FRAMEWORKS = {
    "OWASP",
    "NIST AI RMF",
    "NIST CSF",
    "ISO 27001",
    "SOC 2",
    "CIS Controls",
}


def load_catalogue() -> dict:
    with CATALOGUE_PATH.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    assert isinstance(value, dict)
    return value


def test_catalogue_has_unique_ids_and_allowed_statuses() -> None:
    catalogue = load_catalogue()
    assert catalogue["catalogue_id"] == "dusk-compliance"
    ids = [control["id"] for control in catalogue["controls"]]
    assert len(ids) == len(set(ids))
    assert {control["status"] for control in catalogue["controls"]} <= VALID_STATUSES


def test_catalogue_controls_have_frameworks_and_evidence() -> None:
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        assert control["frameworks"]
        assert control["evidence"]


def test_evidence_paths_exist_or_are_explicitly_unverified() -> None:
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        if control["status"] in {"implemented", "partial"}:
            assert all((ROOT / path).exists() for path in control["evidence"])


def test_framework_names_are_allowlisted() -> None:
    catalogue = load_catalogue()
    for control in catalogue["controls"]:
        assert set(control["frameworks"]) <= ALLOWED_FRAMEWORKS


def test_documentation_mentions_catalogue_and_claim_boundary() -> None:
    path = ROOT / "docs" / "compliance-control-catalogue.md"
    assert path.exists()
    text = path.read_text(encoding="utf-8")
    assert "compliance-v1.yaml" in text
    assert "does not claim certification" in text
