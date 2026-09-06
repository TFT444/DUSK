"""Release and activation gates for deferred live provider certification."""

from pathlib import Path

RELEASE_WORKFLOW = Path(".github/workflows/release.yml")
LIVE_MANIFEST = Path("docs/evidence/provider-certification.json")


def test_pull_request_work_can_proceed_without_fabricated_live_manifest() -> None:
    assert not LIVE_MANIFEST.exists()


def test_production_release_requires_validated_provider_manifest() -> None:
    workflow = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    assert "python scripts/validate_provider_certification.py" in workflow
    assert "docs/evidence/provider-certification.json" in workflow
