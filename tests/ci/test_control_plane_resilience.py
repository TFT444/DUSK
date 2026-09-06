"""Keep the resilience qualification contract complete and continuously exercised."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).parents[2]
DOCUMENT = ROOT / "docs" / "control-plane-resilience.md"
WORKFLOW = ROOT / ".github" / "workflows" / "dusk.yml"

REQUIRED_FAULTS = (
    "PostgreSQL outage or connection loss",
    "Policy dependency failure",
    "Identity-provider outage or expired JWKS",
    "SIE timeout",
    "Outbox saturation",
    "Duplicate submission",
    "Migration interruption",
    "Worker crash",
    "Clock anomaly",
    "Partial dependency recovery",
    "High concurrency",
)

REQUIRED_EVIDENCE_TESTS = (
    "test_consequential_evaluation_fails_closed_on_storage_outage",
    "test_database_connection_loss_rolls_back_and_normal_retry_recovers",
    "test_stalled_evaluation_is_cancelled_by_fail_closed_request_deadline",
    "test_cancelled_audit_signing_rolls_back_and_idempotent_retry_recovers",
    "test_policy_provider_outage_fails_closed",
    "test_expired_cache_never_falls_back_to_stale_key_during_outage",
    "test_identity_provider_recovery_revalidates_without_stale_bypass",
    "test_sie_timeout_uses_deterministic_fail_soft_embedding",
    "test_batch_saturation_and_concurrency_are_strictly_bounded",
    "test_high_concurrency_duplicate_submission_commits_one_complete_bundle",
    "test_latest_migration_supports_mixed_version_rollback_and_retry",
    "test_expired_lease_is_reclaimed_after_worker_restart",
    "test_broker_acknowledgement_freshness_uses_postgresql_not_worker_clock",
    "test_stale_broker_acknowledgement_fails_closed_against_postgresql_clock",
    "test_concurrent_sequence_allocation_and_restart_recovery",
    "test_idempotency_lock_does_not_block_another_tenant",
)


def test_resilience_contract_covers_every_required_fault_and_recovery_objective() -> None:
    document = DOCUMENT.read_text(encoding="utf-8")
    normalized = " ".join(document.split())
    for fault in REQUIRED_FAULTS:
        assert f"| {fault} |" in document
    assert "Authoritative decision RPO: zero committed records" in document
    assert "Control-plane RTO: five minutes" in document
    assert "Outbox recovery RTO: six minutes" in document
    assert "Audit RPO: zero committed decisions" in document
    assert "not fabricated production measurements" in normalized


def test_every_documented_resilience_evidence_test_exists() -> None:
    test_sources = "\n".join(
        path.read_text(encoding="utf-8")
        for root in (ROOT / "tests", ROOT / "services" / "control-plane" / "tests")
        for path in root.rglob("test_*.py")
    )
    document = DOCUMENT.read_text(encoding="utf-8")
    for test_name in REQUIRED_EVIDENCE_TESTS:
        assert f"def {test_name}" in test_sources
        assert test_name in document


def test_ci_runs_resilience_storage_cases_against_postgresql() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    correctness = workflow["jobs"]["correctness"]
    database = correctness["services"]["postgresql"]
    assert database["image"].startswith("postgres:")
    integration_steps = [
        step
        for step in correctness["steps"]
        if "services/control-plane/tests/integration" in str(step.get("run", ""))
    ]
    assert len(integration_steps) == 1
    assert "DUSK_TEST_DATABASE_URL" in integration_steps[0]["env"]
