"""Fail-closed tests for live AWS, Azure, and Kubernetes evidence."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/validate_provider_certification.py"
SPEC = importlib.util.spec_from_file_location("validate_provider_certification", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
NOW = "2026-09-04T10:00:00Z"
LATER = "2026-09-04T10:01:00Z"


def _result(*, mode: str, malicious: bool) -> dict[str, Any]:
    verdict = "ALLOW"
    if malicious:
        verdict = "WOULD-BLOCK" if mode == "watch" else "BLOCK"
    return {
        "mode": mode,
        "verdict": verdict,
        "trace_id": f"trace-{mode}",
        "decision_id": f"decision-{mode}",
        "policy_rule_ids": ["DUSK-CLOUD-TEST"] if malicious else [],
        "evidence_state": "CONFIRMED",
        "dashboard_visible": True,
        "audit": {"sequence": 1, "digest": DIGEST_A},
        "lifecycle": {
            "status": "BLOCKED" if malicious and mode == "enforce" else "ACKNOWLEDGED",
            "acknowledgement_id": f"ack-{mode}",
        },
        "before_digest": DIGEST_A,
        "after_digest": DIGEST_A if malicious and mode == "enforce" else DIGEST_B,
        "downstream_mutated": not (malicious and mode == "enforce"),
    }


def _scenario(name: str) -> dict[str, Any]:
    malicious = not name.startswith("benign_")
    return {
        "name": name,
        "classification": "malicious" if malicious else "benign",
        "commands": [
            {
                "argv": ["provider-cli", "apply", "redacted-resource-alias"],
                "started_at": NOW,
                "finished_at": LATER,
                "exit_code": 0,
                "output_digest": DIGEST_A,
            }
        ],
        "results": [
            _result(mode="watch", malicious=malicious),
            _result(mode="enforce", malicious=malicious),
        ],
    }


def valid_manifest() -> dict[str, Any]:
    providers = []
    for provider, names in VALIDATOR.REQUIRED_SCENARIOS.items():
        providers.append(
            {
                "name": provider,
                "sandbox_approved": True,
                "identity": {"mechanism": "oidc", "principal_digest": DIGEST_A},
                "resource_id_digest": DIGEST_A,
                "service_image_digest": DIGEST_B,
                "scenarios": [_scenario(name) for name in sorted(names)],
                "teardown": {
                    "completed": True,
                    "baseline_restored": True,
                    "baseline_digest": DIGEST_A,
                    "final_digest": DIGEST_A,
                },
            }
        )
    return {
        "schema_version": "1.0",
        "commit_sha": "c" * 40,
        "run_id": "protected-run-123",
        "started_at": NOW,
        "finished_at": LATER,
        "review": {
            "reviewer": "security-reviewer",
            "approval_reference": "change-123",
            "approved_at": LATER,
        },
        "certified_rule_ids": sorted(VALIDATOR.CERTIFIED_RULE_IDS),
        "providers": providers,
    }


def _malicious_aws_scenario(manifest: dict[str, Any]) -> dict[str, Any]:
    aws = next(provider for provider in manifest["providers"] if provider["name"] == "aws")
    return next(
        scenario for scenario in aws["scenarios"] if scenario["classification"] == "malicious"
    )


def test_complete_live_provider_manifest_is_accepted() -> None:
    assert VALIDATOR.validate_manifest(valid_manifest()) == []


def test_all_three_providers_are_mandatory() -> None:
    manifest = valid_manifest()
    manifest["providers"] = manifest["providers"][:-1]

    assert "providers must contain aws, azure, and kubernetes exactly once" in (
        VALIDATOR.validate_manifest(manifest)
    )


def test_complete_cloud_rule_set_is_mandatory() -> None:
    manifest = valid_manifest()
    manifest["certified_rule_ids"].pop()

    assert any(
        "DUSK-CLOUD-001 through DUSK-CLOUD-010" in failure
        for failure in VALIDATOR.validate_manifest(manifest)
    )


def test_simulated_or_secret_bearing_commands_are_rejected() -> None:
    manifest = valid_manifest()
    scenario = manifest["providers"][0]["scenarios"][0]
    scenario["commands"][0]["argv"] = ["mock-provider", "Bearer secret-token"]

    failures = VALIDATOR.validate_manifest(manifest)

    assert any("simulated or sensitive content" in failure for failure in failures)


def test_missing_attack_scenario_is_rejected() -> None:
    manifest = valid_manifest()
    manifest["providers"][0]["scenarios"].pop()

    assert any(
        "does not match the required aws matrix" in failure
        for failure in VALIDATOR.validate_manifest(manifest)
    )


def test_watch_and_enforce_are_both_required() -> None:
    manifest = valid_manifest()
    results = manifest["providers"][0]["scenarios"][0]["results"]
    results[1] = copy.deepcopy(results[0])

    assert any(
        "must cover watch and enforce exactly once" in failure
        for failure in VALIDATOR.validate_manifest(manifest)
    )


def test_blocked_action_must_prove_unchanged_downstream_state() -> None:
    manifest = valid_manifest()
    result = _malicious_aws_scenario(manifest)["results"][1]
    result["after_digest"] = DIGEST_B
    result["downstream_mutated"] = True

    failures = VALIDATOR.validate_manifest(manifest)

    assert any("downstream_mutated must be false" in failure for failure in failures)
    assert any("proves downstream mutation" in failure for failure in failures)


def test_trace_policy_audit_dashboard_and_acknowledgement_are_required() -> None:
    manifest = valid_manifest()
    result = _malicious_aws_scenario(manifest)["results"][0]
    result["trace_id"] = ""
    result["policy_rule_ids"] = []
    result["audit"] = {}
    result["dashboard_visible"] = False
    result["lifecycle"] = {}

    failures = VALIDATOR.validate_manifest(manifest)

    for field in (
        "trace_id",
        "policy_rule_ids",
        "audit.sequence",
        "audit.digest",
        "dashboard_visible",
        "lifecycle.status",
        "lifecycle.acknowledgement_id",
    ):
        assert any(field in failure for failure in failures)


def test_teardown_must_restore_provider_baseline() -> None:
    manifest = valid_manifest()
    manifest["providers"][2]["teardown"]["final_digest"] = DIGEST_B

    assert any(
        "final state differs from its baseline" in failure
        for failure in VALIDATOR.validate_manifest(manifest)
    )


def test_load_rejects_oversized_and_invalid_json(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("not json", encoding="utf-8")
    assert VALIDATOR.load_and_validate(invalid)[0].startswith("unable to load manifest")

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (VALIDATOR.MAX_MANIFEST_BYTES + 1))
    assert VALIDATOR.load_and_validate(oversized) == ["manifest exceeds the 2 MiB size limit"]


def test_cli_returns_nonzero_for_incomplete_evidence(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"schema_version": "1.0"}), encoding="utf-8")

    assert VALIDATOR.main([str(manifest)]) == 1
