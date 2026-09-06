"""Tests for the deterministic enterprise policy pack."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from dusk.policies import Decision, load_enterprise_pack
from dusk.policies.engine import load_policy_pack


def _write_pack(tmp_path: Path, raw: object) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def _raw_pack() -> dict[str, object]:
    path = Path(__file__).parents[1] / "src" / "dusk" / "policies" / "enterprise-v1.yaml"
    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_enterprise_catalogue_is_complete_and_unique() -> None:
    pack = load_enterprise_pack()
    assert pack.name == "dusk-enterprise"
    assert len(pack.rules) == 87
    assert len({rule.id for rule in pack.rules}) == len(pack.rules)
    assert sum(rule.status == "enforced" for rule in pack.rules) == 51
    assert {rule.category for rule in pack.rules} >= {
        "identity",
        "permit",
        "broker",
        "filesystem",
        "execution",
        "network",
        "cloud",
        "secrets",
        "data",
        "communication",
        "mcp",
        "supply-chain",
        "behavior",
        "tenant",
    }


def test_deny_overrides_approval() -> None:
    context = {
        "action": {
            "category": "production",
            "type": "network.firewall.update",
            "cidrs": ["0.0.0.0/0"],
        },
        "approval": {"valid": False},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert {rule.id for rule in result.matched_rules} == {"DUSK-NET-001", "DUSK-CONSEQ-001"}


def test_cross_tenant_rule_compares_runtime_fields() -> None:
    context = {
        "identity": {"tenant_id": "tenant-a"},
        "action": {"tenant_id": "tenant-b"},
    }
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is Decision.DENY
    assert [rule.id for rule in result.matched_rules] == ["DUSK-IAM-002"]


def test_clean_action_is_allowed() -> None:
    context = {
        "action": {"type": "filesystem.read", "consequential": False},
        "resource": {"within_approved_root": True, "classification": "internal"},
    }
    assert load_enterprise_pack().evaluate(context).decision is Decision.ALLOW


@pytest.mark.parametrize(
    ("rule_id", "context", "decision"),
    [
        (
            "DUSK-IAM-001",
            {
                "identity": {"agent_id": "agent-a"},
                "action": {
                    "type": "iam.role.assign",
                    "target_identity": "agent-a",
                    "role": "owner",
                },
            },
            Decision.DENY,
        ),
        (
            "DUSK-IAM-002",
            {"identity": {"tenant_id": "a"}, "action": {"tenant_id": "b"}},
            Decision.DENY,
        ),
        (
            "DUSK-PERMIT-001",
            {"action": {"consequential": True}, "permit": {"valid": False}},
            Decision.DENY,
        ),
        ("DUSK-PERMIT-002", {"permit": {"expired": True}}, Decision.DENY),
        ("DUSK-PERMIT-003", {"permit": {"replayed": True}}, Decision.DENY),
        (
            "DUSK-PERMIT-004",
            {"permit": {"present": True, "action_matches": False}},
            Decision.DENY,
        ),
        (
            "DUSK-BROKER-001",
            {"action": {"protected_target": True}, "execution": {"via_broker": False}},
            Decision.DENY,
        ),
        (
            "DUSK-SECRET-001",
            {
                "action": {"type": "filesystem.read"},
                "resource": {"classification": "secret"},
            },
            Decision.DENY,
        ),
        (
            "DUSK-SECRET-002",
            {"data": {"contains_secret": True}, "destination": {"external": True}},
            Decision.DENY,
        ),
        (
            "DUSK-EXEC-001",
            {"action": {"type": "process.execute", "command_class": "destructive"}},
            Decision.DENY,
        ),
        (
            "DUSK-FS-001",
            {
                "action": {"type": "filesystem.write"},
                "resource": {"within_approved_root": False},
            },
            Decision.DENY,
        ),
        (
            "DUSK-NET-001",
            {"action": {"type": "network.firewall.update", "cidrs": ["0.0.0.0/0"]}},
            Decision.DENY,
        ),
        (
            "DUSK-NET-002",
            {"destination": {"external": True, "approved": False}},
            Decision.DENY,
        ),
        (
            "DUSK-MCP-001",
            {"action": {"type": "mcp.tool.call"}, "tool": {"trusted": False}},
            Decision.DENY,
        ),
        (
            "DUSK-CONSEQ-001",
            {
                "action": {"category": "financial", "consequential": False},
                "approval": {"valid": False},
            },
            Decision.REQUIRE_APPROVAL,
        ),
    ],
)
def test_every_enforced_rule_has_a_denial_scenario(
    rule_id: str, context: dict[str, object], decision: Decision
) -> None:
    result = load_enterprise_pack().evaluate(context)
    assert result.decision is decision
    assert rule_id in {rule.id for rule in result.matched_rules}


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda raw: raw["rules"].append(deepcopy(raw["rules"][0])), "unique"),
        (lambda raw: raw["rules"][0].update({"severity": "urgent"}), "severity"),
        (lambda raw: raw["rules"][0].update({"unsupported": True}), "unsupported"),
        (lambda raw: raw["rules"][0].update({"tests": []}), "require"),
    ],
)
def test_invalid_catalogues_fail_closed(tmp_path: Path, mutation: object, message: str) -> None:
    raw = _raw_pack()
    assert callable(mutation)
    mutation(raw)
    with pytest.raises(ValueError, match=message):
        load_policy_pack(_write_pack(tmp_path, raw))


def test_decision_evidence_contains_versions_and_no_context() -> None:
    # Use a valid domain ("identity") so strict context validation passes.
    # The unique sentinel value verifies that context field values are never
    # echoed in the audit output.
    result = (
        load_enterprise_pack()
        .evaluate(
            {
                "permit": {"expired": True},
                "identity": {"agent_id": "must-not-appear"},
            }
        )
        .to_dict()
    )
    assert result["policy_version"] == "1.0.0"
    assert result["matched_rules"] == [
        {
            "id": "DUSK-PERMIT-002",
            "version": "1.0.0",
            "title": "Reject expired permits",
            "owner": "DUSK Security",
            "severity": "critical",
            "frameworks": ["OWASP-AGENTIC", "NIST-AI-RMF"],
            "reason": "Expired authorization cannot approve a new action.",
        }
    ]
    assert "must-not-appear" not in str(result)
