"""Cloud, infrastructure, and Kubernetes policy scenarios."""

from __future__ import annotations

import pytest

from dusk.policies import Decision, load_enterprise_pack


def _confirmed(context: dict[str, object]) -> dict[str, object]:
    return {
        domain: {**value, "_evidence": "CONFIRMED"} if isinstance(value, dict) else value
        for domain, value in context.items()
    }


@pytest.mark.parametrize(
    ("rule_id", "context", "decision"),
    [
        (
            "DUSK-CLOUD-001",
            {
                "action": {"type": "cloud.resource.delete"},
                "cloud": {"environment": "production"},
                "approval": {"valid": False},
            },
            Decision.REQUIRE_APPROVAL,
        ),
        (
            "DUSK-CLOUD-002",
            {
                "action": {"type": "cloud.control.update"},
                "cloud": {"control": "audit", "enabled": False},
            },
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-003",
            {"cloud": {"public_exposure": True}, "approval": {"valid": False}},
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-004",
            {"kubernetes": {"operation": "rbac.grant", "role": "cluster-admin"}},
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-005",
            {"kubernetes": {"operation": "workload.create", "privileged": True}},
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-006",
            {
                "action": {"type": "secret.read"},
                "cloud": {"workload_identity_authorized": False},
            },
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-007",
            {
                "kubernetes": {"operation": "service.create", "public_exposure": True},
                "approval": {"valid": False},
            },
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-008",
            {"infrastructure": {"destructive": True}, "approval": {"valid": False}},
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-009",
            {"infrastructure": {"disables_controls": ["audit"]}},
            Decision.DENY,
        ),
        (
            "DUSK-CLOUD-010",
            {"cloud": {"source_boundary": "account-a", "target_boundary": "account-b"}},
            Decision.DENY,
        ),
    ],
)
def test_cloud_rule_denial_scenarios(
    rule_id: str, context: dict[str, object], decision: Decision
) -> None:
    result = load_enterprise_pack().evaluate(_confirmed(context))

    assert result.decision is decision
    assert rule_id in {rule.id for rule in result.matched_rules}


@pytest.mark.parametrize(
    "context",
    [
        {
            "action": {"type": "cloud.resource.delete", "consequential": False},
            "cloud": {"environment": "development"},
            "approval": {"valid": False},
        },
        {
            "action": {"type": "cloud.control.update", "consequential": False},
            "cloud": {"control": "audit", "enabled": True},
        },
        {"cloud": {"public_exposure": False}},
        {"kubernetes": {"operation": "rbac.grant", "role": "view"}},
        {"kubernetes": {"operation": "workload.create", "privileged": False}},
        {
            "action": {"type": "secret.read", "consequential": False},
            "cloud": {"workload_identity_authorized": True},
        },
        {
            "kubernetes": {"operation": "service.create", "public_exposure": False},
            "approval": {"valid": False},
        },
        {"infrastructure": {"destructive": False, "disables_controls": []}},
        {"cloud": {"source_boundary": "account-a", "target_boundary": "account-a"}},
    ],
)
def test_cloud_rule_benign_equivalents_are_allowed(context: dict[str, object]) -> None:
    assert load_enterprise_pack().evaluate(context).decision is Decision.ALLOW


@pytest.mark.parametrize("control", ["audit", "backup", "encryption"])
def test_infrastructure_safeguard_disablement_is_denied(control: str) -> None:
    result = load_enterprise_pack().evaluate(
        _confirmed({"infrastructure": {"disables_controls": [control]}})
    )

    assert "DUSK-CLOUD-009" in {rule.id for rule in result.matched_rules}


def test_cloud_rule_domains_require_live_verified_sources() -> None:
    pack = load_enterprise_pack()
    domains = {
        condition.field.split(".", 1)[0]
        for rule in pack.rules
        if rule.id.startswith("DUSK-CLOUD-") and rule.status == "enforced"
        for condition in rule.conditions
    }

    assert domains >= {"action", "approval", "cloud", "kubernetes", "infrastructure"}
