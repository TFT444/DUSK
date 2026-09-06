from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dusk.policies import Decision, load_enterprise_pack
from dusk.proxy import RestrictedExecutionProxy
from dusk.secure_action_flow import SecureActionFlow


@dataclass
class _Gateway:
    response: dict[str, object]
    calls: int = 0

    def forward(
        self,
        payload: dict[str, object],
        *,
        action: dict[str, object],
        gate: object,
    ) -> dict[str, object]:
        self.calls += 1
        assert callable(gate)
        assert gate(action) == "ALLOW"
        return self.response


def _context() -> dict[str, object]:
    return {
        "action": {"_evidence": "CONFIRMED"},
        "identity": {"_evidence": "CONFIRMED"},
        "tenant": {"_evidence": "CONFIRMED"},
        "execution": {"_evidence": "CONFIRMED"},
        "permit": {"_evidence": "CONFIRMED"},
    }


def _flow(gateway: _Gateway) -> SecureActionFlow:
    key = Ed25519PrivateKey.generate()
    return SecureActionFlow(
        gateway=gateway,
        policy=load_enterprise_pack(),
        private_key=key,
        proxy=RestrictedExecutionProxy(key.public_key()),
        now=lambda: datetime(2026, 9, 6, 12, 0, tzinfo=UTC),
        trace_id=lambda: "trace-1",
    )


def test_safe_action_is_authorized_permitted_executed_and_redacted() -> None:
    gateway = _Gateway({"id": "gateway-response-1"})
    action = {
        "type": "resource.read",
        "target": "customer-record-7",
        "consequential": True,
        "tenant_id": "tenant-a",
    }
    calls: list[dict[str, object]] = []

    result = _flow(gateway).execute(
        payload={"messages": [{"role": "user", "content": "secret prompt"}]},
        action=action,
        policy_context=_context(),
        tenant_id="tenant-a",
        agent_id="agent-a",
        executor=lambda value: calls.append(value) or {"value": "secret result"},
    )

    assert gateway.calls == 1
    assert calls == [action]
    assert result.tool_result == {"value": "secret result"}
    assert result.receipt.decision is Decision.ALLOW
    assert result.receipt.execution_status == "EXECUTED"
    receipt = result.receipt.to_dict()
    assert receipt["trace_id"] == "trace-1"
    assert "secret prompt" not in str(receipt)
    assert "secret result" not in str(receipt)
    assert "customer-record-7" not in str(receipt)


def test_denied_action_never_reaches_the_executor() -> None:
    gateway = _Gateway({"id": "gateway-response-1"})
    calls: list[dict[str, object]] = []

    result = _flow(gateway).execute(
        payload={"messages": []},
        action={
            "type": "network.firewall.update",
            "cidrs": ["0.0.0.0/0"],
            "consequential": True,
            "tenant_id": "tenant-a",
        },
        policy_context=_context(),
        tenant_id="tenant-a",
        agent_id="agent-a",
        executor=lambda value: calls.append(value),
    )

    assert gateway.calls == 1
    assert calls == []
    assert result.tool_result is None
    assert result.receipt.decision is Decision.DENY
    assert result.receipt.execution_status == "BLOCKED"
    assert result.receipt.matched_rule_ids == ("DUSK-NET-001",)


def test_authorization_stage_evaluates_danger_without_requiring_a_future_permit() -> None:
    context = _context()
    context["action"] = {
        "type": "resource.read",
        "consequential": True,
        "tenant_id": "tenant-a",
        "_evidence": "CONFIRMED",
    }
    context["identity"] = {
        "tenant_id": "tenant-a",
        "agent_id": "agent-a",
        "_evidence": "CONFIRMED",
    }

    result = load_enterprise_pack().evaluate(context, stage="authorization")

    assert result.decision is Decision.ALLOW


class _FailingGateway:
    def forward(
        self,
        payload: dict[str, object],
        *,
        action: dict[str, object],
        gate: object,
    ) -> dict[str, object]:
        raise OSError("gateway unavailable")


def test_gateway_failure_fails_closed_before_permit_or_executor() -> None:
    calls: list[dict[str, object]] = []

    result = _flow(_FailingGateway()).execute(  # type: ignore[arg-type]
        payload={"messages": [{"content": "secret prompt"}]},
        action={"type": "resource.read", "consequential": True, "tenant_id": "tenant-a"},
        policy_context=_context(),
        tenant_id="tenant-a",
        agent_id="agent-a",
        executor=lambda value: calls.append(value),
    )

    assert calls == []
    assert result.gateway_response is None
    assert result.tool_result is None
    assert result.receipt.decision is Decision.DENY
    assert result.receipt.gateway_status == "FAILED_CLOSED"
    assert result.receipt.execution_status == "NOT_EXECUTED"


def test_kill_switch_fails_closed_after_policy_authorization() -> None:
    from dusk.proxy import EmergencyKillSwitch

    gateway = _Gateway({"id": "gateway-response-1"})
    key = Ed25519PrivateKey.generate()
    switch = EmergencyKillSwitch()
    switch.activate("incident")
    flow = SecureActionFlow(
        gateway=gateway,
        policy=load_enterprise_pack(),
        private_key=key,
        proxy=RestrictedExecutionProxy(key.public_key(), kill_switch=switch),
        now=lambda: datetime(2026, 9, 6, 12, 0, tzinfo=UTC),
        trace_id=lambda: "trace-kill-switch",
    )
    calls: list[dict[str, object]] = []

    result = flow.execute(
        payload={"messages": []},
        action={"type": "resource.read", "consequential": True, "tenant_id": "tenant-a"},
        policy_context=_context(),
        tenant_id="tenant-a",
        agent_id="agent-a",
        executor=lambda value: calls.append(value),
    )

    assert gateway.calls == 1
    assert calls == []
    assert result.receipt.decision is Decision.DENY
    assert result.receipt.execution_status == "BLOCKED"
