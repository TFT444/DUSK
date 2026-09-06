from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dusk.permits import PermitError, issue_permit
from dusk.proxy import EmergencyKillSwitch, ExecutionBlockedError, RestrictedExecutionProxy


def test_proxy_verifies_permit_before_executor() -> None:
    key = Ed25519PrivateKey.generate()
    action = {"action_type": "read", "target": "safe"}
    permit = issue_permit(
        key,
        tenant_id="t",
        agent_id="a",
        action=action,
        policy_version="p",
        now=datetime.now(UTC),
    )
    calls: list[dict[str, object]] = []
    result = RestrictedExecutionProxy(key.public_key()).execute(
        permit,
        tenant_id="t",
        agent_id="a",
        action=action,
        policy_version="p",
        executor=lambda value: calls.append(value) or "ok",
    )
    assert result == "ok"
    assert calls == [action]


def test_proxy_fails_closed_when_kill_switch_is_active() -> None:
    key = Ed25519PrivateKey.generate()
    action = {"action_type": "read", "target": "safe"}
    permit = issue_permit(key, tenant_id="t", agent_id="a", action=action, policy_version="p")
    switch = EmergencyKillSwitch()
    switch.activate("incident")
    with pytest.raises(ExecutionBlockedError, match="kill switch"):
        RestrictedExecutionProxy(key.public_key(), kill_switch=switch).execute(
            permit,
            tenant_id="t",
            agent_id="a",
            action=action,
            policy_version="p",
            executor=lambda _: "bad",
        )


def test_proxy_never_calls_executor_for_invalid_permit() -> None:
    key = Ed25519PrivateKey.generate()
    action = {"action_type": "read", "target": "safe"}
    permit = issue_permit(key, tenant_id="t", agent_id="a", action=action, policy_version="p")
    calls = 0

    def executor(_: dict[str, object]) -> str:
        nonlocal calls
        calls += 1
        return "bad"

    with pytest.raises(PermitError):
        RestrictedExecutionProxy(key.public_key()).execute(
            permit,
            tenant_id="wrong",
            agent_id="a",
            action=action,
            policy_version="p",
            executor=executor,
        )
    assert calls == 0


def test_kill_switch_reports_active_reason() -> None:
    switch = EmergencyKillSwitch()
    switch.activate("incident")
    assert switch.active is True
    assert switch.reason == "incident"
