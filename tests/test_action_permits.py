from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dusk.permits import PermitError, ReplayGuard, issue_permit, verify_permit


def _action() -> dict[str, object]:
    return {
        "action_type": "route_change",
        "target": "rt-corp-prod",
        "tool": "update_route_table",
        "change": {"destination": "10.0.2.0/24", "gateway": "igw-2"},
    }


def test_signed_permit_verifies_for_exact_action() -> None:
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    permit = issue_permit(
        key,
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
        ttl_seconds=30,
    )

    verified = verify_permit(
        permit,
        key.public_key(),
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
    )

    assert verified.permit_id == permit.permit_id


@pytest.mark.parametrize("field", ["tenant_id", "agent_id", "policy_version"])
def test_permit_rejects_context_mismatch(field: str) -> None:
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    permit = issue_permit(
        key,
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
    )
    values = {
        "tenant_id": "tenant-b",
        "agent_id": "agent-2",
        "policy_version": "enterprise-v2",
    }
    kwargs = {
        "tenant_id": "tenant-a",
        "agent_id": "agent-1",
        "action": _action(),
        "policy_version": "enterprise-v1",
        "now": now,
    }
    kwargs[field] = values[field]

    with pytest.raises(PermitError, match="binding"):
        verify_permit(permit, key.public_key(), **kwargs)


def test_permit_rejects_tampered_action_and_expiry() -> None:
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    permit = issue_permit(
        key,
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
        ttl_seconds=10,
    )

    changed = {**_action(), "target": "rt-other"}
    with pytest.raises(PermitError, match="binding"):
        verify_permit(
            permit,
            key.public_key(),
            tenant_id="tenant-a",
            agent_id="agent-1",
            action=changed,
            policy_version="enterprise-v1",
            now=now,
        )

    with pytest.raises(PermitError, match="expired"):
        verify_permit(
            permit,
            key.public_key(),
            tenant_id="tenant-a",
            agent_id="agent-1",
            action=_action(),
            policy_version="enterprise-v1",
            now=now.replace(second=11),
        )


def test_permit_rejects_wrong_public_key() -> None:
    key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    permit = issue_permit(
        key,
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
    )
    with pytest.raises(PermitError):
        verify_permit(
            permit,
            wrong_key.public_key(),
            tenant_id="tenant-a",
            agent_id="agent-1",
            action=_action(),
            policy_version="enterprise-v1",
            now=now,
        )


def test_permit_rejects_boolean_substitution_for_integer() -> None:
    key = Ed25519PrivateKey.generate()
    permit = issue_permit(key, tenant_id="t", agent_id="a", action={"count": 1}, policy_version="p")
    with pytest.raises(PermitError, match="binding"):
        verify_permit(
            permit,
            key.public_key(),
            tenant_id="t",
            agent_id="a",
            action={"count": True},
            policy_version="p",
        )


def test_permit_is_single_use() -> None:
    key = Ed25519PrivateKey.generate()
    now = datetime(2026, 9, 3, 12, 0, tzinfo=UTC)
    permit = issue_permit(
        key,
        tenant_id="tenant-a",
        agent_id="agent-1",
        action=_action(),
        policy_version="enterprise-v1",
        now=now,
    )
    guard = ReplayGuard()
    kwargs = {
        "tenant_id": "tenant-a",
        "agent_id": "agent-1",
        "action": _action(),
        "policy_version": "enterprise-v1",
        "now": now,
        "replay_guard": guard,
    }
    verify_permit(permit, key.public_key(), **kwargs)
    with pytest.raises(PermitError, match="replay"):
        verify_permit(permit, key.public_key(), **kwargs)
