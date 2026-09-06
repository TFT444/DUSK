"""Tests for the Cloudflare edge demo policy service.

Covers all 12 scenarios from docs/claude-cloudflare-edge-demo-prompt.md.
Tests exercise business logic directly; no HTTP server is spun up.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import time
from dataclasses import replace

import pytest

from dusk.demo_cloudflare import (
    DemoExecutor,
    DemoPolicy,
    HmacGuard,
    Permit,
    _action_digest,
    _issue_permit,
    _permit_payload,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TENANT = "demo-tenant"
AGENT = "demo-agent"
_HMAC_SECRET = b"test-hmac-secret-32bytes-padding!"


@pytest.fixture()
def guard() -> HmacGuard:
    return HmacGuard(secret=_HMAC_SECRET)


@pytest.fixture()
def policy() -> DemoPolicy:
    return DemoPolicy()


@pytest.fixture()
def executor(policy: DemoPolicy) -> DemoExecutor:
    return DemoExecutor(policy.public_key)


def _sign(guard: HmacGuard, method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    msg = f"{method}\n{path}\n{timestamp}\n{nonce}\n".encode() + body
    return _hmac.new(_HMAC_SECRET, msg, hashlib.sha256).hexdigest()


def _fresh_permit(policy: DemoPolicy, action: str = "demo.read_status") -> Permit:
    return _issue_permit(action, TENANT, AGENT, policy._private_key)


# ---------------------------------------------------------------------------
# Scenario 9: HmacGuard — valid request passes
# ---------------------------------------------------------------------------


def test_valid_hmac_passes(guard: HmacGuard) -> None:
    ts = str(int(time.time()))
    nonce = "nonce-abc"
    body = b'{"action":"demo.read_status"}'
    sig = _sign(guard, "POST", "/v1/demo/evaluate", ts, nonce, body)
    assert guard.verify("POST", "/v1/demo/evaluate", ts, nonce, body, sig) is True


# ---------------------------------------------------------------------------
# Scenario 9: HmacGuard — invalid signature blocked
# ---------------------------------------------------------------------------


def test_invalid_hmac_is_blocked(guard: HmacGuard) -> None:
    ts = str(int(time.time()))
    nonce = "nonce-bad"
    body = b'{"action":"demo.read_status"}'
    assert guard.verify("POST", "/v1/demo/evaluate", ts, nonce, body, "deadbeef") is False


# ---------------------------------------------------------------------------
# Scenario 10: HmacGuard — stale timestamp rejected
# ---------------------------------------------------------------------------


def test_stale_timestamp_is_blocked(guard: HmacGuard) -> None:
    stale = str(int(time.time()) - 120)  # 2 minutes ago
    nonce = "nonce-stale"
    body = b"{}"
    sig = _sign(guard, "POST", "/v1/demo/evaluate", stale, nonce, body)
    assert guard.verify("POST", "/v1/demo/evaluate", stale, nonce, body, sig) is False


# ---------------------------------------------------------------------------
# Scenario 10: HmacGuard — replayed nonce blocked
# ---------------------------------------------------------------------------


def test_replayed_nonce_is_blocked(guard: HmacGuard) -> None:
    ts = str(int(time.time()))
    nonce = "nonce-once"
    body = b"{}"
    sig = _sign(guard, "POST", "/v1/demo/evaluate", ts, nonce, body)
    assert guard.verify("POST", "/v1/demo/evaluate", ts, nonce, body, sig) is True
    ts2 = str(int(time.time()))
    sig2 = _sign(guard, "POST", "/v1/demo/evaluate", ts2, nonce, body)
    assert guard.verify("POST", "/v1/demo/evaluate", ts2, nonce, body, sig2) is False


# ---------------------------------------------------------------------------
# Scenario 1: demo.read_status with normal signal → ALLOW + permit issued
# ---------------------------------------------------------------------------


def test_read_status_normal_is_allowed(policy: DemoPolicy) -> None:
    result = policy.evaluate("demo.read_status", "normal", TENANT, AGENT)
    assert result.decision == "ALLOW"
    assert result.permit is not None
    assert result.permit.action == "demo.read_status"
    assert result.permit.tenant_id == TENANT
    assert result.permit.agent_id == AGENT


# ---------------------------------------------------------------------------
# Scenario 2: demo.rotate_demo_key with prompt_injection → BLOCK, no permit
# ---------------------------------------------------------------------------


def test_rotate_key_prompt_injection_is_blocked(policy: DemoPolicy) -> None:
    result = policy.evaluate("demo.rotate_demo_key", "prompt_injection", TENANT, AGENT)
    assert result.decision == "BLOCK"
    assert result.reason_code == "PROMPT_INJECTION_DETECTED"
    assert result.permit is None


# ---------------------------------------------------------------------------
# Scenario 3: Unknown action rejected
# ---------------------------------------------------------------------------


def test_unknown_action_is_rejected(policy: DemoPolicy) -> None:
    result = policy.evaluate("admin.delete_all", "normal", TENANT, AGENT)
    assert result.decision == "BLOCK"
    assert result.reason_code == "UNKNOWN_ACTION"
    assert result.permit is None


# ---------------------------------------------------------------------------
# Scenario 4: Unknown signal rejected
# ---------------------------------------------------------------------------


def test_unknown_signal_is_rejected(policy: DemoPolicy) -> None:
    result = policy.evaluate("demo.read_status", "suspicious", TENANT, AGENT)
    assert result.decision == "BLOCK"
    assert result.reason_code == "UNKNOWN_SIGNAL"
    assert result.permit is None


# ---------------------------------------------------------------------------
# Permit structure: required fields and valid signature
# ---------------------------------------------------------------------------


def test_permit_has_required_fields(policy: DemoPolicy) -> None:
    permit = _fresh_permit(policy)
    assert permit.permit_id
    assert permit.action == "demo.read_status"
    assert permit.action_digest == _action_digest("demo.read_status")
    assert permit.tenant_id == TENANT
    assert permit.agent_id == AGENT
    assert permit.issued_at > 0
    assert permit.expires_at > permit.issued_at
    assert permit.signature


def test_permit_signature_is_verifiable(policy: DemoPolicy, executor: DemoExecutor) -> None:
    """Executor's public key must verify the permit signature."""
    permit = _fresh_permit(policy)
    result = executor.execute(permit, "demo.read_status", TENANT, AGENT)
    assert result.executed is True


# ---------------------------------------------------------------------------
# Scenario 1: Full allow path — executor executes and returns receipt fields
# ---------------------------------------------------------------------------


def test_full_allow_path_returns_execution_success(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    result = executor.execute(permit, "demo.read_status", TENANT, AGENT)
    assert result.executed is True
    assert result.decision == "ALLOW"
    assert result.permit_id == permit.permit_id
    assert result.action_digest == permit.action_digest


# ---------------------------------------------------------------------------
# Scenario 5: Expired permit blocked
# ---------------------------------------------------------------------------


def test_expired_permit_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    expired = replace(permit, expires_at=int(time.time()) - 1)
    result = executor.execute(expired, "demo.read_status", TENANT, AGENT)
    assert result.executed is False
    assert result.reason_code == "PERMIT_EXPIRED"


# ---------------------------------------------------------------------------
# Scenario 6: Replayed permit blocked
# ---------------------------------------------------------------------------


def test_replayed_permit_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    first = executor.execute(permit, "demo.read_status", TENANT, AGENT)
    assert first.executed is True
    second = executor.execute(permit, "demo.read_status", TENANT, AGENT)
    assert second.executed is False
    assert second.reason_code == "PERMIT_REPLAYED"


# ---------------------------------------------------------------------------
# Scenario 7: Permit with changed action blocked
# ---------------------------------------------------------------------------


def test_altered_action_digest_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy, "demo.read_status")
    # Present a different action than what the permit was issued for
    result = executor.execute(permit, "demo.rotate_demo_key", TENANT, AGENT)
    assert result.executed is False
    assert result.reason_code == "ACTION_MISMATCH"


# ---------------------------------------------------------------------------
# Scenario 8: Tenant mismatch blocked
# ---------------------------------------------------------------------------


def test_tenant_mismatch_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    result = executor.execute(permit, "demo.read_status", "other-tenant", AGENT)
    assert result.executed is False
    assert result.reason_code == "IDENTITY_MISMATCH"


# ---------------------------------------------------------------------------
# Scenario 8: Agent mismatch blocked
# ---------------------------------------------------------------------------


def test_agent_mismatch_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    result = executor.execute(permit, "demo.read_status", TENANT, "other-agent")
    assert result.executed is False
    assert result.reason_code == "IDENTITY_MISMATCH"


# ---------------------------------------------------------------------------
# Scenario 8: Tampered signature blocked
# ---------------------------------------------------------------------------


def test_tampered_signature_is_blocked(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    bad_sig = bytes(b ^ 0xFF for b in permit.signature[:32]) + permit.signature[32:]
    tampered = replace(permit, signature=bad_sig)
    result = executor.execute(tampered, "demo.read_status", TENANT, AGENT)
    assert result.executed is False
    assert result.reason_code == "INVALID_SIGNATURE"


# ---------------------------------------------------------------------------
# Scenario 12: Receipt redaction — sensitive values never appear in output
# ---------------------------------------------------------------------------


def test_receipt_does_not_contain_payload_values(policy: DemoPolicy, executor: DemoExecutor) -> None:
    permit = _fresh_permit(policy)
    result = executor.execute(permit, "demo.read_status", TENANT, AGENT)
    result_str = json.dumps(
        {
            "executed": result.executed,
            "decision": result.decision,
            "reason_code": result.reason_code,
            "permit_id": result.permit_id,
            "action_digest": result.action_digest,
        }
    )
    assert TENANT not in result_str
    assert AGENT not in result_str
    # Raw signature bytes must never appear
    assert permit.signature.hex() not in result_str


def test_permit_payload_is_deterministic(policy: DemoPolicy) -> None:
    permit = _fresh_permit(policy)
    assert _permit_payload(permit) == _permit_payload(permit)


def test_action_digest_is_stable_across_calls() -> None:
    assert _action_digest("demo.read_status") == _action_digest("demo.read_status")
    assert _action_digest("demo.read_status") != _action_digest("demo.rotate_demo_key")
