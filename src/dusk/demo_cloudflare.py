"""Narrowly scoped demo policy HTTP service for the Cloudflare edge demo.

Exposes three classes consumed by the Worker via loopback HTTP:
- HmacGuard  -- verifies HMAC-SHA-256 on every inbound request
- DemoPolicy -- evaluates demo actions and issues Ed25519 permits
- DemoExecutor -- independently verifies permits and runs fake execution

The HTTP server (DemoServer) wraps all three and binds to 127.0.0.1 only.
Never deploy or expose to external networks.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from dusk.policies import Decision, load_enterprise_pack

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_ALLOWED_ACTIONS: Final = frozenset({"demo.read_status", "demo.rotate_demo_key"})
_ALLOWED_SIGNALS: Final = frozenset({"normal", "prompt_injection"})
_PERMIT_TTL: Final = 60  # seconds a permit remains valid
_MAX_TIMESTAMP_SKEW: Final = 30  # seconds tolerated clock drift
_BODY_SIZE_LIMIT: Final = 4096  # bytes maximum request body

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Permit:
    """Ed25519-signed, action-bound, single-use authorization token."""

    permit_id: str
    action: str
    action_digest: str  # SHA-256 hex of the canonical action string
    tenant_id: str
    agent_id: str
    issued_at: int  # Unix timestamp
    expires_at: int  # Unix timestamp (issued_at + _PERMIT_TTL)
    signature: bytes  # Ed25519 signature over _permit_payload(self)


@dataclass(frozen=True)
class EvalResult:
    """Policy evaluation outcome from DemoPolicy.evaluate()."""

    decision: str  # "ALLOWED" or "BLOCKED"
    reason_code: str
    permit: Permit | None = None


@dataclass(frozen=True)
class ExecResult:
    """Execution outcome from DemoExecutor.execute()."""

    executed: bool
    decision: str  # "ALLOWED" or "BLOCKED"
    reason_code: str
    permit_id: str | None
    action_digest: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _action_digest(action: str) -> str:
    """Stable SHA-256 hex digest of a canonical action string."""
    return hashlib.sha256(action.encode()).hexdigest()


def _permit_payload(permit: Permit) -> bytes:
    """Deterministic bytes signed (and re-derived for verification) from a Permit."""
    payload = {
        "permit_id": permit.permit_id,
        "action": permit.action,
        "action_digest": permit.action_digest,
        "tenant_id": permit.tenant_id,
        "agent_id": permit.agent_id,
        "issued_at": permit.issued_at,
        "expires_at": permit.expires_at,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _issue_permit(
    action: str,
    tenant_id: str,
    agent_id: str,
    private_key: Ed25519PrivateKey,
) -> Permit:
    """Create and sign a new single-use permit for an allowed action."""
    now = int(time.time())
    unsigned = Permit(
        permit_id=secrets.token_hex(16),
        action=action,
        action_digest=_action_digest(action),
        tenant_id=tenant_id,
        agent_id=agent_id,
        issued_at=now,
        expires_at=now + _PERMIT_TTL,
        signature=b"",
    )
    payload = _permit_payload(unsigned)
    sig = private_key.sign(payload)
    return Permit(
        permit_id=unsigned.permit_id,
        action=unsigned.action,
        action_digest=unsigned.action_digest,
        tenant_id=unsigned.tenant_id,
        agent_id=unsigned.agent_id,
        issued_at=unsigned.issued_at,
        expires_at=unsigned.expires_at,
        signature=sig,
    )


def _build_policy_context(action: str, signal: str) -> dict[str, object]:
    """Map demo action and signal to a DUSK policy evaluation context."""
    return {
        "action": {
            "type": action,
            "category": "demo",
            "consequential": False,
        },
    }


# ---------------------------------------------------------------------------
# HmacGuard
# ---------------------------------------------------------------------------


@dataclass
class HmacGuard:
    """Verifies HMAC-SHA-256 on Worker-to-policy requests.

    Covers: method, path, timestamp, nonce, and raw body bytes.
    Rejects stale timestamps and replayed nonces.
    """

    secret: bytes
    _seen_nonces: set[str] = field(default_factory=set)

    def verify(
        self,
        method: str,
        path: str,
        timestamp: str,
        nonce: str,
        body: bytes,
        given: str,
    ) -> bool:
        """Return True only when the HMAC is valid, fresh, and the nonce is new."""
        try:
            ts = int(timestamp)
        except ValueError:
            return False

        if abs(time.time() - ts) > _MAX_TIMESTAMP_SKEW:
            return False

        if nonce in self._seen_nonces:
            return False

        msg = f"{method}\n{path}\n{timestamp}\n{nonce}\n".encode() + body
        expected = hmac.new(self.secret, msg, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected, given):
            return False

        self._seen_nonces.add(nonce)
        return True


# ---------------------------------------------------------------------------
# DemoPolicy
# ---------------------------------------------------------------------------


class DemoPolicy:
    """Evaluates demo actions and issues Ed25519 permits for allowed ones."""

    def __init__(self) -> None:
        self._pack = load_enterprise_pack()
        self._private_key = Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def evaluate(
        self,
        action: str,
        signal: str,
        tenant_id: str,
        agent_id: str,
    ) -> EvalResult:
        """Evaluate an action request and return a decision with an optional permit."""
        if action not in _ALLOWED_ACTIONS:
            return EvalResult("BLOCKED", "UNKNOWN_ACTION")

        if signal not in _ALLOWED_SIGNALS:
            return EvalResult("BLOCKED", "UNKNOWN_SIGNAL")

        if signal == "prompt_injection":
            return EvalResult("BLOCKED", "PROMPT_INJECTION_DETECTED")

        context = _build_policy_context(action, signal)
        result = self._pack.evaluate(context)

        if result.decision is not Decision.ALLOW:
            return EvalResult("BLOCKED", "POLICY_DENIED")

        permit = _issue_permit(action, tenant_id, agent_id, self._private_key)
        return EvalResult("ALLOWED", "POLICY_ALLOWED", permit)


# ---------------------------------------------------------------------------
# DemoExecutor
# ---------------------------------------------------------------------------


class DemoExecutor:
    """Restricted fake executor -- verifies permit independently before any execution.

    Only process-local state (a counter and a seen-permit set) is ever mutated.
    No real keys are accessed or rotated.
    """

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        self._public_key = public_key
        self._seen_permit_ids: set[str] = set()
        self._demo_counter: int = 0

    def execute(
        self,
        permit: Permit,
        action: str,
        tenant_id: str,
        agent_id: str,
    ) -> ExecResult:
        """Verify the permit and run a fake action if all checks pass."""
        now = int(time.time())

        if now >= permit.expires_at:
            return self._block("PERMIT_EXPIRED", permit)

        if permit.permit_id in self._seen_permit_ids:
            return self._block("PERMIT_REPLAYED", permit)

        expected_digest = _action_digest(action)
        if not hmac.compare_digest(expected_digest, permit.action_digest):
            return self._block("ACTION_MISMATCH", permit)

        if permit.tenant_id != tenant_id or permit.agent_id != agent_id:
            return self._block("IDENTITY_MISMATCH", permit)

        payload = _permit_payload(permit)
        try:
            self._public_key.verify(permit.signature, payload)
        except InvalidSignature:
            return self._block("INVALID_SIGNATURE", permit)

        self._seen_permit_ids.add(permit.permit_id)
        self._demo_counter += 1

        return ExecResult(True, "ALLOWED", "PERMIT_VALID", permit.permit_id, permit.action_digest)

    @staticmethod
    def _block(reason_code: str, permit: Permit) -> ExecResult:
        return ExecResult(False, "BLOCKED", reason_code, permit.permit_id, permit.action_digest)


# ---------------------------------------------------------------------------
# HTTP server (used when run as a service by the Worker)
# ---------------------------------------------------------------------------


class _DemoHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler for the demo policy service.

    Routes:
        GET  /healthz                        -- readiness probe (Worker only)
        POST /v1/demo/authorize-and-execute  -- full pipeline: policy + execution
    """

    guard: HmacGuard
    policy: DemoPolicy
    executor: DemoExecutor

    def log_message(self, fmt: str, *args: object) -> None:
        pass  # suppress default access log

    def _read_body(self) -> bytes | None:
        length = int(self.headers.get("Content-Length", 0))
        if length > _BODY_SIZE_LIMIT:
            self._send(413, {"error": "body too large"})
            return None
        return self.rfile.read(length)

    def _hmac_headers(self) -> tuple[str, str, str] | None:
        ts = self.headers.get("X-Timestamp", "")
        nonce = self.headers.get("X-Nonce", "")
        sig = self.headers.get("X-Hmac-Signature", "")
        if not (ts and nonce and sig):
            return None
        return ts, nonce, sig

    def _send(self, status: int, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path != "/healthz":
            self._send(404, {"error": "not found"})
            return
        self._send(200, {"status": "ok"})

    def do_POST(self) -> None:
        if self.path != "/v1/demo/authorize-and-execute":
            self._send(404, {"error": "not found"})
            return

        raw = self._read_body()
        if raw is None:
            return

        auth = self._hmac_headers()
        if auth is None or not self.guard.verify("POST", self.path, auth[0], auth[1], raw, auth[2]):
            self._send(401, {"error": "unauthorized"})
            return

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid json"})
            return

        self._handle_authorize_and_execute(payload)

    def _handle_authorize_and_execute(self, payload: dict[str, object]) -> None:
        action = payload.get("action", "")
        risk_signal = payload.get("risk_signal", "")
        tenant_id = payload.get("tenant_id", "")
        agent_id = payload.get("agent_id", "")

        if not isinstance(action, str) or not isinstance(risk_signal, str):
            self._send(400, {"error": "invalid fields"})
            return
        if not isinstance(tenant_id, str) or not isinstance(agent_id, str):
            self._send(400, {"error": "invalid fields"})
            return

        eval_result = self.policy.evaluate(action, risk_signal, tenant_id, agent_id)

        if eval_result.decision != "ALLOWED" or eval_result.permit is None:
            digest = _action_digest(action) if action in _ALLOWED_ACTIONS else ""
            self._send(
                200,
                {
                    "decision": "BLOCKED",
                    "reason_code": eval_result.reason_code,
                    "executed": False,
                    "permit_id": None,
                    "action_digest": digest,
                },
            )
            return

        exec_result = self.executor.execute(eval_result.permit, action, tenant_id, agent_id)

        self._send(
            200,
            {
                "decision": exec_result.decision,
                "reason_code": exec_result.reason_code,
                "executed": exec_result.executed,
                "permit_id": exec_result.permit_id,
                "action_digest": exec_result.action_digest,
            },
        )


class DemoServer:
    """Loopback-only HTTP service used by the Cloudflare Worker for local demos."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8787,
        hmac_secret: bytes = b"",
    ) -> None:
        if not hmac_secret:
            hmac_secret = secrets.token_bytes(32)

        guard = HmacGuard(secret=hmac_secret)
        policy = DemoPolicy()
        executor = DemoExecutor(policy.public_key)

        handler = type(
            "_BoundHandler",
            (_DemoHandler,),
            {"guard": guard, "policy": policy, "executor": executor},
        )
        self._server = HTTPServer((host, port), handler)

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._server.shutdown()
