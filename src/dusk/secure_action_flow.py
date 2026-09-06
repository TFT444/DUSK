"""One fail-closed Cloudflare to DUSK protected-action workflow."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, TypeVar

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dusk.permits import PermitError, issue_permit
from dusk.policies import Decision, PolicyPack, PolicyResult, PolicyStage
from dusk.proxy import ExecutionBlockedError, RestrictedExecutionProxy

ResultT = TypeVar("ResultT")


class GatewayPort(Protocol):
    """The limited gateway operation needed by the protected-action flow."""

    def forward(
        self,
        payload: dict[str, object],
        *,
        action: dict[str, object],
        gate: Callable[[dict[str, object]], str],
    ) -> dict[str, object]:
        """Forward a model request through an approved gateway."""


@dataclass(frozen=True)
class ActionReceipt:
    """Redacted evidence for one protected action attempt."""

    trace_id: str
    action_digest: str
    policy_version: str
    decision: Decision
    matched_rule_ids: tuple[str, ...]
    gateway_status: str
    execution_status: str

    def to_dict(self) -> dict[str, object]:
        """Return only fixed metadata, never payload, target, or tool output."""
        return {
            "trace_id": self.trace_id,
            "action_digest": self.action_digest,
            "policy_version": self.policy_version,
            "decision": self.decision.name,
            "matched_rule_ids": list(self.matched_rule_ids),
            "gateway_status": self.gateway_status,
            "execution_status": self.execution_status,
        }


@dataclass(frozen=True)
class SecureActionFlowResult:
    """Gateway result, optional tool result, and a redacted receipt."""

    gateway_response: dict[str, object] | None
    tool_result: object | None
    receipt: ActionReceipt


class _PolicyBlockedError(Exception):
    def __init__(self, result: PolicyResult) -> None:
        self.result = result


@dataclass
class SecureActionFlow:
    """Join gateway delivery to DUSK authorization and restricted execution.

    The first policy evaluation is an authorization decision.  A signed permit
    is issued only after that result is ALLOW.  The execution-stage policy and
    cryptographic proxy verification run before the supplied tool executor.
    """

    gateway: GatewayPort
    policy: PolicyPack
    signing_key: Ed25519PrivateKey
    proxy: RestrictedExecutionProxy
    now: Callable[[], datetime]
    trace_id: Callable[[], str]

    def execute(
        self,
        *,
        payload: dict[str, object],
        action: dict[str, object],
        policy_context: Mapping[str, object],
        tenant_id: str,
        agent_id: str,
        executor: Callable[[dict[str, object]], ResultT],
    ) -> SecureActionFlowResult:
        """Run one consequential action through every required boundary."""
        trace_id = self.trace_id()
        digest = _action_digest(action)
        try:
            gateway_response = self.gateway.forward(payload, action=action, gate=lambda _: "ALLOW")
        except Exception:
            return SecureActionFlowResult(
                gateway_response=None,
                tool_result=None,
                receipt=self._receipt(
                    trace_id, digest, Decision.DENY, (), "FAILED_CLOSED", "NOT_EXECUTED"
                ),
            )

        try:
            authorization = self.policy.evaluate(
                _policy_context(policy_context, action, tenant_id, agent_id, "authorization"),
                stage=PolicyStage.AUTHORIZATION,
            )
        except Exception:
            return SecureActionFlowResult(
                gateway_response=gateway_response,
                tool_result=None,
                receipt=self._receipt(trace_id, digest, Decision.DENY, (), "FORWARDED", "BLOCKED"),
            )
        if authorization.decision is not Decision.ALLOW:
            return SecureActionFlowResult(
                gateway_response=gateway_response,
                tool_result=None,
                receipt=self._receipt(
                    trace_id,
                    digest,
                    authorization.decision,
                    _rule_ids(authorization),
                    "FORWARDED",
                    "BLOCKED",
                ),
            )

        issued_at = _aware_utc(self.now())
        permit = issue_permit(
            self.signing_key,
            tenant_id=tenant_id,
            agent_id=agent_id,
            action=action,
            policy_version=authorization.policy_version,
            now=issued_at,
        )
        execution_policy: PolicyResult | None = None

        def guarded_executor(value: dict[str, object]) -> ResultT:
            nonlocal execution_policy
            execution_policy = self.policy.evaluate(
                _policy_context(policy_context, value, tenant_id, agent_id, "execution"),
                stage=PolicyStage.EXECUTION,
            )
            if execution_policy.decision is not Decision.ALLOW:
                raise _PolicyBlockedError(execution_policy)
            return executor(value)

        try:
            tool_result = self.proxy.execute(
                permit,
                tenant_id=tenant_id,
                agent_id=agent_id,
                action=action,
                policy_version=authorization.policy_version,
                executor=guarded_executor,
                now=issued_at,
            )
        except _PolicyBlockedError as blocked:
            return SecureActionFlowResult(
                gateway_response=gateway_response,
                tool_result=None,
                receipt=self._receipt(
                    trace_id,
                    digest,
                    blocked.result.decision,
                    _rule_ids(blocked.result),
                    "FORWARDED",
                    "BLOCKED",
                ),
            )
        except (PermitError, ExecutionBlockedError):
            return SecureActionFlowResult(
                gateway_response=gateway_response,
                tool_result=None,
                receipt=self._receipt(trace_id, digest, Decision.DENY, (), "FORWARDED", "BLOCKED"),
            )
        return SecureActionFlowResult(
            gateway_response=gateway_response,
            tool_result=tool_result,
            receipt=self._receipt(
                trace_id,
                digest,
                execution_policy.decision if execution_policy is not None else Decision.DENY,
                _rule_ids(execution_policy) if execution_policy is not None else (),
                "FORWARDED",
                "EXECUTED",
            ),
        )

    def _receipt(
        self,
        trace_id: str,
        digest: str,
        decision: Decision,
        rule_ids: tuple[str, ...],
        gateway_status: str,
        execution_status: str,
    ) -> ActionReceipt:
        return ActionReceipt(
            trace_id=trace_id,
            action_digest=digest,
            policy_version=self.policy.version,
            decision=decision,
            matched_rule_ids=rule_ids,
            gateway_status=gateway_status,
            execution_status=execution_status,
        )


def _policy_context(
    source: Mapping[str, object],
    action: dict[str, object],
    tenant_id: str,
    agent_id: str,
    stage: str,
) -> dict[str, object]:
    context = copy.deepcopy(dict(source))
    context["action"] = {**_mapping(context.get("action")), **copy.deepcopy(action)}
    context["identity"] = {
        **_mapping(context.get("identity")),
        "tenant_id": tenant_id,
        "agent_id": agent_id,
    }
    context["execution"] = {
        **_mapping(context.get("execution")),
        "stage": stage,
        "via_broker": True,
    }
    context["permit"] = {
        **_mapping(context.get("permit")),
        "present": stage == "execution",
        "valid": stage == "execution",
        "expired": False,
        "replayed": False,
        "action_matches": True,
        "issuer_trusted": stage == "execution",
        "lifetime_exceeded": False,
        "scope": _action_digest(action),
        "action_scope": _action_digest(action),
    }
    return context


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, Mapping) else {}


def _action_digest(action: Mapping[str, object]) -> str:
    canonical = json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("clock must return a timezone-aware instant")
    return value.astimezone(UTC)


def _rule_ids(result: PolicyResult) -> tuple[str, ...]:
    return tuple(rule.id for rule in result.matched_rules)
