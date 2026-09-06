"""Load, validate, and evaluate deterministic agent-action policies."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from importlib.resources import files
from pathlib import Path

import yaml

from dusk.policies.evidence import EvidenceState as EvidenceState
from dusk.policies.evidence import classify_evidence

_SEVERITIES = {"low", "medium", "high", "critical"}
_STATUSES = {"proposed", "planned", "implemented", "validated", "enforced"}
_OPERATORS = {
    "equals",
    "in",
    "contains",
    "contains_any",
    "exists",
    "not_equals",
    "not_equals_or_missing",
    "not_true",
    "greater_than",
    "greater_than_or_missing",
    "less_than",
    "less_than_or_missing",
}
_MISSING = object()
_RULE_FIELDS = {
    "id",
    "version",
    "title",
    "category",
    "severity",
    "decision",
    "status",
    "owner",
    "rationale",
    "frameworks",
    "match",
    "prerequisites",
    "tests",
}

# Top-level domain keys permitted in a policy context (issue #144).
# Unknown keys are rejected at the enforcement boundary to prevent
# callers from inadvertently smuggling credential-shaped data through
# the evaluator or relying on undefined field semantics.
_CONTEXT_DOMAINS: frozenset[str] = frozenset(
    {
        "action",
        "identity",
        "tenant",
        "session",
        "objective",
        "delegation",
        "tool",
        "resource",
        "data",
        "destination",
        "permit",
        "approval",
        "execution",
        "cloud",
        "kubernetes",
        "infrastructure",
    }
)


class Decision(IntEnum):
    """Policy result ordered by enforcement priority."""

    ALLOW = 0
    REQUIRE_APPROVAL = 1
    DENY = 2


@dataclass(frozen=True)
class Condition:
    """One field comparison."""

    field: str
    operator: str
    value: object = None


@dataclass(frozen=True)
class Rule:
    """One validated deterministic policy rule."""

    id: str
    version: str
    title: str
    category: str
    severity: str
    decision: Decision
    status: str
    owner: str
    rationale: str
    frameworks: tuple[str, ...]
    conditions: tuple[Condition, ...]
    prerequisites: tuple[str, ...]
    tests: tuple[str, ...]


@dataclass(frozen=True)
class PolicyResult:
    """Aggregate policy decision and matched rules.

    Attributes:
        decision:          The highest-priority decision across matched rules.
        policy_version:    Semantic version of the pack that produced this result.
        matched_rules:     Enforced rules whose conditions were satisfied.
        evidence_degraded: True when at least one context domain carried
                           UNKNOWN, STALE, or CONFLICTED evidence.  Callers
                           must record this in audit evidence.
    """

    decision: Decision
    policy_version: str
    matched_rules: tuple[Rule, ...]
    evidence_degraded: bool = field(default=False)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable audit record.

        Only rule metadata is included.  Context field values are never
        echoed to prevent credential or sensitive payload leakage.
        """
        return {
            "decision": self.decision.name,
            "policy_version": self.policy_version,
            "evidence_degraded": self.evidence_degraded,
            "matched_rules": [
                {
                    "id": rule.id,
                    "version": rule.version,
                    "title": rule.title,
                    "owner": rule.owner,
                    "severity": rule.severity,
                    "frameworks": list(rule.frameworks),
                    "reason": rule.rationale,
                }
                for rule in self.matched_rules
            ],
        }


@dataclass(frozen=True)
class PolicyPack:
    """One immutable, validated rule pack."""

    name: str
    version: str
    default_decision: Decision
    rules: tuple[Rule, ...]

    def evaluate(self, context: Mapping[str, object]) -> PolicyResult:
        """Evaluate ``context`` against all enforced rules.

        Raises:
            ValueError: if ``context`` contains keys outside
                ``_CONTEXT_DOMAINS``.
        """
        _validate_context_domains(context)

        matched = tuple(
            rule
            for rule in self.rules
            if rule.status == "enforced" and _matches(rule.conditions, context)
        )
        decision = max((rule.decision for rule in matched), default=self.default_decision)

        consequential, degraded = classify_evidence(context)
        if degraded and consequential:
            decision = Decision.DENY

        return PolicyResult(
            decision=decision,
            policy_version=self.version,
            matched_rules=matched,
            evidence_degraded=degraded,
        )


def load_policy_pack(path: Path) -> PolicyPack:
    """Load and strictly validate a YAML policy pack."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return _load_mapping(raw)


def load_enterprise_pack() -> PolicyPack:
    """Load the bundled enterprise-v1 policy pack."""
    resource = files("dusk.policies").joinpath("enterprise-v1.yaml")
    with resource.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle)
    return _load_mapping(raw)


# ---------------------------------------------------------------------------
# Internal: context validation
# ---------------------------------------------------------------------------


def _validate_context_domains(context: Mapping[str, object]) -> None:
    unknown = set(context.keys()) - _CONTEXT_DOMAINS
    if unknown:
        raise ValueError(
            f"unknown context domain(s): {sorted(unknown)}; "
            f"permitted domains: {sorted(_CONTEXT_DOMAINS)}"
        )


# ---------------------------------------------------------------------------
# Internal: pack and rule loading
# ---------------------------------------------------------------------------


def _load_mapping(raw: object) -> PolicyPack:
    if not isinstance(raw, dict):
        raise ValueError("policy pack must be a mapping")
    if set(raw) != {"name", "version", "default_decision", "rules"}:
        raise ValueError("policy pack has missing or unsupported fields")
    raw_rules = raw["rules"]
    if not isinstance(raw_rules, list) or not raw_rules:
        raise ValueError("policy pack rules must be a non-empty list")
    rules = tuple(_load_rule(item) for item in raw_rules)
    ids = [rule.id for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("policy rule IDs must be unique")
    return PolicyPack(
        name=_required_text(raw, "name"),
        version=_required_text(raw, "version"),
        default_decision=_decision(raw["default_decision"]),
        rules=rules,
    )


def _load_rule(raw: object) -> Rule:
    if not isinstance(raw, dict) or set(raw) != _RULE_FIELDS:
        raise ValueError("rule has missing or unsupported fields")
    severity = _required_text(raw, "severity")
    status = _required_text(raw, "status")
    if severity not in _SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    if status not in _STATUSES:
        raise ValueError(f"invalid status: {status!r}; valid statuses: {sorted(_STATUSES)}")
    conditions = _conditions(raw["match"])
    prerequisites = _text_tuple(raw["prerequisites"], "prerequisites")
    tests = _text_tuple(raw["tests"], "tests")
    _validate_rule_lifecycle(status, conditions, prerequisites, tests)
    rule_id = _required_text(raw, "id")
    version = _required_text(raw, "version")
    if re.fullmatch(r"DUSK-[A-Z]+-[0-9]{3}", rule_id) is None:
        raise ValueError(f"invalid rule ID: {rule_id}")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        raise ValueError(f"invalid rule version: {version}")
    return Rule(
        id=rule_id,
        version=version,
        title=_required_text(raw, "title"),
        category=_required_text(raw, "category"),
        severity=severity,
        decision=_decision(raw["decision"]),
        status=status,
        owner=_required_text(raw, "owner"),
        rationale=_required_text(raw, "rationale"),
        frameworks=_text_tuple(raw["frameworks"], "frameworks"),
        conditions=conditions,
        prerequisites=prerequisites,
        tests=tests,
    )


def _validate_rule_lifecycle(
    status: str,
    conditions: tuple[Condition, ...],
    prerequisites: tuple[str, ...],
    tests: tuple[str, ...],
) -> None:
    """Enforce the per-lifecycle requirements on rule completeness.

    Lifecycle progression and what each status requires:
        proposed:    No requirements; rule is being scoped.
        planned:     Prerequisites must be listed (telemetry not yet available).
        implemented: Conditions required; tests not yet mandatory.
        validated:   Conditions and tests both required; ready for enforcement.
        enforced:    Conditions and tests required; active at runtime.
    """
    if status == "enforced" and (not conditions or not tests):
        raise ValueError("enforced rules require conditions and tests")
    if status == "validated" and (not conditions or not tests):
        raise ValueError("validated rules require conditions and tests")
    if status == "implemented" and not conditions:
        raise ValueError("implemented rules require conditions")
    if status == "planned" and not prerequisites:
        raise ValueError("planned rules require prerequisites")
    # proposed: no field requirements


# ---------------------------------------------------------------------------
# Internal: condition matching
# ---------------------------------------------------------------------------


def _conditions(raw: object) -> tuple[Condition, ...]:
    if not isinstance(raw, list):
        raise ValueError("match must be a list")
    result: list[Condition] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"field", "operator", "value"}:
            raise ValueError("condition has missing or unsupported fields")
        operator = _required_text(item, "operator")
        if operator not in _OPERATORS:
            raise ValueError(f"invalid condition operator: {operator}")
        result.append(Condition(_required_text(item, "field"), operator, item["value"]))
    return tuple(result)


def _matches(conditions: tuple[Condition, ...], context: Mapping[str, object]) -> bool:
    return bool(conditions) and all(
        _compare(_resolve(context, item.field), item, context) for item in conditions
    )


def _resolve(context: Mapping[str, object], path: str) -> object:
    value: object = context
    for part in path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _compare_numeric(actual: object, expected: object, op: str) -> bool:
    """Numeric greater_than / less_than comparison; missing or non-numeric values do not fire."""
    if actual is _MISSING:
        return False
    try:
        a, e = float(actual), float(expected)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return a > e if op == "greater_than" else a < e


def _compare_numeric_or_missing(actual: object, expected: object, op: str) -> bool:
    """Fail closed when either required numeric operand is absent or malformed."""
    if actual is _MISSING or expected is _MISSING:
        return True
    try:
        a, e = float(actual), float(expected)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return True
    return a > e if op == "greater_than_or_missing" else a < e


def _compare_numeric_condition(actual: object, expected: object, op: str) -> bool:
    if op.endswith("_or_missing"):
        return _compare_numeric_or_missing(actual, expected, op)
    return _compare_numeric(actual, expected, op)


def _compare_collection(actual: object, expected: object, op: str) -> bool:
    if not isinstance(actual, (str, list, tuple, set)):
        return False
    if op == "contains":
        return expected in actual
    return isinstance(expected, list) and any(value in actual for value in expected)


def _compare(actual: object, condition: Condition, context: Mapping[str, object]) -> bool:
    expected = condition.value
    if isinstance(expected, str) and expected.startswith("$"):
        expected = _resolve(context, expected[1:])
    if condition.operator == "exists":
        return (actual is not _MISSING) is bool(expected)
    if condition.operator == "equals":
        return actual == expected
    if condition.operator == "not_equals":
        return actual is not _MISSING and actual != expected
    if condition.operator == "not_equals_or_missing":
        return actual is _MISSING or expected is _MISSING or actual != expected
    if condition.operator == "not_true":
        return actual is not True
    if condition.operator in {"contains", "contains_any"}:
        return _compare_collection(actual, expected, condition.operator)
    if condition.operator == "in":
        return isinstance(expected, list) and actual in expected
    if condition.operator in {
        "greater_than",
        "less_than",
        "greater_than_or_missing",
        "less_than_or_missing",
    }:
        return _compare_numeric_condition(actual, expected, condition.operator)
    return False


def _decision(raw: object) -> Decision:
    if not isinstance(raw, str) or raw not in Decision.__members__:
        raise ValueError(f"invalid decision: {raw}")
    return Decision[raw]


def _required_text(raw: Mapping[str, object], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return value


def _text_tuple(raw: object, field: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or any(not isinstance(item, str) or not item for item in raw):
        raise ValueError(f"{field} must be a list of non-empty strings")
    return tuple(raw)
