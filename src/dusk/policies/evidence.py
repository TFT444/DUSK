"""Fail-closed evidence classification for policy enforcement."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum


class EvidenceState(StrEnum):
    """Trust state attached to a policy context domain."""

    CONFIRMED = "CONFIRMED"  # pragma: no mutate
    UNKNOWN = "UNKNOWN"  # pragma: no mutate
    STALE = "STALE"  # pragma: no mutate
    CONFLICTED = "CONFLICTED"  # pragma: no mutate
    NOT_APPLICABLE = "NOT_APPLICABLE"  # pragma: no mutate


_SAFE_EVIDENCE = frozenset(
    {
        EvidenceState.CONFIRMED,
        EvidenceState.NOT_APPLICABLE,
    }
)


def classify_evidence(context: Mapping[str, object]) -> tuple[bool, bool]:
    """Return ``(consequential, degraded)`` for an evaluation context.

    A present action is consequential unless it is explicitly classified with
    the boolean value ``False``. For consequential actions, missing, malformed,
    stale, conflicted, or unknown evidence is degraded and must fail closed.
    """
    action = context.get("action")
    consequential = isinstance(action, Mapping) and action.get("consequential") is not False
    degraded = any(
        _domain_evidence(value, strict=consequential) not in _SAFE_EVIDENCE
        for value in context.values()
        if isinstance(value, Mapping)
    )
    return consequential, degraded


def _domain_evidence(domain: Mapping[str, object], *, strict: bool) -> EvidenceState:
    raw = domain.get("_evidence")
    if raw is None:
        return EvidenceState.UNKNOWN if strict else EvidenceState.CONFIRMED
    if isinstance(raw, EvidenceState):
        return raw
    if not isinstance(raw, str):
        return EvidenceState.UNKNOWN
    try:
        return EvidenceState(raw)
    except ValueError:
        return EvidenceState.UNKNOWN
