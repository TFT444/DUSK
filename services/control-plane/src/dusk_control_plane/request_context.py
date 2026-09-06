"""Request-scoped correlation state."""

from __future__ import annotations

from contextvars import ContextVar, Token
from uuid import uuid4

_request_id: ContextVar[str | None] = ContextVar("dusk_request_id", default=None)
_decision_trace_id: ContextVar[str | None] = ContextVar("dusk_decision_trace_id", default=None)


def new_request_id() -> str:
    """Return a server-generated opaque request identifier."""
    return uuid4().hex


def set_request_id(value: str) -> Token[str | None]:
    """Set the current request identifier and return its reset token."""
    return _request_id.set(value)


def reset_request_id(token: Token[str | None]) -> None:
    """Restore the previous request context."""
    _request_id.reset(token)


def get_request_id() -> str:
    """Return the active identifier or create a safe fallback for error handling."""
    value = _request_id.get()
    return value if value is not None else new_request_id()


def set_decision_trace_id(value: str | None) -> Token[str | None]:
    return _decision_trace_id.set(value)


def reset_decision_trace_id(token: Token[str | None]) -> None:
    _decision_trace_id.reset(token)


def get_decision_trace_id() -> str | None:
    return _decision_trace_id.get()
