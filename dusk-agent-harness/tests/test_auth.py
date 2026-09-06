"""Direct boundary tests for fail-closed gate authentication."""

from __future__ import annotations

import pytest

from dusk.auth import gate_request_is_authorized


@pytest.mark.parametrize("value", [None, "", "false", "1", "yes", " truex "])
def test_missing_key_denies_without_explicit_anonymous_opt_in(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    if value is None:
        monkeypatch.delenv("DUSK_GATE_ALLOW_ANONYMOUS", raising=False)
    else:
        monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", value)
    assert gate_request_is_authorized("") is False


@pytest.mark.parametrize("value", ["true", "TRUE", " True "])
def test_missing_key_allows_only_explicit_true(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", value)
    assert gate_request_is_authorized("") is True


@pytest.mark.parametrize(
    "presented",
    ["", "secret", "bearer secret", "Bearer", "Bearer ", "Bearer wrong", "Basic secret"],
)
def test_configured_key_rejects_missing_or_incorrect_bearer_tokens(
    monkeypatch: pytest.MonkeyPatch, presented: str
) -> None:
    monkeypatch.setenv("DUSK_GATE_API_KEY", "secret")
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    assert gate_request_is_authorized(presented) is False


def test_configured_key_accepts_only_exact_bearer_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DUSK_GATE_API_KEY", "secret")
    assert gate_request_is_authorized("Bearer secret") is True
    assert gate_request_is_authorized("Bearer secret ") is False
