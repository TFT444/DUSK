"""Decision-to-broker routing invariants."""

from __future__ import annotations

import pytest
from test_audit import _request, _response

from dusk_control_plane.audit import ProviderBrokerIntentResolver


@pytest.mark.parametrize("verdict", ["BLOCK", "WOULD-BLOCK"])
def test_refused_actions_never_create_enforcement_broker_intents(verdict: str) -> None:
    resolver = ProviderBrokerIntentResolver("provider-broker")
    response = _response().model_copy(update={"verdict": verdict})

    intent = resolver.resolve(_request(), response)

    assert intent.destination_kind == "WEBHOOK"
    assert intent.delivery_kind == "DECISION_RECORDED"
    assert intent.destination_key == "decision-events"


def test_allowed_action_uses_credential_holding_broker() -> None:
    resolver = ProviderBrokerIntentResolver("provider-broker")
    response = _response().model_copy(update={"verdict": "ALLOW"})

    intent = resolver.resolve(_request(), response)

    assert intent.destination_kind == "ENFORCEMENT_BROKER"
    assert intent.delivery_kind == "ACTION_EXECUTION"
    assert intent.destination_key == "provider-broker"


@pytest.mark.parametrize(
    "changes",
    [
        {"broker_destination_key": ""},
        {"event_destination_key": ""},
        {"max_attempts": 101},
    ],
)
def test_invalid_broker_intents_fail_configuration(changes: dict[str, object]) -> None:
    values: dict[str, object] = {"broker_destination_key": "provider-broker"}
    values.update(changes)
    with pytest.raises(ValueError):
        ProviderBrokerIntentResolver(**values)
