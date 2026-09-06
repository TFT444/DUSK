"""Tests for DuskBedrockClient -- the model-call wrapper."""

from __future__ import annotations

import sys
import types
from typing import Any
from unittest.mock import MagicMock

import pytest
from bedrock_client import (
    DuskBedrockClient,
    DuskBlockedError,
    MantleClient,
    build_provider_client,
    extract_function_call,
    propose_tool_call,
    tool_config_to_openai_tools,
)


def test_converse_forwards_to_underlying_client():
    mock_client = MagicMock()
    mock_client.converse.return_value = {
        "output": {"message": {"content": [{"text": "a normal reply"}]}}
    }
    wrapper = DuskBedrockClient(client=mock_client)

    result = wrapper.converse(messages=[{"role": "user", "content": [{"text": "hi"}]}])

    assert result["output"]["message"]["content"][0]["text"] == "a normal reply"
    mock_client.converse.assert_called_once()
    _, kwargs = mock_client.converse.call_args
    assert kwargs["modelId"] == wrapper.model_id
    assert kwargs["messages"] == [{"role": "user", "content": [{"text": "hi"}]}]


def test_dusk_blocked_request_carries_full_payload():
    verdict: dict[str, Any] = {
        "verdict": "BLOCK",
        "score": 0.93,
        "reasons": ["out of baseline", "privileged term introduced"],
    }

    with pytest.raises(DuskBlockedError) as exc_info:
        raise DuskBlockedError(verdict)

    assert exc_info.value.verdict == verdict
    assert "out of baseline" in str(exc_info.value)


# --- Provider dispatch -----------------------------------------------------


def test_build_provider_client_runtime_returns_bedrock_client(monkeypatch):
    """provider='runtime' wraps a real boto3 client in DuskBedrockClient."""
    sentinel = object()
    monkeypatch.setattr("bedrock_client.build_real_client", lambda region: sentinel)
    client = build_provider_client(region="eu-west-2", model_id="anything", provider="runtime")
    assert isinstance(client, DuskBedrockClient)
    assert client.client is sentinel


def test_build_provider_client_unknown_raises():
    """An unrecognised provider string is rejected loudly."""
    with pytest.raises(ValueError, match="Unknown provider"):
        build_provider_client(region="eu-west-2", model_id="m", provider="nope")


def test_build_provider_client_mantle_calls_build_mantle_client(monkeypatch):
    """provider='mantle' delegates to build_mantle_client."""
    captured: dict[str, Any] = {}

    def _fake_build_mantle_client(region: str, model_id: str):
        captured["region"] = region
        captured["model_id"] = model_id
        return "mantle-client"

    monkeypatch.setattr("bedrock_client.build_mantle_client", _fake_build_mantle_client)
    result = build_provider_client(
        region="eu-west-2", model_id="moonshotai.kimi-k2.5", provider="mantle"
    )
    assert result == "mantle-client"
    assert captured == {"region": "eu-west-2", "model_id": "moonshotai.kimi-k2.5"}


# --- Mantle client construction --------------------------------------------


def _install_fake_token_and_openai(monkeypatch, token="secret-bearer-token"):
    """Stub aws_bedrock_token_generator and openai as importable modules.

    Returns the recording dict the fake OpenAI captures its kwargs into.
    All constructor keyword arguments (including timeout and max_retries)
    are stored so tests can assert on the exact bounded configuration.
    """
    captured: dict[str, Any] = {}

    token_mod = types.ModuleType("aws_bedrock_token_generator")

    def _provide_token(region: str):
        captured["token_region"] = region
        return token

    token_mod.provide_token = _provide_token  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aws_bedrock_token_generator", token_mod)

    openai_mod = types.ModuleType("openai")

    class _FakeOpenAI:
        def __init__(self, *, base_url: str, api_key: str, **kwargs: Any):
            captured["base_url"] = base_url
            captured["api_key"] = api_key
            captured.update(kwargs)

    openai_mod.OpenAI = _FakeOpenAI  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "openai", openai_mod)

    return captured


def test_build_mantle_client_uses_london_mantle_endpoint(monkeypatch):
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert captured["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_build_mantle_client_uses_kimi_model_id(monkeypatch):
    _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    client = build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert client.model_id == "moonshotai.kimi-k2.5"


def test_build_mantle_client_raises_if_token_is_falsy(monkeypatch):
    _install_fake_token_and_openai(monkeypatch, token="")
    from bedrock_client import build_mantle_client

    with pytest.raises(RuntimeError):
        build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")


def test_mantle_client_does_not_echo_token_in_repr(monkeypatch):
    _install_fake_token_and_openai(monkeypatch, token="super-secret-token-xyz")
    from bedrock_client import build_mantle_client

    client = build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert "super-secret-token-xyz" not in repr(client)
    assert "super-secret-token-xyz" not in str(client)


def test_build_mantle_client_gives_kimi_a_bounded_extended_timeout(monkeypatch):
    """Kimi gets bounded headroom for slower Bedrock inference."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert captured.get("timeout") == 180


def test_build_mantle_client_allows_one_kimi_transient_retry(monkeypatch):
    """Kimi gets one bounded SDK retry for transport and provider failures."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert captured.get("max_retries") == 1


@pytest.mark.parametrize(
    "model_id",
    ["zai.glm-5", "qwen.qwen3-32b", "openai.gpt-oss-120b"],
)
def test_build_mantle_client_keeps_default_bounds_for_other_models(monkeypatch, model_id):
    """Models without timeout evidence retain the stricter existing bounds."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id=model_id)
    assert captured.get("timeout") == 120
    assert captured.get("max_retries") == 0


def test_mantle_client_sends_max_completion_tokens():
    """Every chat_completions_create call must include max_completion_tokens=512."""
    openai_client = MagicMock()
    client = MantleClient(openai_client, "zai.glm-5")

    client.chat_completions_create(
        messages=[{"role": "user", "content": "check route table"}],
        tools=[{"type": "function", "function": {"name": "update_route_table"}}],
    )

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["max_completion_tokens"] == 4096


@pytest.mark.parametrize(
    "model_id",
    [
        "moonshotai.kimi-k2.5",
        "zai.glm-5",
        "qwen.qwen3-32b",
        "openai.gpt-oss-120b",
    ],
)
def test_mantle_client_keeps_exact_model_id_in_outgoing_request(model_id):
    openai_client = MagicMock()
    client = MantleClient(openai_client, model_id)

    client.chat_completions_create(
        messages=[{"role": "user", "content": "check route table"}],
        tools=[{"type": "function", "function": {"name": "update_route_table"}}],
    )

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["model"] == model_id


def test_mantle_client_retries_once_on_token_length_truncation():
    """When finish_reason='length' and no tool calls, chat_completions_create retries once.

    Reasoning models sometimes enter an extended chain-of-thought mode that exhausts
    max_completion_tokens before the tool call JSON is written. The retry gives the
    model a second chance at its short-mode reasoning path.
    """
    openai_client = MagicMock()

    truncated = MagicMock()
    truncated.choices = [MagicMock(finish_reason="length", message=MagicMock(tool_calls=None))]

    success = MagicMock()
    tc = MagicMock()
    tc.id = "call_1"
    tc.function = MagicMock(name="update_firewall_rule", arguments='{"target": "fw-1"}')
    success.choices = [MagicMock(finish_reason="tool_calls", message=MagicMock(tool_calls=[tc]))]

    openai_client.chat.completions.create.side_effect = [truncated, success]
    client = MantleClient(openai_client, "qwen.qwen3-32b")

    result = client.chat_completions_create(
        messages=[{"role": "user", "content": "test"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    assert openai_client.chat.completions.create.call_count == 2
    assert result is success


def test_mantle_client_does_not_retry_when_length_but_no_tool_required():
    """No retry for finish_reason='length' when require_tool_call is False."""
    openai_client = MagicMock()

    truncated = MagicMock()
    truncated.choices = [MagicMock(finish_reason="length", message=MagicMock(tool_calls=None))]
    openai_client.chat.completions.create.return_value = truncated

    client = MantleClient(openai_client, "qwen.qwen3-32b")
    client.chat_completions_create(
        messages=[{"role": "user", "content": "test"}],
        tools=[],
        require_tool_call=False,
    )

    assert openai_client.chat.completions.create.call_count == 1


# --- Endpoint routing ---------------------------------------------------------


def test_build_mantle_client_uses_v1_endpoint_for_kimi(monkeypatch):
    """moonshotai.kimi-k2.5 must use the standard /v1 Mantle endpoint."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert captured["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_build_mantle_client_uses_v1_endpoint_for_glm5(monkeypatch):
    """zai.glm-5 must use the standard /v1 Mantle endpoint."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="zai.glm-5")
    assert captured["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_build_mantle_client_uses_v1_endpoint_for_qwen3_32b(monkeypatch):
    """qwen.qwen3-32b must use the standard /v1 Mantle endpoint."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="qwen.qwen3-32b")
    assert captured["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_build_mantle_client_uses_v1_endpoint_for_gpt_oss_120b(monkeypatch):
    """openai.gpt-oss-120b must use the authenticated standard Mantle endpoint."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="openai.gpt-oss-120b")
    assert captured["base_url"] == "https://bedrock-mantle.eu-west-2.api.aws/v1"


def test_build_mantle_client_qwen_does_not_use_openai_v1_endpoint(monkeypatch):
    """Qwen must not be routed to the /openai/v1 endpoint."""
    captured = _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    build_mantle_client(region="eu-west-2", model_id="qwen.qwen3-32b")
    assert "/openai/" not in captured["base_url"]


def test_build_mantle_client_raises_for_unknown_model_id(monkeypatch):
    """build_mantle_client must reject model IDs not in the approved allowlist."""
    _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    with pytest.raises(ValueError, match="Unsupported Bedrock Mantle model"):
        build_mantle_client(region="eu-west-2", model_id="unknown.model-xyz")


def test_build_mantle_client_raises_for_malformed_model_id(monkeypatch):
    """build_mantle_client must reject model IDs not in the approved allowlist."""
    _install_fake_token_and_openai(monkeypatch)
    from bedrock_client import build_mantle_client

    with pytest.raises(ValueError):
        build_mantle_client(region="eu-west-2", model_id="../../etc/passwd")


def test_build_mantle_client_token_absent_from_repr_and_exceptions(monkeypatch):
    """Bearer token must never appear in repr or in exception messages."""
    _install_fake_token_and_openai(monkeypatch, token="secret-bearer-XYZXYZ")
    from bedrock_client import build_mantle_client

    client = build_mantle_client(region="eu-west-2", model_id="moonshotai.kimi-k2.5")
    assert "secret-bearer-XYZXYZ" not in repr(client)
    assert "secret-bearer-XYZXYZ" not in str(client)


def test_mantle_client_can_require_a_tool_call():
    openai_client = MagicMock()
    client = MantleClient(openai_client, "moonshotai.kimi-k2.5")

    client.chat_completions_create(
        messages=[{"role": "user", "content": "update firewall"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["tool_choice"] == "required"
    assert request["temperature"] == 0


def test_gpt_oss_mantle_client_selects_the_only_exposed_function():
    openai_client = MagicMock()
    client = MantleClient(openai_client, "openai.gpt-oss-120b")

    client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate firewall change"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["tool_choice"] == {
        "type": "function",
        "function": {"name": "update_firewall_rule"},
    }


def test_gpt_oss_mantle_client_requires_exactly_one_function_to_select():
    openai_client = MagicMock()
    client = MantleClient(openai_client, "openai.gpt-oss-120b")

    client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate one change"}],
        tools=[
            {"type": "function", "function": {"name": "update_firewall_rule"}},
            {"type": "function", "function": {"name": "update_route_table"}},
        ],
        require_tool_call=True,
    )

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["tool_choice"] == "required"


def test_gpt_oss_retries_once_with_gate_correction_after_no_tool_call():
    openai_client = MagicMock()
    no_tool = {"choices": [{"finish_reason": "stop", "message": {"content": "cannot assist"}}]}
    tool_call = _openai_response_with_tool_call()
    openai_client.chat.completions.create.side_effect = [no_tool, tool_call]
    client = MantleClient(openai_client, "openai.gpt-oss-120b")

    result = client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate firewall change"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    assert result is tool_call
    assert openai_client.chat.completions.create.call_count == 2
    retry_messages = openai_client.chat.completions.create.call_args.kwargs["messages"]
    assert retry_messages[-1]["role"] == "user"
    assert "before DUSK Gate could inspect" in retry_messages[-1]["content"]


def test_gpt_oss_token_limit_uses_one_corrective_retry_total():
    openai_client = MagicMock()
    truncated = {
        "choices": [{"finish_reason": "length", "message": {"content": None, "tool_calls": None}}]
    }
    tool_call = _openai_response_with_tool_call()
    openai_client.chat.completions.create.side_effect = [truncated, tool_call]
    client = MantleClient(openai_client, "openai.gpt-oss-120b")

    result = client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate firewall change"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    assert result is tool_call
    assert openai_client.chat.completions.create.call_count == 2
    retry_messages = openai_client.chat.completions.create.call_args.kwargs["messages"]
    assert "before DUSK Gate could inspect" in retry_messages[-1]["content"]


def test_gpt_oss_does_not_correct_when_first_response_has_tool_call():
    openai_client = MagicMock()
    tool_call = _openai_response_with_tool_call()
    openai_client.chat.completions.create.return_value = tool_call
    client = MantleClient(openai_client, "openai.gpt-oss-120b")

    result = client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate firewall change"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    assert result is tool_call
    assert openai_client.chat.completions.create.call_count == 1


def test_other_mantle_models_do_not_use_gpt_oss_corrective_retry():
    openai_client = MagicMock()
    no_tool = {"choices": [{"finish_reason": "stop", "message": {"content": "no tool"}}]}
    openai_client.chat.completions.create.return_value = no_tool
    client = MantleClient(openai_client, "qwen.qwen3-32b")

    result = client.chat_completions_create(
        messages=[{"role": "user", "content": "simulate firewall change"}],
        tools=[{"type": "function", "function": {"name": "update_firewall_rule"}}],
        require_tool_call=True,
    )

    assert result is no_tool
    assert openai_client.chat.completions.create.call_count == 1


def test_mantle_client_uses_profile_token_limit(monkeypatch):
    from models.registry import ModelProfile

    profile = ModelProfile(
        "Test model",
        "test-model",
        "test.model",
        max_completion_tokens=1234,
    )
    openai_client = MagicMock()
    client = MantleClient(openai_client, profile)

    client.chat_completions_create(messages=[], tools=[])

    request = openai_client.chat.completions.create.call_args.kwargs
    assert request["max_completion_tokens"] == 1234


# --- extract_function_call -------------------------------------------------


def _openai_response_with_tool_call() -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "tool_calls": [
                        {
                            "id": "call_abc123",
                            "function": {
                                "name": "update_route_table",
                                "arguments": '{"target": "rt-1"}',
                            },
                        }
                    ]
                }
            }
        ]
    }


def test_extract_function_call_returns_none_for_no_tool_calls():
    response = {"choices": [{"message": {"content": "just text"}}]}
    assert extract_function_call(response) is None


def test_extract_function_call_returns_first_tool_call():
    fc = extract_function_call(_openai_response_with_tool_call())
    assert fc is not None
    assert fc["id"] == "call_abc123"
    assert fc["name"] == "update_route_table"
    assert fc["arguments_json"] == '{"target": "rt-1"}'


def test_extract_function_call_handles_missing_choices():
    assert extract_function_call({}) is None
    assert extract_function_call({"choices": []}) is None


def _bedrock_tool_config() -> dict[str, Any]:
    return {
        "tools": [
            {
                "toolSpec": {
                    "name": "update_firewall_rule",
                    "description": "Update a firewall rule.",
                    "inputSchema": {
                        "json": {
                            "type": "object",
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"],
                        }
                    },
                }
            }
        ]
    }


def test_tool_config_to_openai_tools_preserves_schema():
    tools = tool_config_to_openai_tools(_bedrock_tool_config())
    assert tools == [
        {
            "type": "function",
            "function": {
                "name": "update_firewall_rule",
                "description": "Update a firewall rule.",
                "parameters": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                    "required": ["target"],
                },
            },
        }
    ]


def test_propose_tool_call_uses_mantle_when_selected(monkeypatch):
    response = _openai_response_with_tool_call()
    mantle_client = MagicMock()
    mantle_client.chat_completions_create.return_value = response
    monkeypatch.setattr("bedrock_client.build_mantle_client", lambda **kwargs: mantle_client)

    provider, tool_call = propose_tool_call(
        provider="mantle",
        region="eu-west-2",
        model_id="moonshotai.kimi-k2.5",
        prompt_text="update the route",
        tool_config=_bedrock_tool_config(),
    )

    assert provider == "mantle"
    assert tool_call == {
        "id": "call_abc123",
        "name": "update_route_table",
        "arguments_json": '{"target": "rt-1"}',
    }
    mantle_client.chat_completions_create.assert_called_once()
    assert mantle_client.chat_completions_create.call_args.kwargs["require_tool_call"] is True


def test_propose_tool_call_gpt_oss_uses_authorized_simulation_context(monkeypatch):
    response = _openai_response_with_tool_call()
    mantle_client = MagicMock()
    mantle_client.chat_completions_create.return_value = response
    monkeypatch.setattr("bedrock_client.build_mantle_client", lambda **kwargs: mantle_client)

    propose_tool_call(
        provider="mantle",
        region="eu-west-2",
        model_id="openai.gpt-oss-120b",
        prompt_text="simulate the requested firewall action",
        tool_config=_bedrock_tool_config(),
    )

    messages = mantle_client.chat_completions_create.call_args.kwargs["messages"]
    assert messages[0]["role"] == "system"
    assert "authorized security validation simulation" in messages[0]["content"]
    assert "DUSK Gate" in messages[0]["content"]
    assert messages[1] == {
        "role": "user",
        "content": "simulate the requested firewall action",
    }


def test_propose_tool_call_keeps_kimi_user_only_message_contract(monkeypatch):
    response = _openai_response_with_tool_call()
    mantle_client = MagicMock()
    mantle_client.chat_completions_create.return_value = response
    monkeypatch.setattr("bedrock_client.build_mantle_client", lambda **kwargs: mantle_client)

    propose_tool_call(
        provider="mantle",
        region="eu-west-2",
        model_id="moonshotai.kimi-k2.5",
        prompt_text="update the route",
        tool_config=_bedrock_tool_config(),
    )

    assert mantle_client.chat_completions_create.call_args.kwargs["messages"] == [
        {"role": "user", "content": "update the route"}
    ]


def test_propose_tool_call_keeps_runtime_converse_path(monkeypatch):
    runtime_client = MagicMock()
    runtime_client.converse.return_value = {
        "output": {
            "message": {
                "content": [
                    {
                        "toolUse": {
                            "toolUseId": "runtime-1",
                            "name": "update_firewall_rule",
                            "input": {"target": "fw-1"},
                        }
                    }
                ]
            }
        }
    }
    monkeypatch.setattr("bedrock_client.build_real_client", lambda region: runtime_client)

    provider, tool_call = propose_tool_call(
        provider="runtime",
        region="us-east-1",
        model_id="claude",
        prompt_text="update firewall",
        tool_config=_bedrock_tool_config(),
    )

    assert provider == "runtime"
    assert tool_call["name"] == "update_firewall_rule"
    runtime_client.converse.assert_called_once_with(
        modelId="claude",
        messages=[{"role": "user", "content": [{"text": "update firewall"}]}],
        toolConfig=_bedrock_tool_config(),
    )
