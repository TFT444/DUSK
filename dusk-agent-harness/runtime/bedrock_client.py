"""Common interface for mock and real Bedrock Converse clients."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast

from models.registry import ModelProfile, get_model_profile


class DuskBlockedError(Exception):
    """Raised when the gate returns a non-ALLOW verdict for a proposed action.

    Carries the full decision payload (verdict, score, reasons, blast
    radius) so callers can inspect and surface why the action was stopped.
    """

    def __init__(self, verdict: dict[str, Any]) -> None:
        self.verdict = verdict
        reasons = ", ".join(verdict.get("reasons", [])) or "no reason given"
        super().__init__(f"blocked ({verdict.get('verdict')}): {reasons}")


class BedrockConverseClient(Protocol):
    """The subset of bedrock-runtime this wrapper depends on."""

    def converse(
        self,
        *,
        modelId: str,  # noqa: N803 -- matches boto3's actual converse() signature
        messages: list[dict[str, Any]],
    ) -> dict[str, Any]: ...


@dataclass
class DuskBedrockClient:
    """Wrap a Bedrock-compatible client behind one Converse interface."""

    client: BedrockConverseClient
    model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"

    def converse(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        """Call the model and return its raw response.

        Args:
            messages: Bedrock Converse-API-shaped message history.

        Returns:
            The raw Bedrock (or mock) response, including any proposed
            tool-call for extract_action() (see actions.py) to parse.
        """
        return self.client.converse(modelId=self.model_id, messages=messages)


def build_real_client(region: str = "us-east-1") -> BedrockConverseClient:
    """Return a real boto3 bedrock-runtime client.

    Requires AWS credentials to be configured in the environment. Only
    called when USE_REAL_BEDROCK=true; the default keyless path uses
    MockBedrock instead (see mock_bedrock.py, wired in by the harness).

    Args:
        region: AWS region for the client.
    """
    import boto3

    return boto3.client("bedrock-runtime", region_name=region)  # type: ignore[no-any-return]


class MantleClient:
    """Wrap an OpenAI-compatible client for the Bedrock Mantle endpoint.

    Mantle speaks the OpenAI Chat Completions protocol rather than the
    Bedrock Converse protocol, so this client is a peer of
    :class:`DuskBedrockClient` rather than a drop-in for it. The bearer
    token used for auth is held only inside the wrapped OpenAI client and
    is never stored as an attribute here, so it cannot leak through repr()
    or logging of this object.
    """

    def __init__(self, client: Any, model: str | ModelProfile) -> None:  # noqa: ANN401
        self._client = client
        self.profile = get_model_profile(model) if isinstance(model, str) else model
        self.model_id = self.profile.model_id

    def __repr__(self) -> str:
        # Deliberately omit the wrapped client (which holds the bearer
        # token) so the token can never surface in logs or tracebacks.
        return f"MantleClient(model_id={self.model_id!r})"

    def chat_completions_create(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        *,
        require_tool_call: bool = False,
    ) -> Any:  # noqa: ANN401 -- raw OpenAI SDK response object is dynamic
        """Call the model with OpenAI-format messages and tool definitions.

        Args:
            messages: OpenAI Chat Completions-shaped message history.
            tools: OpenAI function/tool definitions the model may call.

        Returns:
            The raw OpenAI-format response object. Pass it to
            :func:`extract_function_call` to pull the proposed tool call.
        """
        request: dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "tools": tools,
            "temperature": 0,
            "max_completion_tokens": self.profile.max_completion_tokens,
        }
        if require_tool_call:
            request["tool_choice"] = "required"
            if self.profile.force_single_tool_choice and len(tools) == 1:
                function_name = tools[0].get("function", {}).get("name")
                if function_name:
                    request["tool_choice"] = {
                        "type": "function",
                        "function": {"name": function_name},
                    }
        response = self._client.chat.completions.create(**request)
        if require_tool_call and self.profile.retry_on_token_limit and _hit_token_limit(response):
            response = self._client.chat.completions.create(**request)
        if (
            require_tool_call
            and self.profile.client_correction_prompt is not None
            and extract_function_call(response) is None
        ):
            corrective_request = {
                **request,
                "messages": [
                    *messages,
                    {"role": "user", "content": self.profile.client_correction_prompt},
                ],
            }
            response = self._client.chat.completions.create(**corrective_request)
        return response


def build_mantle_client(region: str, model_id: str) -> MantleClient:
    """Return a MantleClient authenticated with a short-term Bedrock token.

    The token generator is imported inside this function (not at module
    scope) so tests can stub the ``aws_bedrock_token_generator`` and
    ``openai`` modules without them being installed. The generated bearer
    token is passed straight into the OpenAI client and is never logged,
    printed, returned, or stored on the returned object.

    Args:
        region: AWS region hosting the Mantle endpoint (e.g. eu-west-2).
        model_id: Mantle model identifier (e.g. the Kimi K2.5 model ID).

    Raises:
        RuntimeError: If the token generator returns a falsy token.
    """
    profile = get_model_profile(model_id)

    from aws_bedrock_token_generator import provide_token
    from openai import OpenAI

    token = provide_token(region)
    if not token:
        # Fail closed: never construct a client with an empty credential.
        raise RuntimeError(
            "Bedrock token generator returned an empty token; "
            "cannot authenticate to the Mantle endpoint"
        )

    openai_client = OpenAI(
        base_url=_mantle_base_url(region, profile.model_id),
        api_key=token,
        timeout=profile.timeout_seconds,
        max_retries=profile.max_retries,
    )
    return MantleClient(client=openai_client, model=profile)


def extract_function_call(openai_response: Any) -> dict[str, Any] | None:  # noqa: ANN401
    """Pull the first tool call out of an OpenAI-format response, if any.

    Args:
        openai_response: A Chat Completions response (object or dict) that
            may carry ``choices[0].message.tool_calls``.

    Returns:
        A dict ``{"id", "name", "arguments_json"}`` for the first tool
        call, or ``None`` if the model proposed no tool call. The raw
        ``arguments_json`` string is returned unparsed; the adapter is
        responsible for validating it as JSON.
    """
    choices = _get(openai_response, "choices")
    if not choices:
        return None
    message = _get(choices[0], "message")
    if message is None:
        return None
    tool_calls = _get(message, "tool_calls")
    if not tool_calls:
        return None

    first = tool_calls[0]
    function = _get(first, "function")
    if function is None:
        return None
    return {
        "id": _get(first, "id"),
        "name": _get(function, "name"),
        "arguments_json": _get(function, "arguments"),
    }


def tool_config_to_openai_tools(tool_config: dict[str, Any]) -> list[dict[str, Any]]:
    """Translate Bedrock Converse tool specs into OpenAI function tools."""
    tools: list[dict[str, Any]] = []
    for entry in tool_config.get("tools", []):
        spec = entry.get("toolSpec", {})
        tools.append(
            {
                "type": "function",
                "function": {
                    "name": spec.get("name"),
                    "description": spec.get("description", ""),
                    "parameters": spec.get("inputSchema", {}).get("json", {}),
                },
            }
        )
    return tools


def propose_tool_call(
    *,
    provider: str,
    region: str,
    model_id: str,
    prompt_text: str,
    tool_config: dict[str, Any],
) -> tuple[str, dict[str, Any] | None]:
    """Ask the selected provider for one action and normalize its tool call."""
    if provider == "mantle":
        profile = get_model_profile(model_id)
        mantle_client = build_mantle_client(region=region, model_id=profile.model_id)
        messages = [{"role": "user", "content": prompt_text}]
        if profile.simulation_context is not None:
            messages.insert(
                0,
                {"role": "system", "content": profile.simulation_context},
            )
        response = mantle_client.chat_completions_create(
            messages=messages,
            tools=tool_config_to_openai_tools(tool_config),
            require_tool_call=True,
        )
        return provider, extract_function_call(response)
    if provider == "runtime":
        from mock_bedrock import extract_tool_use

        # boto3's generated client supports toolConfig, but its precise
        # dynamic signature is not represented by our smaller Converse protocol.
        runtime_client = cast(Any, build_real_client(region))
        response = runtime_client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt_text}]}],
            toolConfig=tool_config,
        )
        return provider, extract_tool_use(response)
    raise ValueError(f"Unknown provider: {provider!r}")


def _mantle_base_url(region: str, model_id: str) -> str:
    """Return the Mantle base URL for an approved model.

    Uses an explicit allowlist so an untrusted model_id cannot silently route
    to an unintended endpoint. Raises ValueError for any unrecognised model_id.

    Args:
        region: AWS region (e.g. eu-west-2).
        model_id: Exact Mantle model identifier from the approved matrix.

    Raises:
        ValueError: If model_id is not in the approved allowlist.
    """
    get_model_profile(model_id)
    return f"https://bedrock-mantle.{region}.api.aws/v1"


def _hit_token_limit(response: Any) -> bool:  # noqa: ANN401 -- OpenAI response is dynamic
    """Return True when the model was truncated before producing any tool call.

    Reasoning models sometimes enter an extended chain-of-thought mode that
    exhausts max_completion_tokens before the tool call JSON is written.
    The caller can then retry to get another chance at the short-mode path.
    """
    choices = _get(response, "choices")
    if not choices:
        return False
    first = choices[0]
    if _get(first, "finish_reason") != "length":
        return False
    message = _get(first, "message")
    return not _get(message, "tool_calls")


def _get(obj: Any, key: str) -> Any:  # noqa: ANN401 -- dict or SDK object, both dynamic
    """Read ``key`` from a dict or an attribute-style object, tolerating both.

    OpenAI SDK responses are attribute objects; test fixtures and JSON are
    dicts. This lets extract_function_call handle either shape.
    """
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def build_provider_client(region: str, model_id: str, provider: str) -> Any:  # noqa: ANN401
    """Return the model client for the selected provider.

    Args:
        region: AWS region for the client.
        model_id: Model identifier (only used by the Mantle provider).
        provider: ``"runtime"`` for the boto3 Bedrock Converse path, or
            ``"mantle"`` for the OpenAI-compatible Mantle endpoint.

    Returns:
        A :class:`DuskBedrockClient` for ``"runtime"`` or a
        :class:`MantleClient` for ``"mantle"``.

    Raises:
        ValueError: If ``provider`` is not a recognised value.
    """
    if provider == "runtime":
        return DuskBedrockClient(client=build_real_client(region))
    if provider == "mantle":
        profile = get_model_profile(model_id)
        return build_mantle_client(region=region, model_id=profile.model_id)
    raise ValueError(f"Unknown provider: {provider!r}")
