"""Normalize proposed Mantle (OpenAI-format) tool calls before execution.

The Bedrock Mantle endpoint speaks the OpenAI Chat Completions protocol, so
a proposed action arrives as an OpenAI ``tool_calls[0]`` entry rather than a
Bedrock ``toolUse`` block. The shape this adapter consumes is the flattened
form produced by ``extract_function_call`` in the agent-demo harness::

    {"id": "call_xxx", "name": "update_route_table",
     "arguments_json": '{"target": "rt-x", "before": {...}, "after": {...}}'}

Unlike the Bedrock adapter, this adapter allow-lists tool names: only the
five DUSK control-plane tools are accepted. Any other name is rejected as a
malformed record rather than mapped to ``unknown``, because a Mantle model
calling an out-of-band tool is a signal worth surfacing, not swallowing.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from dusk.actions.adapters.base import AdapterError, SourceAdapter
from dusk.actions.event import AgentAction

#: Substrings of the tool name mapped to a canonical action_type. Mirrors
#: the Bedrock adapter's classification so both providers agree.
_ACTION_TYPE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("firewall", "securitygroup"), "firewall_rule_change"),
    (("route",), "route_change"),
    (("segment", "subnet", "vpc"), "segment_change"),
    (("role", "permission"), "role_assignment"),
    (("port",), "port_change"),
)

#: The only tool names a DUSK agent is permitted to call. Anything else is a
#: malformed record, not an ``unknown`` action.
_ALLOWED_TOOLS: frozenset[str] = frozenset(
    {
        "update_route_table",
        "update_firewall_rule",
        "assign_role",
        "copy_data",
        "delete_resource",
    }
)


def _action_type(tool_name: str | None) -> str:
    """Classify the canonical action_type from the tool name."""
    if not tool_name:
        return "unknown"
    lowered = tool_name.lower()
    for needles, action_type in _ACTION_TYPE_RULES:
        if any(needle in lowered for needle in needles):
            return action_type
    return "unknown"


class MantleAdapter(SourceAdapter):
    """Adapter for a proposed Mantle (OpenAI function-call) tool-call."""

    source = "mantle"

    def parse(self, raw: dict[str, Any]) -> AgentAction:
        """Map a raw record already carrying agent_id/timestamp into an AgentAction.

        Args:
            raw: A dict with ``function_call`` (the flattened OpenAI tool
                call) plus ``agent_id`` and ``timestamp``.

        Returns:
            The canonical :class:`AgentAction`.

        Raises:
            AdapterError: If the function call, identity, or timestamp is
                missing or malformed.
        """
        function_call = raw.get("function_call")
        if not isinstance(function_call, dict):
            raise AdapterError("Mantle record missing 'function_call' block")
        try:
            timestamp = raw["timestamp"]
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp)
            return self.parse_function_call(
                function_call, agent_id=raw["agent_id"], timestamp=timestamp
            )
        except KeyError as exc:
            raise AdapterError(f"Mantle record missing required field: {exc}") from exc
        except (TypeError, ValueError) as exc:
            raise AdapterError(f"Malformed Mantle record: {exc}") from exc

    def parse_function_call(
        self, fc: dict[str, Any], *, agent_id: str, timestamp: datetime
    ) -> AgentAction:
        """Map one OpenAI function call into an :class:`AgentAction`.

        Args:
            fc: The flattened function call (``id``, ``name``,
                ``arguments_json``).
            agent_id: Identity of the agent that made the call. Supplied by
                the harness, not present in the function call itself.
            timestamp: When the call was made. Must be timezone-aware.

        Returns:
            The canonical :class:`AgentAction`.

        Raises:
            AdapterError: If the arguments are not valid JSON, the tool name
                is not an allowed DUSK tool, or the target is missing.
        """
        tool_name = fc.get("name")
        if tool_name not in _ALLOWED_TOOLS:
            raise AdapterError(
                f"Mantle proposed a tool that is not a permitted DUSK tool: {tool_name!r}"
            )

        arguments_json = fc.get("arguments_json")
        try:
            arguments = json.loads(arguments_json) if arguments_json is not None else {}
        except (TypeError, ValueError) as exc:
            raise AdapterError(f"Mantle arguments are not valid JSON: {exc}") from exc
        if not isinstance(arguments, dict):
            raise AdapterError("Mantle arguments JSON must decode to an object")

        target = arguments.get("target")
        if not target:
            raise AdapterError("Mantle function-call arguments missing 'target'")

        action_type = _action_type(tool_name if isinstance(tool_name, str) else None)
        change = {
            "before": arguments.get("before"),
            "after": arguments.get("after"),
        }

        try:
            return AgentAction(
                agent_id=agent_id,
                timestamp=timestamp,
                action_type=action_type,
                target=target,
                change=change,
                source=self.source,
                raw_ref=fc.get("id"),
            )
        except ValueError as exc:
            raise AdapterError(f"Malformed Mantle tool-call: {exc}") from exc
