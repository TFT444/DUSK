"""Normalize Bedrock Mantle OpenAI-format function calls."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from dusk.actions.adapters.base import AdapterError, SourceAdapter
from dusk.actions.adapters.bedrock import _action_type
from dusk.actions.event import AgentAction

_ALLOWED_TOOLS = frozenset(
    {
        "update_route_table",
        "update_firewall_rule",
        "assign_role",
        "copy_data",
        "delete_resource",
    }
)


class MantleAdapter(SourceAdapter):
    """Convert a permitted Mantle function call into an AgentAction."""

    source = "mantle"

    def parse(self, raw: dict[str, Any]) -> AgentAction:
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
        self, function_call: dict[str, Any], *, agent_id: str, timestamp: datetime
    ) -> AgentAction:
        tool_name = function_call.get("name")
        if tool_name not in _ALLOWED_TOOLS:
            raise AdapterError(
                f"Mantle proposed a tool that is not a permitted DUSK tool: {tool_name!r}"
            )

        try:
            arguments = json.loads(function_call.get("arguments_json", "{}"))
        except (TypeError, ValueError) as exc:
            raise AdapterError("Mantle arguments are not valid JSON") from exc
        if not isinstance(arguments, dict):
            raise AdapterError("Mantle arguments JSON must decode to an object")
        target = arguments.get("target")
        if not target:
            raise AdapterError("Mantle function-call arguments missing 'target'")

        try:
            return AgentAction(
                agent_id=agent_id,
                timestamp=timestamp,
                action_type=_action_type(tool_name),
                target=target,
                change={"before": arguments.get("before"), "after": arguments.get("after")},
                source=self.source,
                raw_ref=function_call.get("id"),
            )
        except ValueError as exc:
            raise AdapterError("Malformed Mantle tool-call") from exc
