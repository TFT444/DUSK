#!/usr/bin/env python3
"""Bounded coverage-guided fuzz smoke test for the public action parser."""

from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from dusk.actions.event import AgentAction


def fuzz_one(data: bytes) -> None:
    """Exercise JSON decoding and canonical event validation."""
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(value, dict):
        return
    try:
        action = AgentAction.from_dict(value)
    except (TypeError, ValueError):
        return
    # Exercise serialization as part of the smoke run.  The parser's
    # canonicalization may intentionally normalize equivalent input values.
    AgentAction.from_dict(action.to_dict())


def main() -> None:
    sys.argv = [sys.argv[0], "-runs=2000", "-max_len=4096"]
    atheris.Setup(sys.argv, fuzz_one)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
