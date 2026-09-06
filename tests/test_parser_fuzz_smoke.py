"""Regression coverage for the bounded parser fuzz smoke harness."""

from __future__ import annotations

import importlib.util
import sys
import types
from contextlib import nullcontext
from pathlib import Path


def test_parser_fuzz_harness_uses_atheris_bounded_run_flag(monkeypatch) -> None:
    """Atheris must exit gracefully after the configured number of runs."""
    setup_args: list[str] = []
    fake_atheris = types.ModuleType("atheris")
    fake_atheris.instrument_imports = nullcontext

    def setup(arguments: list[str], _callback: object) -> None:
        setup_args.extend(arguments)

    fake_atheris.Setup = setup
    fake_atheris.Fuzz = lambda: None
    monkeypatch.setitem(sys.modules, "atheris", fake_atheris)

    script_path = Path("scripts/ci/parser_fuzz_smoke.py")
    spec = importlib.util.spec_from_file_location("parser_fuzz_smoke", script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    module.main()

    assert "-atheris_runs=2000" in setup_args
    assert "-runs=2000" not in setup_args
