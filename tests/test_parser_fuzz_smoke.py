"""Regression coverage for the bounded parser fuzz smoke harness."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import types
from contextlib import nullcontext
from pathlib import Path

import pytest


def test_parser_fuzz_harness_uses_atheris_bounded_run_flag(monkeypatch) -> None:
    """Atheris must exit gracefully after the configured number of runs."""
    setup_args: list[str] = []
    instrumented_functions: list[str] = []
    fake_atheris = types.ModuleType("atheris")
    fake_atheris.instrument_imports = nullcontext

    def instrument_func(callback: object) -> object:
        instrumented_functions.append(callback.__name__)  # type: ignore[attr-defined]
        return callback

    def setup(arguments: list[str], _callback: object) -> None:
        setup_args.extend(arguments)

    fake_atheris.instrument_func = instrument_func
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
    assert instrumented_functions == ["fuzz_one"]


@pytest.mark.parametrize(
    ("fuzzer_output", "expected_returncode"),
    [
        ("Done 2000 in 0 second(s)\n", 0),
        ("ERROR: no interesting inputs were found\n", 1),
        ("=== Uncaught Python exception: ===\nValueError: bad input\n", 1),
    ],
)
def test_parser_fuzz_ci_wrapper_only_accepts_bounded_success(
    tmp_path: Path, fuzzer_output: str, expected_returncode: int
) -> None:
    """Atheris's bounded exit is accepted only without a failure marker."""
    fake_python = tmp_path / "fake-python"
    fake_python.write_text(
        f"#!/bin/sh\nprintf '%s' '{fuzzer_output}'\nexit 1\n",
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    environment = os.environ | {"PYTHON_BIN": str(fake_python)}
    shell_path = (
        shutil.which("sh") or shutil.which("sh.exe") or str(Path("C:/Program Files/Git/bin/sh.exe"))
    )
    if shell_path is None:
        pytest.skip("a POSIX shell is required to test the CI wrapper")

    completed = subprocess.run(
        [shell_path, "scripts/ci/run_parser_fuzz_smoke.sh"],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )

    assert completed.returncode == expected_returncode
