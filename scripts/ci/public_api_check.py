#!/usr/bin/env python3
"""Reject removals from explicitly exported Python APIs relative to a Git base."""

from __future__ import annotations

import argparse
import ast
import shutil
import subprocess
from pathlib import Path


def exports(source: str, label: str) -> set[str]:
    """Return a module's literal ``__all__`` contract."""
    tree = ast.parse(source, filename=label)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "__all__" for target in targets):
                value = node.value
                if value is None:
                    break
                literal = ast.literal_eval(value)
                if not isinstance(literal, (list, tuple)) or not all(
                    isinstance(item, str) for item in literal
                ):
                    raise ValueError(f"{label}: __all__ must be a literal list of strings")
                return set(literal)
    return set()


def base_source(base: str, path: Path) -> str | None:
    """Read a path from the base revision, or return None if it is new."""
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required for public API compatibility checks")
    completed = subprocess.run(  # noqa: S603 -- fixed executable and argv, never a shell
        [git, "show", f"{base}:{path.as_posix()}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode == 0:
        return completed.stdout
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("base", help="Git revision used as the compatibility baseline")
    args = parser.parse_args()
    failures: list[str] = []
    for path in sorted(Path("src/dusk").glob("**/__init__.py")):
        old_source = base_source(args.base, path)
        if old_source is None:
            continue
        old = exports(old_source, f"{args.base}:{path}")
        current = exports(path.read_text(encoding="utf-8"), str(path))
        removed = sorted(old - current)
        if removed:
            failures.append(f"{path}: removed public exports: {', '.join(removed)}")
    if failures:
        raise SystemExit("\n".join(failures))
    print("Public __all__ contracts are backward compatible with the base revision.")


if __name__ == "__main__":
    main()
