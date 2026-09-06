#!/usr/bin/env python3
"""Run one command and write the same auditable outcome for related controls."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

try:
    from scripts.ci.control import load_catalogue, record
except ModuleNotFoundError:  # Direct execution adds scripts/ci, not the repository root.
    from control import load_catalogue, record


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalogue", default="ci/controls.yml")
    parser.add_argument("--results", required=True)
    parser.add_argument("--controls", nargs="+", required=True)
    parser.add_argument("--not-applicable", action="store_true")
    parser.add_argument("--changed-file", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    controls = load_catalogue(Path(args.catalogue))
    if args.not_applicable:
        return_code = 0
        status = "NOT_APPLICABLE"
        detail = "catalogue-authorized documentation-only change"
    else:
        if not args.command:
            parser.error("a command is required unless --not-applicable is used")
        command = args.command[1:] if args.command[0] == "--" else args.command
        completed = subprocess.run(command, check=False)  # noqa: S603
        return_code = completed.returncode
        status = "PASS" if return_code == 0 else "FAIL"
        detail = f"command exited {return_code}: {' '.join(command)}"
    for control_id in args.controls:
        record(
            argparse.Namespace(
                control=control_id,
                status=status,
                output=str(Path(args.results) / f"{control_id}.json"),
                details=detail,
                changed_file=args.changed_file,
            ),
            controls,
        )
    raise SystemExit(return_code)


if __name__ == "__main__":
    main()
