#!/usr/bin/env python3
"""Write the deterministic control-plane OpenAPI document."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dusk_control_plane.openapi import render_openapi


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "contracts" / "openapi.json",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when the committed document differs from the generated schema.",
    )
    args = parser.parse_args()
    rendered = render_openapi()
    if args.check:
        if not args.output.is_file() or args.output.read_text(encoding="utf-8") != rendered:
            print(f"OpenAPI contract is stale: {args.output}", file=sys.stderr)
            raise SystemExit(1)
        return
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
