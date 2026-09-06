#!/usr/bin/env python3
"""Validate the control catalogue, emit evidence, and aggregate fail closed."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

STATUSES = {"PASS", "FAIL", "NOT_APPLICABLE"}
APPLICABILITY = {"always", "code_changes", "dependency_changes", "non_docs"}


def load_catalogue(path: Path) -> dict[str, dict[str, Any]]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if (
        not isinstance(raw, dict)
        or raw.get("version") != 1
        or not isinstance(raw.get("controls"), list)
    ):
        raise ValueError("catalogue must have version 1 and a controls list")
    controls: dict[str, dict[str, Any]] = {}
    required = {"id", "description", "tool", "lane", "blocking", "applicability"}
    for item in raw["controls"]:
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError(f"malformed control: {item!r}")
        control_id = item["id"]
        if not isinstance(control_id, str) or control_id in controls:
            raise ValueError(f"duplicate or invalid control ID: {control_id!r}")
        if item["lane"] not in {"pr", "deep", "release"}:
            raise ValueError(f"invalid lane for {control_id}")
        if item["applicability"] not in APPLICABILITY or item["blocking"] is not True:
            raise ValueError(f"invalid policy for {control_id}")
        controls[control_id] = item
    if len(controls) != 100:
        raise ValueError(f"catalogue must contain exactly 100 controls, found {len(controls)}")
    return controls


def docs_only(paths: list[str]) -> bool:
    return bool(paths) and all(
        p.endswith((".md", ".rst", ".txt")) or p.startswith("docs/") for p in paths
    )


def record(args: argparse.Namespace, controls: dict[str, dict[str, Any]]) -> None:
    if args.control not in controls:
        raise ValueError(f"unknown control: {args.control}")
    if args.status not in STATUSES:
        raise ValueError(f"invalid status: {args.status}")
    control = controls[args.control]
    changed = args.changed_file or []
    if args.status == "NOT_APPLICABLE":
        if control["applicability"] != "non_docs" or not docs_only(changed):
            raise ValueError(f"unauthorized NOT_APPLICABLE for {args.control}")
    evidence = {
        "schema_version": 1,
        "control_id": args.control,
        "status": args.status,
        "tool": control["tool"],
        "timestamp": datetime.now(UTC).isoformat(),
        "details": args.details,
        "changed_files": changed,
    }
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, sort_keys=True) + "\n", encoding="utf-8")


def aggregate(  # noqa: C901
    args: argparse.Namespace, controls: dict[str, dict[str, Any]]
) -> None:
    expected = {key for key, item in controls.items() if item["lane"] == args.lane}
    seen: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for path in sorted(Path(args.results).glob("**/*.json")):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"malformed evidence {path}: {exc}")
            continue
        control_id = result.get("control_id")
        if control_id in seen:
            errors.append(f"duplicate result: {control_id}")
            continue
        if control_id not in expected:
            errors.append(f"unexpected result for {args.lane}: {control_id}")
            continue
        seen[control_id] = result
        status = result.get("status")
        if result.get("schema_version") != 1 or status not in STATUSES:
            errors.append(f"malformed result: {control_id}")
        elif status == "FAIL":
            errors.append(f"failed control: {control_id}")
        elif status == "NOT_APPLICABLE":
            item = controls[control_id]
            if item["applicability"] != "non_docs" or not docs_only(
                result.get("changed_files", [])
            ):
                errors.append(f"unauthorized NOT_APPLICABLE: {control_id}")
    for missing in sorted(expected - seen.keys()):
        errors.append(f"missing result: {missing}")
    summary = {
        "lane": args.lane,
        "expected": len(expected),
        "received": len(seen),
        "errors": errors,
    }
    print(json.dumps(summary, indent=2))
    if errors:
        raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalogue", default="ci/controls.yml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate")
    emit = sub.add_parser("record")
    emit.add_argument("--control", required=True)
    emit.add_argument("--status", required=True)
    emit.add_argument("--output", required=True)
    emit.add_argument("--details", default="")
    emit.add_argument("--changed-file", action="append")
    gate = sub.add_parser("aggregate")
    gate.add_argument("--lane", choices=("pr", "deep", "release"), required=True)
    gate.add_argument("--results", required=True)
    args = parser.parse_args()
    try:
        controls = load_catalogue(Path(args.catalogue))
        if args.command == "record":
            record(args, controls)
        elif args.command == "aggregate":
            aggregate(args, controls)
    except (OSError, ValueError) as exc:
        print(f"control error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
