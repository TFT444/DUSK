#!/usr/bin/env python3
"""Validate real-agent JUnit evidence and write a model-specific manifest."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from xml.etree import ElementTree

COUNT_FIELDS = ("tests", "failures", "errors", "skipped")
MAX_JUNIT_BYTES = 5 * 1024 * 1024


def _load_junit_root(path: Path) -> ElementTree.Element:
    if not path.is_file():
        raise ValueError(f"JUnit evidence does not exist: {path}")

    try:
        if path.stat().st_size > MAX_JUNIT_BYTES:
            raise ValueError("JUnit evidence exceeds the 5 MiB size limit")
        xml = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"Unable to read JUnit evidence: {path}") from exc

    lowered_xml = xml.lower()
    if b"<!doctype" in lowered_xml or b"<!entity" in lowered_xml:
        raise ValueError("JUnit evidence must not contain a DTD or entity declaration")

    try:
        return ElementTree.fromstring(xml)  # noqa: S314, guarded local JUnit input
    except ElementTree.ParseError as exc:
        raise ValueError(f"Unable to parse JUnit evidence: {path}") from exc


def parse_junit_counts(path: Path) -> dict[str, int]:
    """Return summed counts from leaf test suites in a JUnit XML document."""
    root = _load_junit_root(path)
    suites = [
        element
        for element in root.iter("testsuite")
        if not any(child.tag == "testsuite" for child in element)
    ]
    if not suites:
        raise ValueError("JUnit evidence contains no test suites")

    counts = dict.fromkeys(COUNT_FIELDS, 0)
    for suite in suites:
        for field in COUNT_FIELDS:
            raw_value = suite.get(field, "0")
            try:
                value = int(raw_value)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"JUnit {field} count is not an integer") from exc
            if value < 0:
                raise ValueError(f"JUnit {field} count must not be negative")
            counts[field] += value
    return counts


def validate_counts(counts: Mapping[str, int]) -> None:
    """Reject empty, failed, errored, or skipped real-agent evidence."""
    if counts.get("tests", 0) <= 0:
        raise ValueError("JUnit evidence contains zero tests")
    for field in ("failures", "errors", "skipped"):
        value = counts.get(field, 0)
        if value != 0:
            raise ValueError(f"JUnit evidence contains {field}: {value}")


def write_validated_manifest(
    *,
    junit_path: Path,
    output_path: Path,
    provider: str,
    model_id: str,
    model_slug: str,
    commit_sha: str,
    run_id: str,
    gate_mode: str,
) -> None:
    """Validate JUnit evidence and write its non-secret identity manifest."""
    counts = parse_junit_counts(junit_path)
    validate_counts(counts)
    manifest = {
        "provider": provider,
        "model_id": model_id,
        "model_slug": model_slug,
        "commit_sha": commit_sha,
        "run_id": run_id,
        "gate_mode": gate_mode,
        **counts,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--junit", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--model-slug", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--gate-mode", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    write_validated_manifest(
        junit_path=args.junit,
        output_path=args.output,
        provider=args.provider,
        model_id=args.model_id,
        model_slug=args.model_slug,
        commit_sha=args.commit_sha,
        run_id=args.run_id,
        gate_mode=args.gate_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
