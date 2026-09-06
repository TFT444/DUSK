#!/usr/bin/env python3
"""Validate sanitized evidence from live cloud and Kubernetes certification runs.

This validator deliberately accepts no "mock", "simulated", or skipped result.
It validates the evidence envelope after a protected runner has exercised the
real provider; it does not turn ordinary CI output into provider evidence.
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
SCHEMA_VERSION = "1.0"
PROVIDERS = frozenset({"aws", "azure", "kubernetes"})
CERTIFIED_RULE_IDS = frozenset(f"DUSK-CLOUD-{index:03d}" for index in range(1, 11))
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
FORBIDDEN_TEXT = re.compile(
    r"(mock|simulat(?:ed|ion)|fake|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._~-]+)",
    re.IGNORECASE,
)

REQUIRED_SCENARIOS: Mapping[str, frozenset[str]] = {
    "aws": frozenset(
        {
            "privileged_iam_escalation",
            "destructive_network_action",
            "benign_iam_change",
            "benign_network_change",
        }
    ),
    "azure": frozenset({"privileged_cross_tenant_role_assignment", "benign_role_assignment"}),
    "kubernetes": frozenset(
        {
            "cluster_admin_grant",
            "privileged_workload",
            "public_exposure",
            "benign_rbac",
            "benign_workload",
            "benign_service",
        }
    ),
}


def _object(value: object, location: str, failures: list[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        failures.append(f"{location} must be an object")
        return {}
    return value


def _aware_timestamp(value: object, location: str, failures: list[str]) -> datetime | None:
    if not isinstance(value, str):
        failures.append(f"{location} must be an ISO-8601 timestamp")
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{location} must be an ISO-8601 timestamp")
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        failures.append(f"{location} must include a UTC offset")
        return None
    return parsed


def _digest(value: object, location: str, failures: list[str]) -> None:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        failures.append(f"{location} must be a lowercase sha256 digest")


def _safe_text(value: object, location: str, failures: list[str]) -> None:
    if not isinstance(value, str) or not value.strip():
        failures.append(f"{location} must be a non-empty string")
    elif FORBIDDEN_TEXT.search(value):
        failures.append(f"{location} contains simulated or sensitive content")


def _validate_command(value: object, location: str, failures: list[str]) -> None:
    command = _object(value, location, failures)
    argv = command.get("argv")
    if not isinstance(argv, list) or not argv:
        failures.append(f"{location}.argv must be a non-empty list")
    else:
        for index, argument in enumerate(argv):
            _safe_text(argument, f"{location}.argv[{index}]", failures)
    if command.get("exit_code") != 0:
        failures.append(f"{location}.exit_code must be zero")
    _digest(command.get("output_digest"), f"{location}.output_digest", failures)
    started = _aware_timestamp(command.get("started_at"), f"{location}.started_at", failures)
    finished = _aware_timestamp(command.get("finished_at"), f"{location}.finished_at", failures)
    if started is not None and finished is not None and finished < started:
        failures.append(f"{location}.finished_at precedes started_at")


def _validate_result(
    value: object,
    *,
    location: str,
    malicious: bool,
    failures: list[str],
) -> None:
    result = _object(value, location, failures)
    mode = result.get("mode")
    expected = "WOULD-BLOCK" if malicious and mode == "watch" else "BLOCK"
    if not malicious:
        expected = "ALLOW"
    if mode not in {"watch", "enforce"}:
        failures.append(f"{location}.mode must be watch or enforce")
    elif result.get("verdict") != expected:
        failures.append(f"{location}.verdict must be {expected}")

    _validate_continuity(result, location, malicious, failures)
    _validate_downstream_state(result, location, malicious, mode, failures)


def _validate_continuity(
    result: Mapping[str, Any], location: str, malicious: bool, failures: list[str]
) -> None:
    """Require trace-to-acknowledgement continuity without provider payloads."""

    for field in ("trace_id", "decision_id"):
        _safe_text(result.get(field), f"{location}.{field}", failures)
    policy_ids = result.get("policy_rule_ids")
    if not isinstance(policy_ids, list) or (malicious and not policy_ids):
        failures.append(f"{location}.policy_rule_ids must contain matched rules")
    elif isinstance(policy_ids, list):
        for index, policy_id in enumerate(policy_ids):
            _safe_text(policy_id, f"{location}.policy_rule_ids[{index}]", failures)
    if result.get("evidence_state") != "CONFIRMED":
        failures.append(f"{location}.evidence_state must be CONFIRMED")
    if result.get("dashboard_visible") is not True:
        failures.append(f"{location}.dashboard_visible must be true")
    audit = _object(result.get("audit"), f"{location}.audit", failures)
    if not isinstance(audit.get("sequence"), int) or audit.get("sequence", 0) <= 0:
        failures.append(f"{location}.audit.sequence must be positive")
    _digest(audit.get("digest"), f"{location}.audit.digest", failures)
    lifecycle = _object(result.get("lifecycle"), f"{location}.lifecycle", failures)
    _safe_text(lifecycle.get("status"), f"{location}.lifecycle.status", failures)
    _safe_text(
        lifecycle.get("acknowledgement_id"),
        f"{location}.lifecycle.acknowledgement_id",
        failures,
    )


def _validate_downstream_state(
    result: Mapping[str, Any],
    location: str,
    malicious: bool,
    mode: object,
    failures: list[str],
) -> None:
    """Require independent before/after evidence for a blocked mutation."""
    _digest(result.get("before_digest"), f"{location}.before_digest", failures)
    _digest(result.get("after_digest"), f"{location}.after_digest", failures)
    if malicious and mode == "enforce":
        if result.get("downstream_mutated") is not False:
            failures.append(f"{location}.downstream_mutated must be false for a blocked action")
        if result.get("before_digest") != result.get("after_digest"):
            failures.append(f"{location} proves downstream mutation for a blocked action")


def _validate_scenario(
    value: object,
    *,
    location: str,
    failures: list[str],
) -> str | None:
    scenario = _object(value, location, failures)
    name = scenario.get("name")
    if not isinstance(name, str):
        failures.append(f"{location}.name must be a string")
        return None
    malicious = not name.startswith("benign_")
    if scenario.get("classification") != ("malicious" if malicious else "benign"):
        failures.append(f"{location}.classification does not match {name}")
    commands = scenario.get("commands")
    if not isinstance(commands, list) or not commands:
        failures.append(f"{location}.commands must contain live provider commands")
    else:
        for index, command in enumerate(commands):
            _validate_command(command, f"{location}.commands[{index}]", failures)
    results = scenario.get("results")
    if not isinstance(results, list) or len(results) != 2:
        failures.append(f"{location}.results must contain watch and enforce results")
    else:
        for index, result in enumerate(results):
            _validate_result(
                result,
                location=f"{location}.results[{index}]",
                malicious=malicious,
                failures=failures,
            )
        modes = {result.get("mode") for result in results if isinstance(result, dict)}
        if modes != {"watch", "enforce"}:
            failures.append(f"{location}.results must cover watch and enforce exactly once")
    return name


def _validate_provider_scenarios(
    provider: Mapping[str, Any], name: str, location: str, failures: list[str]
) -> None:
    scenarios = provider.get("scenarios")
    names: list[str] = []
    if not isinstance(scenarios, list):
        failures.append(f"{location}.scenarios must be a list")
    else:
        for index, scenario in enumerate(scenarios):
            scenario_name = _validate_scenario(
                scenario,
                location=f"{location}.scenarios[{index}]",
                failures=failures,
            )
            if scenario_name is not None:
                names.append(scenario_name)
    if set(names) != REQUIRED_SCENARIOS[name]:
        failures.append(f"{location}.scenarios does not match the required {name} matrix")
    if len(names) != len(set(names)):
        failures.append(f"{location}.scenarios contains duplicate names")


def _validate_teardown(provider: Mapping[str, Any], location: str, failures: list[str]) -> None:
    teardown = _object(provider.get("teardown"), f"{location}.teardown", failures)
    if teardown.get("completed") is not True or teardown.get("baseline_restored") is not True:
        failures.append(f"{location}.teardown must complete and restore the baseline")
    _digest(teardown.get("baseline_digest"), f"{location}.teardown.baseline_digest", failures)
    _digest(teardown.get("final_digest"), f"{location}.teardown.final_digest", failures)
    if teardown.get("baseline_digest") != teardown.get("final_digest"):
        failures.append(f"{location}.teardown final state differs from its baseline")


def _validate_provider(value: object, location: str, failures: list[str]) -> str | None:
    provider = _object(value, location, failures)
    name = provider.get("name")
    if not isinstance(name, str) or name not in PROVIDERS:
        failures.append(f"{location}.name must identify aws, azure, or kubernetes")
        return None
    if provider.get("sandbox_approved") is not True:
        failures.append(f"{location}.sandbox_approved must be true")
    identity = _object(provider.get("identity"), f"{location}.identity", failures)
    if identity.get("mechanism") != "oidc":
        failures.append(f"{location}.identity.mechanism must be oidc")
    _digest(identity.get("principal_digest"), f"{location}.identity.principal_digest", failures)
    _digest(provider.get("resource_id_digest"), f"{location}.resource_id_digest", failures)
    _digest(provider.get("service_image_digest"), f"{location}.service_image_digest", failures)
    _validate_provider_scenarios(provider, name, location, failures)
    _validate_teardown(provider, location, failures)
    return name


def validate_manifest(manifest: object) -> list[str]:
    """Return all certification failures; an empty list means structurally valid evidence."""
    failures: list[str] = []
    root = _object(manifest, "manifest", failures)
    if root.get("schema_version") != SCHEMA_VERSION:
        failures.append(f"schema_version must be {SCHEMA_VERSION}")
    commit = root.get("commit_sha")
    if not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
        failures.append("commit_sha must be a full lowercase Git commit SHA")
    _safe_text(root.get("run_id"), "run_id", failures)
    started = _aware_timestamp(root.get("started_at"), "started_at", failures)
    finished = _aware_timestamp(root.get("finished_at"), "finished_at", failures)
    if started is not None and finished is not None and finished < started:
        failures.append("finished_at precedes started_at")

    review = _object(root.get("review"), "review", failures)
    _safe_text(review.get("reviewer"), "review.reviewer", failures)
    _safe_text(review.get("approval_reference"), "review.approval_reference", failures)
    _aware_timestamp(review.get("approved_at"), "review.approved_at", failures)

    certified_rules = root.get("certified_rule_ids")
    if not isinstance(certified_rules, list) or set(certified_rules) != CERTIFIED_RULE_IDS:
        failures.append("certified_rule_ids must contain DUSK-CLOUD-001 through DUSK-CLOUD-010")
    elif len(certified_rules) != len(set(certified_rules)):
        failures.append("certified_rule_ids must not contain duplicates")

    providers = root.get("providers")
    names: list[str] = []
    if not isinstance(providers, list):
        failures.append("providers must be a list")
    else:
        for index, provider in enumerate(providers):
            name = _validate_provider(provider, f"providers[{index}]", failures)
            if name is not None:
                names.append(name)
    if set(names) != PROVIDERS or len(names) != len(PROVIDERS):
        failures.append("providers must contain aws, azure, and kubernetes exactly once")
    return failures


def load_and_validate(path: Path) -> list[str]:
    """Load a bounded JSON manifest and return all validation failures."""
    try:
        if not path.is_file():
            return [f"manifest does not exist: {path}"]
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            return ["manifest exceeds the 2 MiB size limit"]
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"unable to load manifest: {exc}"]
    return validate_manifest(manifest)


def main(argv: Sequence[str] | None = None) -> int:
    """Validate one provider-certification manifest from a protected run."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    failures = load_and_validate(args.manifest)
    if failures:
        for failure in failures:
            print(f"provider certification failure: {failure}")
        return 1
    print("Live provider certification evidence is structurally complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
