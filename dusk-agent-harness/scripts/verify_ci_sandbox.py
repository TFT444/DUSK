"""Verify the authenticated DUSK Compose sandbox over its public HTTP seams."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any

_CLEAN_ACTION = {
    "agent_id": "netops-agent",
    "timestamp": datetime(2026, 1, 1, tzinfo=UTC).isoformat(),
    "action_type": "route_change",
    "target": "rt-corp-prod",
    "change": {
        "before": {"cidr": "10.0.2.0/24", "next_hop": "igw-1"},
        "after": {"cidr": "10.0.2.0/24", "next_hop": "igw-2"},
    },
    "source": "generic",
    "raw_ref": "ci-clean",
}

_POISONED_ACTION = {
    "agent_id": "netops-agent",
    "timestamp": datetime(2026, 1, 1, 0, 1, tzinfo=UTC).isoformat(),
    "action_type": "firewall_rule_change",
    "target": "fw-corp-restricted-segment",
    "change": {
        "before": None,
        "after": {"port": 22, "cidr": "0.0.0.0/0", "action": "allow"},
    },
    "source": "generic",
    "raw_ref": "ci-poisoned",
}


def _request_json(
    url: str,
    *,
    method: str = "GET",
    payload: object | None = None,
    token: str | None = None,
) -> tuple[int, dict[str, Any]]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("sandbox verifier accepts only HTTP(S) URLs")
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(  # nosec B310  # noqa: S310 - scheme restricted above
        url, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(  # nosec B310  # noqa: S310 - scheme restricted above
            request, timeout=10
        ) as response:
            body = json.load(response)
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = json.load(exc)
        return exc.code, body


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _evaluate_and_apply(
    gate_url: str,
    target_url: str,
    token: str,
    action: dict[str, Any],
    expected_verdict: str,
) -> bool:
    status, verdict = _request_json(
        f"{gate_url}/v1/gate", method="POST", payload=action, token=token
    )
    _require(status == 200, f"gate returned HTTP {status}: {verdict}")
    _require(
        verdict.get("verdict") == expected_verdict,
        f"expected {expected_verdict}, got {verdict.get('verdict')}: {verdict}",
    )

    if verdict["verdict"] == "BLOCK":
        return False

    apply_status, applied = _request_json(f"{target_url}/apply", method="POST", payload=action)
    _require(apply_status == 200, f"mock target returned HTTP {apply_status}: {applied}")
    return True


def verify(mode: str, gate_url: str, target_url: str, token: str) -> None:
    """Run authentication, validation, verdict, and downstream-state checks."""
    expected_poisoned = "WOULD-BLOCK" if mode == "watch" else "BLOCK"

    status, initial_log = _request_json(f"{target_url}/log")
    _require(status == 200 and initial_log.get("count") == 0, "sandbox did not start clean")

    status, _ = _request_json(f"{gate_url}/v1/gate", method="POST", payload=_CLEAN_ACTION)
    _require(status == 401, f"missing credential returned HTTP {status}, expected 401")

    status, _ = _request_json(
        f"{gate_url}/v1/gate",
        method="POST",
        payload=_CLEAN_ACTION,
        token=f"invalid-{token}",
    )
    _require(status == 401, f"invalid credential returned HTTP {status}, expected 401")

    status, _ = _request_json(
        f"{gate_url}/v1/gate", method="POST", payload={"invalid": True}, token=token
    )
    _require(status == 400, f"malformed action returned HTTP {status}, expected 400")

    clean_applied = _evaluate_and_apply(gate_url, target_url, token, _CLEAN_ACTION, "ALLOW")
    poisoned_applied = _evaluate_and_apply(
        gate_url, target_url, token, _POISONED_ACTION, expected_poisoned
    )
    _require(clean_applied, "clean action did not reach the mock target")
    _require(
        poisoned_applied is (mode == "watch"),
        f"poisoned action forwarding did not match {mode} mode",
    )

    status, final_log = _request_json(f"{target_url}/log")
    expected_targets = ["rt-corp-prod"]
    if mode == "watch":
        expected_targets.append("fw-corp-restricted-segment")
    actual_targets = [entry.get("target") for entry in final_log.get("entries", [])]
    _require(status == 200, f"mock target log returned HTTP {status}")
    _require(
        actual_targets == expected_targets,
        f"downstream state changed unexpectedly: expected {expected_targets}, got {actual_targets}",
    )
    print(
        json.dumps(
            {
                "mode": mode,
                "clean_verdict": "ALLOW",
                "poisoned_verdict": expected_poisoned,
                "applied_targets": actual_targets,
                "authentication_checks": "passed",
                "malformed_request_check": "passed",
                "sie_mode": "deterministic-fallback",
            },
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("watch", "enforce"))
    parser.add_argument("--gate-url", default="http://127.0.0.1:8000")
    parser.add_argument("--target-url", default="http://127.0.0.1:9000")
    parser.add_argument("--token", required=True)
    args = parser.parse_args()
    verify(args.mode, args.gate_url, args.target_url, args.token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
