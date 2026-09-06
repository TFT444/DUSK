"""Tests for the /v1/gate HTTP endpoint (contracts/gate.openapi.yaml)."""

from __future__ import annotations

import os
import secrets
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from dusk import api
from dusk.config import reset_config

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
BASELINE_PATH = str(FIXTURES / "actions_normal.json")

LAB_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "lab", "actions")
sys.path.insert(0, os.path.abspath(LAB_DIR))

import generate_actions  # noqa: E402

if not Path(BASELINE_PATH).exists():
    generate_actions.generate(str(FIXTURES))

CONTRACT_FIELDS = {
    "trace_id",
    "verdict",
    "score",
    "blast",
    "mitre_attack",
    "mitre_atlas",
    "reasons",
    "predicted_next",
    "similar_decision_ids",
}


@pytest.fixture(autouse=True)
def _reset_gate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", BASELINE_PATH)
    monkeypatch.setenv("DUSK_GATE_BASELINE_SOURCE", "generic")
    monkeypatch.delenv("DUSK_ENFORCE", raising=False)
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    # Explicit opt-in for keyless test access -- mirrors the local demo compose
    # setting. Tests that verify the fail-closed default override this via
    # monkeypatch.delenv("DUSK_GATE_ALLOW_ANONYMOUS").
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    # Isolated per test by default so a refusal in one test never writes
    # into the repo's working directory; test_offense_memory_persists_*
    # overrides this explicitly to exercise the real default-path behaviour.
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offense-memory.json"))
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()
    yield
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()


@pytest.fixture
def client():
    api.app.config["TESTING"] = True
    with api.app.test_client() as c:
        yield c


def _action_payload(
    agent_id: str = "netops-agent", target: str = "fw-corp-https", **after: object
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "timestamp": "2023-11-14T22:20:00+00:00",
        "action_type": "firewall_rule_change",
        "target": target,
        "change": {"before": None, "after": dict(after) if after else None},
        "source": "generic",
        "raw_ref": "evt-test-1",
    }


def test_health(client) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_gate_returns_contract_shaped_verdict(client) -> None:
    r = client.post("/v1/gate", json=_action_payload(port=443))
    assert r.status_code == 200
    data = r.get_json()
    assert set(data) == CONTRACT_FIELDS
    assert data["verdict"] in {"ALLOW", "WOULD-BLOCK", "BLOCK"}
    assert isinstance(data["mitre_attack"], list)
    assert isinstance(data["mitre_atlas"], list)
    assert isinstance(data["reasons"], list)
    assert isinstance(data["similar_decision_ids"], list)
    assert 0.0 <= data["score"] <= 1.0
    assert data["blast"] in {"low", "medium", "high"}


def test_gate_allows_known_agent_pattern(client) -> None:
    r = client.post("/v1/gate", json=_action_payload(port=443))
    assert r.get_json()["verdict"] == "ALLOW"


def test_gate_flags_unknown_agent_touching_sensitive_target(client) -> None:
    r = client.post(
        "/v1/gate", json=_action_payload(agent_id="ghost-agent", target="fw-restricted")
    )
    assert r.get_json()["verdict"] in {"WOULD-BLOCK", "BLOCK"}


def test_gate_rejects_invalid_action(client) -> None:
    r = client.post("/v1/gate", json={"agent_id": "netops-agent"})
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_gate_rejects_non_object_body(client) -> None:
    r = client.post("/v1/gate", data="not json", content_type="application/json")
    assert r.status_code == 400


def test_gate_rejects_oversized_body(client) -> None:
    oversized = "x" * (2 * 1024 * 1024)
    r = client.post("/v1/gate", data=oversized, content_type="application/json")
    assert r.status_code == 413


def test_gate_requires_configured_bearer_token(client, monkeypatch) -> None:
    gate_key = secrets.token_urlsafe(32)
    monkeypatch.setenv("DUSK_GATE_API_KEY", gate_key)

    missing = client.post("/v1/gate", json=_action_payload(port=443))
    incorrect = client.post(
        "/v1/gate",
        json=_action_payload(port=443),
        headers={"Authorization": f"Bearer {gate_key}-incorrect"},
    )
    accepted = client.post(
        "/v1/gate",
        json=_action_payload(port=443),
        headers={"Authorization": f"Bearer {gate_key}"},
    )

    assert missing.status_code == 401
    assert missing.headers["WWW-Authenticate"] == "Bearer"
    assert incorrect.status_code == 401
    assert accepted.status_code == 200


def test_health_does_not_require_gate_token(client, monkeypatch) -> None:
    monkeypatch.setenv("DUSK_GATE_API_KEY", secrets.token_urlsafe(32))
    assert client.get("/health").status_code == 200


def test_gate_without_baseline_defaults_to_unknown_agent(client, monkeypatch) -> None:
    monkeypatch.delenv("DUSK_GATE_BASELINE_PATH", raising=False)
    api.reset_gate_engine()
    r = client.post("/v1/gate", json=_action_payload())
    assert r.status_code == 200
    assert any("no established baseline" in reason for reason in r.get_json()["reasons"])


def test_health_reports_ok_when_baseline_not_configured(client, monkeypatch) -> None:
    monkeypatch.delenv("DUSK_GATE_BASELINE_PATH", raising=False)
    api.reset_gate_engine()
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_health_reports_degraded_when_baseline_path_is_broken(client, monkeypatch) -> None:
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", "/does/not/exist.json")
    api.reset_gate_engine()
    r = client.get("/health")
    assert r.status_code == 503
    body = r.get_json()
    assert body["status"] == "degraded"
    assert "baseline_error" in body


def test_health_baseline_error_is_stable_code_not_raw_exception(client, monkeypatch) -> None:
    """Health must return a stable code, not a raw exception string with paths."""
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", "/does/not/exist.json")
    api.reset_gate_engine()
    body = client.get("/health").get_json()
    assert body["baseline_error"] == "BASELINE_LOAD_FAILED"


def test_gate_requires_explicit_anonymous_opt_in_when_no_key_set(client, monkeypatch) -> None:
    """Without DUSK_GATE_API_KEY, requests must be refused unless DUSK_GATE_ALLOW_ANONYMOUS=true."""
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    monkeypatch.delenv("DUSK_GATE_ALLOW_ANONYMOUS", raising=False)
    r = client.post("/v1/gate", json=_action_payload(port=443))
    assert r.status_code == 401


def test_health_offense_memory_error_is_stable_code_not_raw_exception(
    client, tmp_path, monkeypatch
) -> None:
    """Health offense_memory_error must be a stable reason code, not a raw exception string."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("blocking file", encoding="utf-8")
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(blocker / "offense-memory.json"))
    reset_config()
    api.reset_gate_engine()
    payload = _action_payload(agent_id="ghost-agent", target="fw-restricted")
    client.post("/v1/gate", json=payload)
    api._get_gate_engine().offense_memory.flush()
    body = client.get("/health").get_json()
    assert body["offense_memory_error"] == "OFFENSE_MEMORY_PERSIST_FAILED"


def test_gate_still_serves_requests_when_baseline_is_broken(client, monkeypatch) -> None:
    """/v1/gate degrades (every agent unknown) rather than refusing outright."""
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", "/does/not/exist.json")
    api.reset_gate_engine()
    r = client.post("/v1/gate", json=_action_payload())
    assert r.status_code == 200
    assert any("no established baseline" in reason for reason in r.get_json()["reasons"])


def test_health_reports_degraded_when_offense_memory_persistence_fails(
    client, tmp_path, monkeypatch
) -> None:
    """A silently failing repeat-offense write must be visible to monitoring, not just logs."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("blocking file", encoding="utf-8")
    bad_storage = blocker / "offense-memory.json"
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(bad_storage))
    reset_config()
    api.reset_gate_engine()

    payload = _action_payload(agent_id="ghost-agent", target="fw-restricted")
    r = client.post("/v1/gate", json=payload)
    assert r.get_json()["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    api._get_gate_engine().offense_memory.flush()

    health = client.get("/health")
    assert health.status_code == 503
    body = health.get_json()
    assert body["status"] == "degraded"
    assert "offense_memory_error" in body


def test_gate_enforce_mode_via_config_blocks_instead_of_would_block(client, monkeypatch) -> None:
    monkeypatch.setenv("DUSK_ENFORCE", "true")
    reset_config()
    api.reset_gate_engine()
    r = client.post(
        "/v1/gate", json=_action_payload(agent_id="ghost-agent", target="fw-restricted")
    )
    assert r.get_json()["verdict"] == "BLOCK"


def test_gate_allow_fires_decision_and_report_but_not_alert(client) -> None:
    with (
        patch("dusk.trace.n8n_client.fire_decision") as mock_decision,
        patch("dusk.trace.n8n_client.fire_report") as mock_report,
        patch("dusk.trace.n8n_client.fire_alert") as mock_alert,
    ):
        r = client.post("/v1/gate", json=_action_payload(port=443))

    assert r.get_json()["verdict"] == "ALLOW"
    mock_decision.assert_called_once()
    mock_report.assert_called_once()
    mock_alert.assert_not_called()


def test_gate_refusal_fires_all_three_webhooks(client) -> None:
    with (
        patch("dusk.trace.n8n_client.fire_decision") as mock_decision,
        patch("dusk.trace.n8n_client.fire_report") as mock_report,
        patch("dusk.trace.n8n_client.fire_alert") as mock_alert,
    ):
        r = client.post(
            "/v1/gate", json=_action_payload(agent_id="ghost-agent", target="fw-restricted")
        )

    assert r.get_json()["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    mock_decision.assert_called_once()
    mock_report.assert_called_once()
    mock_alert.assert_called_once()


def test_gate_webhook_payload_includes_action_context(client) -> None:
    with patch("dusk.trace.n8n_client.fire_decision") as mock_decision:
        client.post("/v1/gate", json=_action_payload(port=443))

    payload = mock_decision.call_args[0][0]
    assert payload["agent_id"] == "netops-agent"
    assert payload["action_type"] == "firewall_rule_change"
    assert payload["target"] == "fw-corp-https"
    assert set(CONTRACT_FIELDS) <= set(payload)


def test_recorded_decision_carries_real_risk_flags_and_similar_ids(client) -> None:
    """TraceDecision.risk_flags and .similar_decision_ids must reflect what the
    response actually computed, not stay at their dataclass defaults -- both
    were previously always empty on the stored object even when the response
    carried real values (similar_decision_ids) or real reasons existed
    (risk_flags). find_similar_cached needs at least 2 prior decisions before
    it returns anything, so this fires three near-identical actions and
    checks the third."""
    client.post("/v1/gate", json=_action_payload(port=443))
    second = client.post("/v1/gate", json=_action_payload(port=443)).get_json()
    third_response = client.post("/v1/gate", json=_action_payload(port=443))
    third = third_response.get_json()

    stored_third = api._decision_history[-1][0]
    assert stored_third.id == third["trace_id"]
    assert stored_third.similar_decision_ids == third["similar_decision_ids"]
    if third["reasons"]:
        assert stored_third.risk_flags == third["reasons"]
        assert stored_third.risk_flags != []

    # The third, near-identical action should find at least the second as a match.
    assert third["similar_decision_ids"] != []
    assert second["trace_id"] in third["similar_decision_ids"]


def test_recorded_decision_carries_the_real_verdict(client) -> None:
    """TraceDecision.verdict must reflect the actual gate verdict, not be left
    at its dataclass default and reconstructed later from a hardcoded score cutoff."""
    response = client.post("/v1/gate", json=_action_payload(port=443))
    body = response.get_json()

    stored = api._decision_history[-1][0]
    assert stored.verdict == body["verdict"]
    assert stored.verdict != ""


def test_decision_history_per_agent_cap_protects_a_quiet_agent(client) -> None:
    """A noisy agent flooding the gate must not evict a quiet agent's decision
    history entirely -- see api._DECISION_HISTORY_PER_AGENT_CAP."""
    quiet_payload = _action_payload(agent_id="quiet-agent", target="fw-corp-https", port=443)
    client.post("/v1/gate", json=quiet_payload)

    noisy_payload = _action_payload(agent_id="noisy-agent", target="fw-corp-https", port=443)
    for _ in range(250):  # past both the per-agent sub-cap and the 200-entry total cap
        client.post("/v1/gate", json=noisy_payload)

    agent_ids = {decision.agent_id for decision, _vec in api._decision_history}
    assert "quiet-agent" in agent_ids
    noisy_count = sum(
        1 for decision, _vec in api._decision_history if decision.agent_id == "noisy-agent"
    )
    assert noisy_count <= 40


def test_repeated_refused_action_scores_at_least_as_high_the_second_time(client) -> None:
    """End-to-end repeat-offense signal through the live /v1/gate handler."""
    payload = _action_payload(agent_id="ghost-agent", target="fw-restricted")
    first = client.post("/v1/gate", json=payload).get_json()
    second = client.post("/v1/gate", json=payload).get_json()

    assert first["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert second["score"] >= first["score"]
    assert any(first["trace_id"] in reason for reason in second["reasons"])


# ---------------------------------------------------------------------------
# Issue #135 – IAM and role escalation scenarios (Groups D-01 through D-04)
# ---------------------------------------------------------------------------

_ROLE_BASELINE_PATH = str(FIXTURES / "actions_role_baseline.json")


def _role_action_payload(
    agent_id: str = "iam-agent",
    target: str = "ra-netops-viewer",
    **after: object,
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "timestamp": "2023-11-14T22:20:00+00:00",
        "action_type": "role_assignment",
        "target": target,
        "change": {"before": None, "after": dict(after) if after else None},
        "source": "generic",
        "raw_ref": "evt-iam-test",
    }


def test_known_iam_agent_normal_role_assignment_is_allowed(client, monkeypatch) -> None:
    """D-01: iam-agent assigning a baseline role returns ALLOW."""
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", _ROLE_BASELINE_PATH)
    reset_config()
    api.reset_gate_engine()

    r = client.post("/v1/gate", json=_role_action_payload(role="viewer"))
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] == "ALLOW"


def test_known_iam_agent_owner_escalation_is_refused(client, monkeypatch) -> None:
    """D-02: iam-agent assigning 'owner' is refused; T1098 in MITRE; blast_radius high."""
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", _ROLE_BASELINE_PATH)
    reset_config()
    api.reset_gate_engine()

    r = client.post(
        "/v1/gate",
        json=_role_action_payload(target="ra-corp-escalation", role="owner"),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert any("T1098" in m for m in data["mitre_attack"])
    assert data["blast"] == "high"
    assert any(
        "owner" in reason.lower() or "sensitive" in reason.lower() for reason in data["reasons"]
    )


def test_unknown_agent_role_assignment_is_refused(client) -> None:
    """D-03: unknown agent performing privileged role_assignment is refused.

    An unknown agent scores 0.5 (unknown-agent weight). Adding a privileged
    role like 'owner' (a sensitive value, +0.35) pushes the total to 0.85,
    which is above the 0.6 gate_block_threshold.
    """
    r = client.post(
        "/v1/gate",
        json=_role_action_payload(agent_id="rogue-provisioner", target="ra-global", role="owner"),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert any("T1098" in m for m in data["mitre_attack"])


def test_role_escalation_to_admin_has_high_blast_radius(client) -> None:
    """D-04: change payload containing 'admin' yields blast_radius high and T1098."""
    r = client.post(
        "/v1/gate",
        json=_role_action_payload(agent_id="rogue-agent", target="ra-global", role="admin"),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["blast"] == "high"
    assert any("T1098" in m for m in data["mitre_attack"])
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}


def test_unknown_agent_any_role_assignment_is_refused(client) -> None:
    """D-05: unknown agent performing any role_assignment is refused (issue #135).

    Prior to the _W_UNKNOWN_ROLE_ASSIGNMENT fix, an unknown agent assigning a
    non-sensitive role ("viewer") scored exactly 0.5 (_W_UNKNOWN_AGENT only),
    which is below gate_block_threshold=0.6 and produced ALLOW.  Issue #135
    requires that ALL unknown-agent role_assignments be refused regardless of
    role name.  The fix adds _W_UNKNOWN_ROLE_ASSIGNMENT=0.15, making the
    minimum score for this path 0.65 (> 0.6).

    Scoring with viewer + non-sensitive target:
      _W_UNKNOWN_AGENT=0.50  (agent not in baseline)
      _W_UNKNOWN_ROLE_ASSIGNMENT=0.15  (any role_assignment from unknown agent)
      = 0.65 > gate_block_threshold=0.60 -> WOULD-BLOCK
    """
    r = client.post(
        "/v1/gate",
        json=_role_action_payload(
            agent_id="newcomer-iam-agent",
            target="ra-netops-viewer",
            role="viewer",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}, (
        f"Unknown agent + any role_assignment must be refused (issue #135); "
        f"got {data['verdict']}; score={data['score']}"
    )
    assert data["score"] >= 0.6, f"Score must reach gate_block_threshold=0.6, got {data['score']}"


def test_role_escalation_to_root_has_high_blast_radius(client) -> None:
    """D-06: role_assignment targeting 'root' is refused with high blast radius.

    'root' is in _SENSITIVE_VALUES; unknown agent + root escalation → score 0.85,
    above gate_block_threshold=0.6. Blast radius must be 'high'; T1098 must be present.
    """
    r = client.post(
        "/v1/gate",
        json=_role_action_payload(
            agent_id="rogue-provisioner",
            target="ra-root-escalation",
            role="root",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert data["blast"] == "high"
    assert any("T1098" in m for m in data["mitre_attack"])


def test_unknown_agent_role_assignment_in_enforce_mode_is_blocked(client, monkeypatch) -> None:
    """D-07: DUSK_ENFORCE=true escalates WOULD-BLOCK to BLOCK for sensitive role assignments.

    Unknown agent + 'owner' role → WOULD-BLOCK in watch mode. With DUSK_ENFORCE=true
    the same action must return BLOCK (not WOULD-BLOCK).
    """
    monkeypatch.setenv("DUSK_ENFORCE", "true")
    reset_config()
    api.reset_gate_engine()

    r = client.post(
        "/v1/gate",
        json=_role_action_payload(
            agent_id="rogue-provisioner",
            target="ra-global",
            role="owner",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] == "BLOCK", (
        f"Enforce mode must escalate WOULD-BLOCK to BLOCK; "
        f"got {data['verdict']}; score={data['score']}"
    )


# ---------------------------------------------------------------------------
# Issue #139 – Sensitive data export and deletion coverage (Groups C-04, C-05)
# ---------------------------------------------------------------------------

_DATA_BASELINE_PATH = str(FIXTURES / "actions_data_agent_baseline.json")


def _data_action_payload(
    agent_id: str = "data-agent",
    target: str = "bucket-approved-reports",
    action_type: str = "unknown",
    **after: object,
) -> dict[str, object]:
    return {
        "agent_id": agent_id,
        "timestamp": "2023-11-14T22:20:00+00:00",
        "action_type": action_type,
        "target": target,
        "change": {"before": None, "after": dict(after) if after else None},
        "source": "generic",
        "raw_ref": "evt-data-test",
    }


def test_data_export_to_unexpected_destination_is_refused(client, monkeypatch) -> None:
    """C-04 scripted: data-agent exporting to an all-data bucket is refused with high blast.

    Baseline has 'data-agent' touching only 'bucket-approved-*' with read/list
    ops.  A new target 'bucket-all-customer-data' introduces new tokens (all,
    customer, data) and 'all' is in _SENSITIVE_TOKENS (+0.35 sensitive signal).
    Combined with new-tokens (+0.2) and new-change-values (+0.25) the score
    reaches 0.80, above the 0.6 gate_block_threshold.
    """
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", _DATA_BASELINE_PATH)
    reset_config()
    api.reset_gate_engine()

    r = client.post(
        "/v1/gate",
        json=_data_action_payload(
            target="bucket-all-customer-data",
            destination="s3://external-corp/exfil/",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert data["blast"] == "high"


def test_unknown_agent_deletion_of_audit_target_is_refused(client) -> None:
    """C-05 scripted: unknown agent deleting a restricted audit target is refused.

    Unknown agent scores 0.5 (_W_UNKNOWN_AGENT). The target 'audit-log-restricted'
    contains 'restricted' which is in _SENSITIVE_TOKENS, pushing the total to 0.85
    and above the 0.6 gate_block_threshold. Blast radius is 'high' due to the
    sensitive token presence.
    """
    r = client.post(
        "/v1/gate",
        json=_data_action_payload(
            agent_id="unknown-cleanup-bot",
            target="audit-log-restricted",
            action_type="unknown",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    assert data["blast"] == "high"
    assert data["reasons"]


def test_known_agent_with_deletion_baseline_is_allowed(client, monkeypatch) -> None:
    """C-06: data-agent deleting a baseline target class returns ALLOW.

    The baseline (actions_data_agent_baseline.json) now includes deletion entries
    (after=null) for bucket-approved-* targets.  Submitting the same deletion
    action for the same known agent must score below the 0.6 gate_block_threshold
    and return ALLOW.
    """
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", _DATA_BASELINE_PATH)
    reset_config()
    api.reset_gate_engine()

    r = client.post(
        "/v1/gate",
        json={
            "agent_id": "data-agent",
            "timestamp": "2023-11-14T22:20:00+00:00",
            "action_type": "unknown",
            "target": "bucket-approved-reports",
            "change": {"before": {"status": "expired"}, "after": None},
            "source": "generic",
            "raw_ref": "evt-data-deletion-test",
        },
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["verdict"] == "ALLOW", (
        f"Known data-agent deletion of baseline target must be ALLOW; "
        f"got {data['verdict']}; score={data['score']}, reasons={data['reasons']}"
    )


def test_data_export_unknown_action_carries_mitre_mapping(client) -> None:
    """Export action on unknown agent returns a MITRE technique (T1078 for unknown type)."""
    r = client.post(
        "/v1/gate",
        json=_data_action_payload(
            agent_id="exfil-agent",
            target="bucket-all-data",
            action_type="unknown",
        ),
    )
    data = r.get_json()
    assert r.status_code == 200
    assert data["mitre_attack"]
    assert any("T1078" in m for m in data["mitre_attack"])


def test_offense_memory_persists_across_a_simulated_restart(client, tmp_path, monkeypatch) -> None:
    """The durability requirement: block an agent, restart the process, confirm
    the next similar action still scores higher because of the earlier block."""
    storage = tmp_path / "offense-memory.json"
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(storage))
    reset_config()
    api.reset_gate_engine()

    payload = _action_payload(agent_id="ghost-agent", target="fw-restricted")
    before_restart = client.post("/v1/gate", json=payload).get_json()
    assert before_restart["verdict"] in {"WOULD-BLOCK", "BLOCK"}
    # The write lands on a background thread; wait for it before asserting on disk.
    api._get_gate_engine().offense_memory.flush()
    assert storage.exists()

    # Simulate a process restart: drop the cached engine, force a fresh load
    # from disk, exactly like a new process would.
    api.reset_gate_engine()

    after_restart = client.post("/v1/gate", json=payload).get_json()
    assert after_restart["score"] >= before_restart["score"]
    assert any(before_restart["trace_id"] in reason for reason in after_restart["reasons"])
