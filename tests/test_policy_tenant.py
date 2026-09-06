"""Behavioral tests for DUSK-TENANT-001 through DUSK-TENANT-008.

Each rule is covered by:
- A denial scenario (cross-tenant / malicious case).
- A benign case (same-tenant, must not fire).
- A bypass case (omitted tenant fields must not grant access).
- A missing-evidence case (UNKNOWN + consequential => DENY via fail-closed).
- A watch-mode test (non-enforced copy does not fire).
- An enforce-mode test (enforced copy fires and returns DENY).
- A downstream state assertion: verdict is DENY before the action executes.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from dusk.policies import Decision, load_enterprise_pack
from dusk.policies.engine import load_policy_pack

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enterprise_pack():
    return load_enterprise_pack()


def _write_pack(tmp_path: Path, raw: object) -> Path:
    path = tmp_path / "pack.yaml"
    path.write_text(yaml.safe_dump(raw), encoding="utf-8")
    return path


def _single_rule_pack(tmp_path: Path, rule: dict) -> object:
    raw = {
        "name": "test-pack",
        "version": "1.0.0",
        "default_decision": "ALLOW",
        "rules": [rule],
    }
    return load_policy_pack(_write_pack(tmp_path, raw))


def _tenant_rule_base(rule_id: str, match: list, status: str = "enforced") -> dict:
    return {
        "id": rule_id,
        "version": "1.0.0",
        "title": f"Test {rule_id}",
        "category": "tenant",
        "severity": "critical",
        "decision": "DENY",
        "status": status,
        "owner": "DUSK Security",
        "rationale": f"Test rationale for {rule_id}.",
        "frameworks": ["OWASP-AGENTIC", "NIST-AI-RMF"],
        "match": match,
        "prerequisites": [],
        "tests": ["allow", "deny", "bypass", "missing-evidence"],
    }


# ---------------------------------------------------------------------------
# DUSK-TENANT-001: Cross-tenant read
# ---------------------------------------------------------------------------


class TestTenant001CrossTenantRead:
    """Agent reads a resource owned by a different tenant."""

    def test_denial_cross_tenant_read(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-001" in {r.id for r in result.matched_rules}

    def test_benign_same_tenant_read(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-a"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-001" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_resource_owner(self) -> None:
        """Omitting resource_owner must not bypass the rule via fail-closed on consequential."""
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b", "_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_is_deny_before_action_executes(self) -> None:
        """Downstream state must not be altered: verdict DENY returned pre-execution."""
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        # matched_rules proves the rule fired (not a silent allow)
        assert any(r.id == "DUSK-TENANT-001" for r in result.matched_rules)

    def test_unrelated_action_type_does_not_match_tenant_001(self) -> None:
        """TENANT-001 is scoped to read actions; unrelated actions must not match it."""
        context = {
            "action": {"type": "email.send"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-001" not in {r.id for r in result.matched_rules}, (
            "TENANT-001 must not fire on email.send — it is scoped to read actions only"
        )

    def test_cross_tenant_write_attributed_to_tenant_002_not_tenant_001(self) -> None:
        """Cross-tenant writes must match TENANT-002 only, not TENANT-001."""
        context = {
            "action": {"type": "resource.write"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        matched = {r.id for r in result.matched_rules}
        assert "DUSK-TENANT-001" not in matched, (
            "TENANT-001 (read rule) must not fire on resource.write"
        )
        assert "DUSK-TENANT-002" in matched, (
            "TENANT-002 (write rule) must fire on cross-tenant resource.write"
        )

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-001",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW
        assert all(r.id != "DUSK-TENANT-001" for r in result.matched_rules)

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-001",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-001" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-002: Cross-tenant write
# ---------------------------------------------------------------------------


class TestTenant002CrossTenantWrite:
    """Agent writes or modifies a resource owned by a different tenant."""

    def test_denial_cross_tenant_write(self) -> None:
        context = {
            "action": {"type": "resource.write"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-c"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-002" in {r.id for r in result.matched_rules}

    def test_benign_same_tenant_write(self) -> None:
        context = {
            "action": {"type": "resource.write"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-a"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-002" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_fields_consequential(self) -> None:
        context = {
            "action": {"type": "resource.write", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "resource.write", "consequential": True},
            "identity": {"tenant_id": "tenant-x"},
            "tenant": {"resource_owner": "tenant-y", "_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "resource.write"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-002" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-002",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
                {
                    "field": "action.type",
                    "operator": "in",
                    "value": [
                        "resource.write",
                        "resource.update",
                        "resource.delete",
                        "resource.patch",
                    ],
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "action": {"type": "resource.write", "consequential": False},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-002",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
                {
                    "field": "action.type",
                    "operator": "in",
                    "value": [
                        "resource.write",
                        "resource.update",
                        "resource.delete",
                        "resource.patch",
                    ],
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "action": {"type": "resource.write"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-002" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-003: Cross-tenant search or vector retrieval
# ---------------------------------------------------------------------------


class TestTenant003CrossTenantSearch:
    """Agent performs search or vector retrieval without a tenant-scoped filter."""

    def test_denial_retrieval_filter_mismatch(self) -> None:
        context = {
            "action": {"type": "vector.search"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-003" in {r.id for r in result.matched_rules}

    def test_benign_matching_retrieval_filter(self) -> None:
        context = {
            "action": {"type": "vector.search"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-a"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-003" not in {r.id for r in result.matched_rules}

    def test_bypass_no_filter_consequential(self) -> None:
        context = {
            "action": {"type": "vector.search", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "vector.search", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-b", "_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "vector.search"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-003" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-003",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.retrieval_filter_tenant", "operator": "exists", "value": True},
                {
                    "field": "tenant.retrieval_filter_tenant",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-003",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.retrieval_filter_tenant", "operator": "exists", "value": True},
                {
                    "field": "tenant.retrieval_filter_tenant",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"retrieval_filter_tenant": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-003" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-004: Cross-tenant cache or memory access
# ---------------------------------------------------------------------------


class TestTenant004CrossTenantCache:
    """Agent accesses a storage partition belonging to a different tenant."""

    def test_denial_storage_partition_mismatch(self) -> None:
        context = {
            "action": {"type": "cache.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {
                "storage_partition": "partition-b",
                "identity_partition": "partition-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-004" in {r.id for r in result.matched_rules}

    def test_benign_same_partition(self) -> None:
        context = {
            "action": {"type": "cache.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {
                "storage_partition": "partition-a",
                "identity_partition": "partition-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-004" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_partition_consequential(self) -> None:
        context = {
            "action": {"type": "cache.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "cache.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {
                "storage_partition": "partition-b",
                "identity_partition": "partition-a",
                "_evidence": "UNKNOWN",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "cache.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {
                "storage_partition": "partition-b",
                "identity_partition": "partition-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-004" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-004",
            [
                {"field": "tenant.storage_partition", "operator": "exists", "value": True},
                {"field": "tenant.identity_partition", "operator": "exists", "value": True},
                {
                    "field": "tenant.storage_partition",
                    "operator": "not_equals",
                    "value": "$tenant.identity_partition",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"storage_partition": "partition-b", "identity_partition": "partition-a"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-004",
            [
                {"field": "tenant.storage_partition", "operator": "exists", "value": True},
                {"field": "tenant.identity_partition", "operator": "exists", "value": True},
                {
                    "field": "tenant.storage_partition",
                    "operator": "not_equals",
                    "value": "$tenant.identity_partition",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"storage_partition": "partition-b", "identity_partition": "partition-a"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-004" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-005: Cross-tenant audit access
# ---------------------------------------------------------------------------


class TestTenant005CrossTenantAudit:
    """Agent reads audit data owned by a different tenant."""

    def test_denial_audit_owner_mismatch(self) -> None:
        context = {
            "action": {"type": "audit.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-005" in {r.id for r in result.matched_rules}

    def test_benign_same_tenant_audit(self) -> None:
        context = {
            "action": {"type": "audit.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-a"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-005" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_owner_consequential(self) -> None:
        context = {
            "action": {"type": "audit.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "audit.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b", "_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "audit.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-005" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-005",
            [
                {"field": "action.type", "operator": "equals", "value": "audit.read"},
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "action": {"type": "audit.read", "consequential": False},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-005",
            [
                {"field": "action.type", "operator": "equals", "value": "audit.read"},
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.resource_owner", "operator": "exists", "value": True},
                {
                    "field": "tenant.resource_owner",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "action": {"type": "audit.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"resource_owner": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-005" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-006: Shared credential use across tenants
# ---------------------------------------------------------------------------


class TestTenant006SharedCredential:
    """A credential bound to a different tenant must not be used."""

    def test_denial_credential_tenant_mismatch(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-006" in {r.id for r in result.matched_rules}

    def test_benign_credential_same_tenant(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-a"},
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-006" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_credential_binding_consequential(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-b", "_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-b"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-006" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-006",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.credential_bound_tenant", "operator": "exists", "value": True},
                {
                    "field": "tenant.credential_bound_tenant",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-006",
            [
                {"field": "identity.tenant_id", "operator": "exists", "value": True},
                {"field": "tenant.credential_bound_tenant", "operator": "exists", "value": True},
                {
                    "field": "tenant.credential_bound_tenant",
                    "operator": "not_equals",
                    "value": "$identity.tenant_id",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "identity": {"tenant_id": "tenant-a"},
            "tenant": {"credential_bound_tenant": "tenant-b"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-006" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-007: Project boundary crossover
# ---------------------------------------------------------------------------


class TestTenant007ProjectBoundary:
    """An agent identity from one project must not access resources in another."""

    def test_denial_project_boundary_crossover(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "project": "project-b",
                "identity_project": "project-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-007" in {r.id for r in result.matched_rules}

    def test_benign_same_project(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "project": "project-a",
                "identity_project": "project-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-007" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_project_fields_consequential(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "tenant": {
                "project": "project-b",
                "identity_project": "project-a",
                "_evidence": "UNKNOWN",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "project": "project-b",
                "identity_project": "project-a",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-007" for r in result.matched_rules)

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-007",
            [
                {"field": "tenant.project", "operator": "exists", "value": True},
                {"field": "tenant.identity_project", "operator": "exists", "value": True},
                {
                    "field": "tenant.project",
                    "operator": "not_equals",
                    "value": "$tenant.identity_project",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"project": "project-b", "identity_project": "project-a"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-007",
            [
                {"field": "tenant.project", "operator": "exists", "value": True},
                {"field": "tenant.identity_project", "operator": "exists", "value": True},
                {
                    "field": "tenant.project",
                    "operator": "not_equals",
                    "value": "$tenant.identity_project",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"project": "project-b", "identity_project": "project-a"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-007" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# DUSK-TENANT-008: Production/non-production crossover
# ---------------------------------------------------------------------------


class TestTenant008EnvCrossover:
    """An agent identity from a non-production environment must not access production."""

    def test_denial_nonprod_to_prod_crossover(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "environment": "production",
                "identity_environment": "staging",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert "DUSK-TENANT-008" in {r.id for r in result.matched_rules}

    def test_benign_prod_to_prod(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "environment": "production",
                "identity_environment": "production",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-008" not in {r.id for r in result.matched_rules}

    def test_benign_dev_to_dev(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "environment": "development",
                "identity_environment": "development",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-008" not in {r.id for r in result.matched_rules}

    def test_bypass_omit_env_fields_consequential(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "tenant": {"_evidence": "UNKNOWN"},
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY

    def test_missing_evidence_unknown_consequential_denied(self) -> None:
        context = {
            "action": {"type": "resource.read", "consequential": True},
            "tenant": {
                "environment": "production",
                "identity_environment": "staging",
                "_evidence": "UNKNOWN",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert result.evidence_degraded is True

    def test_verdict_deny_pre_execution(self) -> None:
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "environment": "production",
                "identity_environment": "development",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-008" for r in result.matched_rules)

    def test_dev_accessing_staging_allowed(self) -> None:
        """Crossover between non-prod environments is permitted (only prod is restricted)."""
        context = {
            "action": {"type": "resource.read"},
            "tenant": {
                "environment": "staging",
                "identity_environment": "development",
            },
        }
        result = _enterprise_pack().evaluate(context)
        assert "DUSK-TENANT-008" not in {r.id for r in result.matched_rules}

    def test_watch_mode_does_not_fire(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-008",
            [
                {
                    "field": "tenant.environment",
                    "operator": "equals",
                    "value": "production",
                },
                {"field": "tenant.identity_environment", "operator": "exists", "value": True},
                {
                    "field": "tenant.identity_environment",
                    "operator": "not_equals",
                    "value": "production",
                },
            ],
            status="implemented",
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"environment": "production", "identity_environment": "staging"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.ALLOW

    def test_enforce_mode_fires(self, tmp_path: Path) -> None:
        rule = _tenant_rule_base(
            "DUSK-TENANT-008",
            [
                {
                    "field": "tenant.environment",
                    "operator": "equals",
                    "value": "production",
                },
                {"field": "tenant.identity_environment", "operator": "exists", "value": True},
                {
                    "field": "tenant.identity_environment",
                    "operator": "not_equals",
                    "value": "production",
                },
            ],
        )
        pack = _single_rule_pack(tmp_path, rule)
        context = {
            "tenant": {"environment": "production", "identity_environment": "staging"},
        }
        result = pack.evaluate(context)
        assert result.decision is Decision.DENY
        assert any(r.id == "DUSK-TENANT-008" for r in result.matched_rules)


# ---------------------------------------------------------------------------
# Cross-rule: tenant category present in enterprise pack
# ---------------------------------------------------------------------------


def test_tenant_category_rules_are_enforced() -> None:
    pack = _enterprise_pack()
    tenant_rules = [r for r in pack.rules if r.category == "tenant"]
    assert len(tenant_rules) == 8
    assert all(r.status == "enforced" for r in tenant_rules)


def test_all_tenant_rule_ids_exist() -> None:
    pack = _enterprise_pack()
    ids = {r.id for r in pack.rules}
    for n in range(1, 9):
        assert f"DUSK-TENANT-00{n}" in ids


def test_tenant_rules_have_correct_frameworks() -> None:
    pack = _enterprise_pack()
    for rule in pack.rules:
        if rule.category == "tenant":
            assert "OWASP-AGENTIC" in rule.frameworks
            assert "NIST-AI-RMF" in rule.frameworks


def test_tenant_rules_are_all_deny() -> None:
    pack = _enterprise_pack()
    for rule in pack.rules:
        if rule.category == "tenant":
            assert rule.decision is Decision.DENY


def test_audit_output_does_not_contain_tenant_values() -> None:
    """Audit trail for a TENANT denial must not echo context values."""
    context = {
        "identity": {"tenant_id": "secret-tenant-id"},
        "tenant": {"resource_owner": "secret-owner-tenant"},
    }
    d = _enterprise_pack().evaluate(context).to_dict()
    output = str(d)
    assert "secret-tenant-id" not in output
    assert "secret-owner-tenant" not in output
