"""Retention and privacy-export boundary unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from dusk_control_plane.audit import redact_for_storage
from dusk_control_plane.config import Settings
from dusk_control_plane.dependencies import AppContainer
from dusk_control_plane.identity import AuthorizationDeniedError, IdentityKind, Principal, Role
from dusk_control_plane.privacy import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_DECISION_RETENTION_DAYS,
    ExportPosition,
    PrivacyExportService,
    RetentionPolicy,
    RetentionPolicyService,
    RetentionService,
)


@pytest.mark.anyio
async def test_retention_defaults_and_bounds_are_explicit() -> None:
    assert DEFAULT_DECISION_RETENTION_DAYS == 90
    assert DEFAULT_AUDIT_RETENTION_DAYS == 365
    service = RetentionService(None, None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="between 1 and 500"):
        await service.run_once(_administrator(), batch_size=501)


def test_privacy_lifecycle_is_default_off_and_requires_v2_storage() -> None:
    assert Settings().privacy_lifecycle_enabled is False
    assert Settings().retention_batch_size == 100
    with pytest.raises(ValidationError, match="requires v2_enabled and storage_enabled"):
        Settings(privacy_lifecycle_enabled=True)


def test_enabled_privacy_lifecycle_requires_audit_signer_dependency() -> None:
    settings = Settings(
        v2_enabled=True,
        oidc_issuer="https://identity.example.test/",
        oidc_audience="dusk-control-plane",
        oidc_jwks_uri="https://identity.example.test/jwks.json",
        storage_enabled=True,
        database_url="postgresql+asyncpg://service:secret@database.test/control",
        privacy_lifecycle_enabled=True,
    )

    class DatabaseStub:
        async def probe(self) -> None:
            return None

    with pytest.raises(ValueError, match="requires database and audit signer"):
        AppContainer.build(
            settings=settings,
            database=DatabaseStub(),  # type: ignore[arg-type]
        )


def test_tenant_retention_policy_is_strictly_bounded() -> None:
    assert RetentionPolicy(
        decision_retention_days=90,
        audit_retention_days=365,
        legal_hold=False,
    ).model_dump() == {
        "decision_retention_days": 90,
        "audit_retention_days": 365,
        "legal_hold": False,
    }
    with pytest.raises(ValidationError):
        RetentionPolicy(
            decision_retention_days=0,
            audit_retention_days=3651,
            legal_hold=False,
        )


def test_export_position_requires_utc() -> None:
    with pytest.raises(ValueError, match="must use UTC"):
        ExportPosition(created_at=datetime(2026, 9, 4), decision_id=uuid4())
    value = ExportPosition(created_at=datetime(2026, 9, 4, tzinfo=UTC), decision_id=uuid4())
    assert value.created_at.tzinfo is UTC


@pytest.mark.anyio
@pytest.mark.parametrize(
    "principal",
    [
        Principal("issuer", "workload", str(uuid4()), IdentityKind.WORKLOAD),
        Principal(
            "issuer",
            "analyst",
            str(uuid4()),
            IdentityKind.HUMAN,
            roles=frozenset({Role.ANALYST}),
        ),
    ],
)
async def test_export_requires_human_tenant_administrator(principal: Principal) -> None:
    service = PrivacyExportService(None)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationDeniedError):
        await service.export_page(principal)
    retention_service = RetentionService(None, None)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationDeniedError):
        await retention_service.run_once(principal)
    policy_service = RetentionPolicyService(None, None)  # type: ignore[arg-type]
    with pytest.raises(AuthorizationDeniedError):
        await policy_service.configure(
            principal,
            RetentionPolicy(
                decision_retention_days=90,
                audit_retention_days=365,
                legal_hold=True,
            ),
        )


@pytest.mark.parametrize(
    "secret",
    [
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE",
        "eyJhbGciOiJSUzI1NiJ9" + "." + "eyJzdWIiOiJzZWNyZXQifQ" + "." + "signaturevalue",
        "postgresql://operator:super-secret@database.internal/control",
        "-----BEGIN PRIVATE KEY-----",
    ],
)
def test_recursive_redaction_masks_secret_bearing_values_under_innocent_keys(
    secret: str,
) -> None:
    result = redact_for_storage({"attributes": [{"value": secret}]})
    assert result == {"attributes": [{"value": "[REDACTED]"}]}
    assert secret not in repr(result)


def test_prohibited_payload_classes_are_never_storage_or_export_candidates() -> None:
    source = {
        "raw_request": {"body": "CANARY_RAW_REQUEST"},
        "prompt": "CANARY_PROMPT",
        "provider_payload": {"response": "CANARY_PROVIDER_PAYLOAD"},
        "response_body": "CANARY_RESPONSE_BODY",
        "safe": "retained",
    }
    result = redact_for_storage(source)
    assert result == {
        "raw_request": "[REDACTED]",
        "prompt": "[REDACTED]",
        "provider_payload": "[REDACTED]",
        "response_body": "[REDACTED]",
        "safe": "retained",
    }
    assert "CANARY" not in repr(result)


def _administrator() -> Principal:
    return Principal(
        "issuer",
        "administrator",
        str(uuid4()),
        IdentityKind.HUMAN,
        roles=frozenset({Role.ADMINISTRATOR}),
    )
