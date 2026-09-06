"""Cryptographic provider evidence boundary tests."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dusk_control_plane.identity import IdentityKind, Principal
from dusk_control_plane.policy import EvidenceRejectedError, EvidenceSubmission
from dusk_control_plane.provider_evidence import (
    InMemoryReplayStore,
    SignedProviderEvidenceVerifier,
    TrustedEvidenceSource,
    signing_bytes,
)

NOW = datetime(2026, 9, 4, 10, 0, tzinfo=UTC)


def _principal(tenant: str = "tenant-a") -> Principal:
    return Principal("issuer", "workload", tenant, IdentityKind.WORKLOAD, workload_id="agent-a")


def _submission(**changes: object) -> EvidenceSubmission:
    payload = {"source_boundary": "account-a", "target_boundary": "account-a"}
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    base = EvidenceSubmission(
        domain="cloud",
        source_identity="aws-collector",
        provenance="aws:cloudtrail:management-event",
        observed_at=NOW,
        digest=f"sha256:{digest}",
        payload=payload,
        tenant_id="tenant-a",
        key_id="key-2026-09",
        nonce="event-000000000001",
        signature="pending-signature",
    )
    return replace(base, **changes)


def _signed(private_key: Ed25519PrivateKey, **changes: object) -> EvidenceSubmission:
    unsigned = _submission(**changes)
    encoded = base64.urlsafe_b64encode(private_key.sign(signing_bytes(unsigned))).rstrip(b"=")
    return replace(unsigned, signature=encoded.decode())


def _verifier(
    private_key: Ed25519PrivateKey,
    *,
    extra_keys: dict[str, Ed25519PrivateKey] | None = None,
) -> SignedProviderEvidenceVerifier:
    keys = {"key-2026-09": private_key.public_key()}
    keys.update({key_id: key.public_key() for key_id, key in (extra_keys or {}).items()})
    source = TrustedEvidenceSource(
        source_identity="aws-collector",
        tenant_id="tenant-a",
        domains=frozenset({"action", "cloud", "infrastructure"}),
        keys=keys,
    )
    return SignedProviderEvidenceVerifier((source,), InMemoryReplayStore())


@pytest.mark.anyio
async def test_valid_tenant_bound_provider_evidence_is_confirmed() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = _verifier(private_key)

    verified = await verifier.verify(_signed(private_key), _principal())

    assert verified.trust == "CONFIRMED"
    assert verified.domain == "cloud"
    assert verifier.live_domains == frozenset({"action", "cloud", "infrastructure"})


@pytest.mark.anyio
async def test_cross_tenant_evidence_is_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = _verifier(private_key)

    with pytest.raises(EvidenceRejectedError, match="tenant"):
        await verifier.verify(_signed(private_key), _principal("tenant-b"))


@pytest.mark.anyio
async def test_payload_or_provenance_tampering_invalidates_signature() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = _verifier(private_key)
    signed = _signed(private_key)

    with pytest.raises(EvidenceRejectedError, match="signature"):
        await verifier.verify(replace(signed, provenance="azure:activity-log"), _principal())


@pytest.mark.anyio
async def test_provider_event_replay_is_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = _verifier(private_key)
    signed = _signed(private_key)
    await verifier.verify(signed, _principal())

    with pytest.raises(EvidenceRejectedError, match="already been consumed"):
        await verifier.verify(signed, _principal())


@pytest.mark.anyio
async def test_unprovisioned_domain_and_stale_key_are_rejected() -> None:
    private_key = Ed25519PrivateKey.generate()
    verifier = _verifier(private_key)

    with pytest.raises(EvidenceRejectedError, match="source or domain"):
        await verifier.verify(_signed(private_key, domain="kubernetes"), _principal())
    with pytest.raises(EvidenceRejectedError, match="key is not active"):
        await verifier.verify(_signed(private_key, key_id="retired-key"), _principal())


@pytest.mark.anyio
async def test_active_rotation_key_is_accepted() -> None:
    current = Ed25519PrivateKey.generate()
    next_key = Ed25519PrivateKey.generate()
    verifier = _verifier(current, extra_keys={"key-2026-10": next_key})

    verified = await verifier.verify(
        _signed(next_key, key_id="key-2026-10", nonce="event-000000000002"), _principal()
    )

    assert verified.source_identity == "aws-collector"
