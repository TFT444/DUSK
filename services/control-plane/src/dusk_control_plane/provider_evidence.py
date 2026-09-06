"""Cryptographic trust boundary for cloud and Kubernetes evidence."""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.dialects.postgresql import insert

from dusk_control_plane.identity import Principal
from dusk_control_plane.policy import (
    EvidenceRejectedError,
    EvidenceSubmission,
    EvidenceTrust,
    VerifiedEvidence,
)
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import EvidenceReplayClaim


class ReplayStore(Protocol):
    """Atomically claim a provider event identifier exactly once."""

    async def claim(
        self, *, tenant_id: str, source_identity: str, nonce: str, observed_at: datetime
    ) -> bool: ...


@dataclass(frozen=True)
class TrustedEvidenceSource:
    """One provisioned telemetry signer and its permitted security boundary."""

    source_identity: str
    tenant_id: str
    domains: frozenset[str]
    keys: Mapping[str, Ed25519PublicKey]

    def __post_init__(self) -> None:
        if not self.source_identity or not self.tenant_id or not self.domains or not self.keys:
            raise ValueError("trusted evidence source fields must not be empty")
        if self.domains - {"action", "approval", "cloud", "kubernetes", "infrastructure"}:
            raise ValueError("trusted evidence source contains an unsupported domain")


@dataclass
class InMemoryReplayStore:
    """Process-local replay control for unit tests; not suitable for production."""

    _claims: set[tuple[str, str, str]] = field(default_factory=set)

    async def claim(
        self, *, tenant_id: str, source_identity: str, nonce: str, observed_at: datetime
    ) -> bool:
        del observed_at
        key = (tenant_id, source_identity, nonce)
        if key in self._claims:
            return False
        self._claims.add(key)
        return True


class SignedProviderEvidenceVerifier:
    """Verify tenant-bound Ed25519 envelopes from provisioned provider collectors."""

    def __init__(
        self,
        sources: tuple[TrustedEvidenceSource, ...],
        replay_store: ReplayStore,
    ) -> None:
        identities = [source.source_identity for source in sources]
        if len(identities) != len(set(identities)):
            raise ValueError("trusted evidence source identities must be unique")
        self._sources = {source.source_identity: source for source in sources}
        self._replay_store = replay_store
        self._live_domains = frozenset(domain for source in sources for domain in source.domains)

    @property
    def live_domains(self) -> frozenset[str]:
        return self._live_domains

    async def verify(
        self, submission: EvidenceSubmission, principal: Principal
    ) -> VerifiedEvidence:
        source = self._sources.get(submission.source_identity)
        if source is None or submission.domain not in source.domains:
            raise EvidenceRejectedError("evidence source or domain is not provisioned")
        if submission.tenant_id != principal.tenant_id or source.tenant_id != principal.tenant_id:
            raise EvidenceRejectedError("evidence tenant does not match authenticated tenant")
        if not submission.key_id or not submission.nonce or not submission.signature:
            raise EvidenceRejectedError("signed evidence metadata is required")
        key = source.keys.get(submission.key_id)
        if key is None:
            raise EvidenceRejectedError("evidence signing key is not active")
        signature = _decode_signature(submission.signature)
        try:
            key.verify(signature, signing_bytes(submission))
        except InvalidSignature as exc:
            raise EvidenceRejectedError("evidence signature is invalid") from exc
        claimed = await self._replay_store.claim(
            tenant_id=principal.tenant_id,
            source_identity=submission.source_identity,
            nonce=submission.nonce,
            observed_at=submission.observed_at,
        )
        if not claimed:
            raise EvidenceRejectedError("evidence event has already been consumed")
        return VerifiedEvidence(
            domain=submission.domain,
            source_identity=submission.source_identity,
            trust=EvidenceTrust.CONFIRMED,
            payload=submission.payload,
        )


class PostgresReplayStore:
    """Durable, horizontally safe replay claims backed by a unique index."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def claim(
        self, *, tenant_id: str, source_identity: str, nonce: str, observed_at: datetime
    ) -> bool:
        statement = (
            insert(EvidenceReplayClaim)
            .values(
                tenant_id=tenant_id,
                source_identity=source_identity,
                nonce=nonce,
                observed_at=observed_at,
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "source_identity", "nonce"])
            .returning(EvidenceReplayClaim.id)
        )
        async with self._database.transaction() as session:
            return (await session.scalar(statement)) is not None


def signing_bytes(submission: EvidenceSubmission) -> bytes:
    """Return the versioned canonical envelope signed by a provider collector."""
    if not all((submission.tenant_id, submission.key_id, submission.nonce)):
        raise EvidenceRejectedError("signed evidence metadata is required")
    envelope = {
        "digest": submission.digest,
        "domain": submission.domain,
        "key_id": submission.key_id,
        "nonce": submission.nonce,
        "observed_at": submission.observed_at.isoformat(),
        "payload": submission.payload,
        "provenance": submission.provenance,
        "source_identity": submission.source_identity,
        "tenant_id": submission.tenant_id,
        "version": "dusk-provider-evidence-v1",
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _decode_signature(value: str) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise EvidenceRejectedError("evidence signature encoding is invalid") from exc
    if len(decoded) != 64:
        raise EvidenceRejectedError("evidence signature length is invalid")
    return decoded
