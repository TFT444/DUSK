"""Tenant-scoped decision investigation queries and public response models."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import Select, Text, and_, func, or_, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from dusk_control_plane.identity import Principal
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import (
    AuditEvent,
    CanonicalAction,
    Decision,
    PolicyMatch,
)

DecisionVerdict = Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
PolicyDecision = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL", "NOT_APPLICABLE"]
ResponseStatus = Literal["PENDING", "DELIVERY_PENDING", "DELIVERED", "FAILED", "EXECUTED"]
_CURSOR_VERSION = 1
_MAX_CURSOR_BYTES = 2048
_MAX_SIMILAR_REFERENCES = 5


class DecisionReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DecisionQueryUnavailableError(Exception):
    """PostgreSQL could not complete a bounded decision query."""


class InvalidDecisionCursorError(Exception):
    """The opaque pagination cursor is invalid for this query."""


class DecisionNotFoundError(Exception):
    """No decision is visible under the authenticated tenant."""


class DecisionListQuery(DecisionReadModel):
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=_MAX_CURSOR_BYTES)
    created_from: datetime | None = None
    created_to: datetime | None = None
    verdict: DecisionVerdict | None = None
    policy_decision: PolicyDecision | None = None
    response_status: ResponseStatus | None = None
    evidence_degraded: bool | None = None
    agent_id: str | None = Field(default=None, min_length=1, max_length=256)
    action_type: str | None = Field(default=None, min_length=1, max_length=200)
    search: str | None = Field(default=None, min_length=1, max_length=100)

    @field_validator("created_from", "created_to")
    @classmethod
    def require_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
            raise ValueError("time range must use UTC")
        return value.astimezone(UTC)

    @field_validator("agent_id", "action_type", "search")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("filter contains control characters")
        return value

    @model_validator(mode="after")
    def validate_range(self) -> DecisionListQuery:
        if (
            self.created_from is not None
            and self.created_to is not None
            and self.created_from > self.created_to
        ):
            raise ValueError("created_from must not be later than created_to")
        return self

    def fingerprint(self) -> str:
        values = self.model_dump(mode="json", exclude={"cursor", "limit"})
        return hashlib.sha256(_canonical_bytes(values)).hexdigest()


class DecisionSummary(DecisionReadModel):
    trace_id: UUID
    created_at: datetime
    agent_id: str
    action_type: str | None
    verdict: DecisionVerdict
    behavioral_score: float = Field(ge=0, le=1)
    blast_radius: str
    policy_decision: PolicyDecision
    evidence_degraded: bool | None
    response_status: ResponseStatus
    detail_available: bool


class DecisionPage(DecisionReadModel):
    items: tuple[DecisionSummary, ...]
    next_cursor: str | None
    snapshot_at: datetime


class SafeCanonicalAction(DecisionReadModel):
    agent_id: str
    action_type: str
    target: str
    consequential: bool
    attributes: dict[str, object]


class PolicyMatchDetail(DecisionReadModel):
    rule_id: str
    rule_version: str
    effect: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    metadata: dict[str, object]


class AuditContinuity(DecisionReadModel):
    sequence: int = Field(gt=0)
    event_type: str
    occurred_at: datetime
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    previous_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class SimilarDecisionReference(DecisionReadModel):
    trace_id: UUID
    created_at: datetime
    verdict: DecisionVerdict
    agent_id: str
    action_type: str | None


class DecisionDetail(DecisionSummary):
    input_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    action: SafeCanonicalAction | None
    reasons: tuple[dict[str, object], ...] | None
    mitre_mappings: tuple[dict[str, object], ...] | None
    predicted_next: dict[str, object] | None
    policy_pack_version: str
    policy_matches: tuple[PolicyMatchDetail, ...]
    evidence_state: dict[str, object] | None
    pipeline_timings: dict[str, object] | None
    audit: AuditContinuity
    similar_decisions: tuple[SimilarDecisionReference, ...]
    detail_deleted_at: datetime | None


@dataclass(frozen=True)
class _CursorPosition:
    snapshot_at: datetime
    after_created_at: datetime
    after_id: UUID


class DecisionReader(Protocol):
    async def list_decisions(
        self, query: DecisionListQuery, principal: Principal
    ) -> DecisionPage: ...

    async def get_decision(self, trace_id: UUID, principal: Principal) -> DecisionDetail: ...


class DecisionCursorCodec:
    """Encode authenticated, tenant- and filter-bound keyset cursors."""

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < 32:
            raise ValueError("cursor signing key must contain at least 32 bytes")
        self._signing_key = signing_key

    def encode(
        self,
        *,
        tenant_id: UUID,
        filter_fingerprint: str,
        snapshot_at: datetime,
        after_created_at: datetime,
        after_id: UUID,
    ) -> str:
        document = {
            "v": _CURSOR_VERSION,
            "tenant": str(tenant_id),
            "filters": filter_fingerprint,
            "snapshot": _utc_text(snapshot_at),
            "after_created": _utc_text(after_created_at),
            "after_id": str(after_id),
        }
        payload = _canonical_bytes(document)
        signature = hmac.digest(self._signing_key, payload, "sha256")
        return _base64url(payload + signature)

    def decode(self, value: str, *, tenant_id: UUID, filter_fingerprint: str) -> _CursorPosition:
        if not 1 <= len(value) <= _MAX_CURSOR_BYTES:
            raise InvalidDecisionCursorError
        try:
            packed = _unbase64url(value)
            if len(packed) <= 32:
                raise ValueError
            payload, signature = packed[:-32], packed[-32:]
            if not hmac.compare_digest(
                signature, hmac.digest(self._signing_key, payload, "sha256")
            ):
                raise ValueError
            document = json.loads(payload, object_pairs_hook=_unique_object)
            if not isinstance(document, dict) or set(document) != {
                "v",
                "tenant",
                "filters",
                "snapshot",
                "after_created",
                "after_id",
            }:
                raise ValueError
            if (
                document["v"] != _CURSOR_VERSION
                or document["tenant"] != str(tenant_id)
                or document["filters"] != filter_fingerprint
            ):
                raise ValueError
            snapshot = _parse_utc(cast(str, document["snapshot"]))
            after_created = _parse_utc(cast(str, document["after_created"]))
            after_id = UUID(cast(str, document["after_id"]))
            if after_created > snapshot:
                raise ValueError
            return _CursorPosition(snapshot, after_created, after_id)
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidDecisionCursorError from exc


class PostgresDecisionReader:
    """Read only persisted, redacted decisions within one claim-derived tenant."""

    def __init__(self, database: Database, cursor_codec: DecisionCursorCodec) -> None:
        self._database = database
        self._cursor_codec = cursor_codec

    async def list_decisions(self, query: DecisionListQuery, principal: Principal) -> DecisionPage:
        tenant_id = _tenant_uuid(principal)
        fingerprint = query.fingerprint()
        try:
            async with self._database.transaction() as session:
                if query.cursor is None:
                    snapshot_at = await _database_now(session)
                    position = None
                else:
                    position = self._cursor_codec.decode(
                        query.cursor,
                        tenant_id=tenant_id,
                        filter_fingerprint=fingerprint,
                    )
                    snapshot_at = position.snapshot_at
                statement = _list_statement(tenant_id, query, snapshot_at, position)
                rows = list((await session.execute(statement.limit(query.limit + 1))).all())
                visible = rows[: query.limit]
                next_cursor = None
                if len(rows) > query.limit and visible:
                    last_decision = visible[-1][0]
                    next_cursor = self._cursor_codec.encode(
                        tenant_id=tenant_id,
                        filter_fingerprint=fingerprint,
                        snapshot_at=snapshot_at,
                        after_created_at=last_decision.created_at,
                        after_id=last_decision.id,
                    )
                return DecisionPage(
                    items=tuple(_summary(decision, action) for decision, action in visible),
                    next_cursor=next_cursor,
                    snapshot_at=snapshot_at,
                )
        except InvalidDecisionCursorError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DecisionQueryUnavailableError from exc

    async def get_decision(self, trace_id: UUID, principal: Principal) -> DecisionDetail:
        tenant_id = _tenant_uuid(principal)
        try:
            async with self._database.transaction() as session:
                row = (
                    await session.execute(
                        select(Decision, CanonicalAction)
                        .join(
                            CanonicalAction,
                            and_(
                                CanonicalAction.tenant_id == Decision.tenant_id,
                                CanonicalAction.id == Decision.action_id,
                            ),
                        )
                        .where(
                            Decision.tenant_id == tenant_id,
                            Decision.trace_id == trace_id,
                        )
                    )
                ).one_or_none()
                if row is None:
                    raise DecisionNotFoundError
                decision, action = row
                audit = await session.scalar(
                    select(AuditEvent)
                    .where(
                        AuditEvent.tenant_id == tenant_id,
                        AuditEvent.decision_id == decision.id,
                        AuditEvent.event_type == "evaluation.decided",
                    )
                    .order_by(AuditEvent.sequence)
                    .limit(1)
                )
                if audit is None:
                    raise DecisionQueryUnavailableError
                matches = list(
                    (
                        await session.scalars(
                            select(PolicyMatch)
                            .where(
                                PolicyMatch.tenant_id == tenant_id,
                                PolicyMatch.decision_id == decision.id,
                            )
                            .order_by(PolicyMatch.rule_id, PolicyMatch.id)
                        )
                    ).all()
                )
                similar = await _similar_decisions(session, tenant_id, decision, action)
                return _detail(decision, action, audit, matches, similar)
        except DecisionNotFoundError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DecisionQueryUnavailableError from exc


def _list_statement(
    tenant_id: UUID,
    query: DecisionListQuery,
    snapshot_at: datetime,
    position: _CursorPosition | None,
) -> Select[tuple[Decision, CanonicalAction]]:
    statement = (
        select(Decision, CanonicalAction)
        .join(
            CanonicalAction,
            and_(
                CanonicalAction.tenant_id == Decision.tenant_id,
                CanonicalAction.id == Decision.action_id,
            ),
        )
        .where(Decision.tenant_id == tenant_id, Decision.created_at <= snapshot_at)
    )
    statement = _apply_filters(statement, query)
    if position is not None:
        statement = statement.where(
            or_(
                Decision.created_at < position.after_created_at,
                and_(
                    Decision.created_at == position.after_created_at,
                    Decision.id < position.after_id,
                ),
            )
        )
    return statement.order_by(Decision.created_at.desc(), Decision.id.desc())


def _apply_filters(
    statement: Select[tuple[Decision, CanonicalAction]], query: DecisionListQuery
) -> Select[tuple[Decision, CanonicalAction]]:
    if query.created_from is not None:
        statement = statement.where(Decision.created_at >= query.created_from)
    if query.created_to is not None:
        statement = statement.where(Decision.created_at <= query.created_to)
    if query.verdict is not None:
        statement = statement.where(Decision.verdict == query.verdict)
    if query.policy_decision is not None:
        statement = statement.where(Decision.policy_decision == query.policy_decision)
    if query.response_status is not None:
        statement = statement.where(Decision.response_status == query.response_status)
    if query.evidence_degraded is not None:
        statement = statement.where(
            cast(Any, Decision.evidence_state)["degraded"].as_boolean() == query.evidence_degraded
        )
    if query.agent_id is not None:
        statement = statement.where(Decision.agent_id == query.agent_id)
    if query.action_type is not None:
        statement = statement.where(
            cast(Any, CanonicalAction.redacted_action)["action_type"].as_string()
            == query.action_type
        )
    if query.search is not None:
        statement = statement.where(_search_predicate(query.search))
    return statement


def _search_predicate(value: str) -> ColumnElement[bool]:
    search_query = func.plainto_tsquery("simple", value)
    predicates: list[ColumnElement[bool]] = [
        func.to_tsvector("simple", Decision.agent_id).op("@@")(search_query),
        func.to_tsvector("simple", cast(Any, CanonicalAction.redacted_action).cast(Text)).op("@@")(
            search_query
        ),
    ]
    trace_id = _optional_uuid(value)
    if trace_id is not None:
        predicates.append(Decision.trace_id == trace_id)
    return or_(*predicates)


async def _similar_decisions(
    session: AsyncSession,
    tenant_id: UUID,
    decision: Decision,
    action: CanonicalAction,
) -> tuple[SimilarDecisionReference, ...]:
    action_type = _action_type(action)
    predicates = [Decision.agent_id == decision.agent_id]
    if action_type is not None:
        predicates.append(
            cast(Any, CanonicalAction.redacted_action)["action_type"].as_string() == action_type
        )
    rows = list(
        (
            await session.execute(
                select(Decision, CanonicalAction)
                .join(
                    CanonicalAction,
                    and_(
                        CanonicalAction.tenant_id == Decision.tenant_id,
                        CanonicalAction.id == Decision.action_id,
                    ),
                )
                .where(
                    Decision.tenant_id == tenant_id,
                    Decision.id != decision.id,
                    or_(*predicates),
                )
                .order_by(Decision.created_at.desc(), Decision.id.desc())
                .limit(_MAX_SIMILAR_REFERENCES)
            )
        ).all()
    )
    return tuple(
        SimilarDecisionReference(
            trace_id=item.trace_id,
            created_at=item.created_at,
            verdict=cast(DecisionVerdict, item.verdict),
            agent_id=item.agent_id,
            action_type=_action_type(item_action),
        )
        for item, item_action in rows
    )


def _summary(decision: Decision, action: CanonicalAction) -> DecisionSummary:
    evidence = decision.evidence_state
    degraded = evidence.get("degraded") if isinstance(evidence, dict) else None
    return DecisionSummary(
        trace_id=decision.trace_id,
        created_at=decision.created_at,
        agent_id=decision.agent_id,
        action_type=_action_type(action),
        verdict=cast(DecisionVerdict, decision.verdict),
        behavioral_score=float(decision.behavioral_score),
        blast_radius=decision.blast_radius,
        policy_decision=cast(PolicyDecision, decision.policy_decision),
        evidence_degraded=degraded if isinstance(degraded, bool) else None,
        response_status=cast(ResponseStatus, decision.response_status),
        detail_available=(decision.detail_deleted_at is None and action.detail_deleted_at is None),
    )


def _detail(
    decision: Decision,
    action: CanonicalAction,
    audit: AuditEvent,
    matches: list[PolicyMatch],
    similar: tuple[SimilarDecisionReference, ...],
) -> DecisionDetail:
    summary = _summary(decision, action)
    action_detail = _safe_action(action.redacted_action)
    return DecisionDetail(
        **summary.model_dump(),
        input_digest=f"sha256:{action.input_digest.hex()}",
        action=action_detail,
        reasons=_object_tuple(decision.reasons),
        mitre_mappings=_object_tuple(decision.mitre_mappings),
        predicted_next=_object_or_none(decision.predicted_next),
        policy_pack_version=decision.policy_pack_version,
        policy_matches=tuple(
            PolicyMatchDetail(
                rule_id=match.rule_id,
                rule_version=match.rule_version,
                effect=cast(Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"], match.effect),
                metadata=cast(dict[str, object], match.safe_metadata),
            )
            for match in matches
        ),
        evidence_state=_object_or_none(decision.evidence_state),
        pipeline_timings=_object_or_none(decision.pipeline_timings),
        audit=AuditContinuity(
            sequence=audit.sequence,
            event_type=audit.event_type,
            occurred_at=audit.occurred_at,
            digest=audit.digest.hex(),
            previous_digest=None if audit.previous_digest is None else audit.previous_digest.hex(),
        ),
        similar_decisions=similar,
        detail_deleted_at=decision.detail_deleted_at or action.detail_deleted_at,
    )


def _safe_action(value: dict[str, object] | None) -> SafeCanonicalAction | None:
    if value is None:
        return None
    try:
        return SafeCanonicalAction.model_validate(
            {key: value[key] for key in SafeCanonicalAction.model_fields}
        )
    except (KeyError, ValueError, TypeError):
        return None


def _action_type(action: CanonicalAction) -> str | None:
    value = action.redacted_action
    action_type = value.get("action_type") if isinstance(value, dict) else None
    return action_type if isinstance(action_type, str) else None


def _object_tuple(value: list[dict[str, object]] | None) -> tuple[dict[str, object], ...] | None:
    return None if value is None else tuple(value)


def _object_or_none(value: dict[str, object] | None) -> dict[str, object] | None:
    return value


def _tenant_uuid(principal: Principal) -> UUID:
    try:
        return UUID(principal.tenant_id)
    except ValueError as exc:
        raise DecisionQueryUnavailableError from exc


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(func.clock_timestamp())
    if not isinstance(value, datetime):
        raise DecisionQueryUnavailableError
    return value.astimezone(UTC)


def _optional_uuid(value: str) -> UUID | None:
    try:
        return UUID(value)
    except ValueError:
        return None


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed.astimezone(UTC)


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unbase64url(value: str) -> bytes:
    if not value.isascii() or not all(
        character.isalnum() or character in "-_" for character in value
    ):
        raise ValueError
    padding = "=" * (-len(value) % 4)
    decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    if _base64url(decoded) != value:
        raise ValueError
    return decoded


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result
