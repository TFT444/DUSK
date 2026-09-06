"""Tenant-scoped dashboard metrics and agent risk investigation queries."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Literal, Protocol, cast
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Float, Select, and_, case, func, or_, select
from sqlalchemy import cast as sql_cast
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from dusk_control_plane.identity import Principal
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import CanonicalAction, Decision

DashboardState = Literal["available", "empty"]
Verdict = Literal["ALLOW", "WOULD-BLOCK", "BLOCK"]
_CURSOR_VERSION = 1
_HIGH_RISK_THRESHOLD = 0.8


class DashboardReadModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DashboardQueryUnavailableError(Exception):
    """PostgreSQL could not complete a bounded dashboard query."""


class InvalidAgentRiskCursorError(Exception):
    """The opaque agent-risk cursor is invalid for the current query."""


class AgentNotFoundError(Exception):
    """No agent is visible under the authenticated tenant and window."""


class DashboardWindow(StrEnum):
    LAST_24_HOURS = "24h"
    LAST_7_DAYS = "7d"
    LAST_30_DAYS = "30d"

    @property
    def duration(self) -> timedelta:
        return {
            DashboardWindow.LAST_24_HOURS: timedelta(hours=24),
            DashboardWindow.LAST_7_DAYS: timedelta(days=7),
            DashboardWindow.LAST_30_DAYS: timedelta(days=30),
        }[self]

    @property
    def bucket(self) -> Literal["hour", "day"]:
        return "hour" if self is DashboardWindow.LAST_24_HOURS else "day"


class DashboardWindowQuery(DashboardReadModel):
    window: DashboardWindow = DashboardWindow.LAST_24_HOURS


class AgentRiskQuery(DashboardReadModel):
    window: DashboardWindow = DashboardWindow.LAST_30_DAYS
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    minimum_risk_score: float = Field(default=0, ge=0, le=1)


class MetricFreshness(DashboardReadModel):
    state: DashboardState
    snapshot_at: datetime
    source_last_updated_at: datetime | None
    poll_after_seconds: int = Field(default=30, ge=1)


class MetricValue(DashboardReadModel):
    value: int
    previous_value: int
    change_percent: float | None


class LatencyMetric(DashboardReadModel):
    p95_ms: float | None = Field(default=None, ge=0)
    sample_count: int = Field(ge=0)


class DashboardSummary(DashboardReadModel):
    window: DashboardWindow
    window_start: datetime
    window_end: datetime
    comparison_start: datetime
    comparison_end: datetime
    timezone: Literal["UTC"] = "UTC"
    decisions: MetricValue
    blocked: MetricValue
    would_block: MetricValue
    allowed: MetricValue
    active_agents: MetricValue
    high_risk_decisions: MetricValue
    evaluation_latency: LatencyMetric
    freshness: MetricFreshness


class DecisionVolumePoint(DashboardReadModel):
    bucket_start: datetime
    allow: int = Field(ge=0)
    would_block: int = Field(ge=0)
    block: int = Field(ge=0)
    total: int = Field(ge=0)


class DecisionVolume(DashboardReadModel):
    window: DashboardWindow
    window_start: datetime
    window_end: datetime
    bucket_granularity: Literal["hour", "day"]
    timezone: Literal["UTC"] = "UTC"
    points: tuple[DecisionVolumePoint, ...]
    freshness: MetricFreshness


class ActionBreakdownItem(DashboardReadModel):
    action_type: str
    decision_count: int = Field(ge=0)
    share_percent: float = Field(ge=0, le=100)


class ActionBreakdown(DashboardReadModel):
    window: DashboardWindow
    window_start: datetime
    window_end: datetime
    timezone: Literal["UTC"] = "UTC"
    items: tuple[ActionBreakdownItem, ...]
    freshness: MetricFreshness


class AgentRiskItem(DashboardReadModel):
    agent_id: str
    risk_score: float = Field(ge=0, le=1)
    decision_count: int = Field(ge=0)
    high_risk_count: int = Field(ge=0)
    block_count: int = Field(ge=0)
    would_block_count: int = Field(ge=0)
    last_seen_at: datetime


class AgentRiskPage(DashboardReadModel):
    window: DashboardWindow
    window_start: datetime
    window_end: datetime
    timezone: Literal["UTC"] = "UTC"
    items: tuple[AgentRiskItem, ...]
    next_cursor: str | None
    freshness: MetricFreshness


class AgentDecisionReference(DashboardReadModel):
    trace_id: UUID
    created_at: datetime
    verdict: Verdict
    behavioral_score: float = Field(ge=0, le=1)
    action_type: str | None


class AgentDetail(AgentRiskItem):
    window: DashboardWindow
    window_start: datetime
    window_end: datetime
    timezone: Literal["UTC"] = "UTC"
    first_seen_at: datetime
    allow_count: int = Field(ge=0)
    evaluation_latency: LatencyMetric
    recent_decisions: tuple[AgentDecisionReference, ...]
    freshness: MetricFreshness


class DashboardReader(Protocol):
    async def summary(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> DashboardSummary: ...

    async def decision_volume(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> DecisionVolume: ...

    async def action_breakdown(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> ActionBreakdown: ...

    async def agent_risk(self, query: AgentRiskQuery, principal: Principal) -> AgentRiskPage: ...

    async def agent_detail(
        self, agent_id: str, query: DashboardWindowQuery, principal: Principal
    ) -> AgentDetail: ...


@dataclass(frozen=True)
class _RiskCursor:
    snapshot_at: datetime
    risk_score: Decimal
    high_risk_count: int
    last_seen_at: datetime
    agent_id: str


class AgentRiskCursorCodec:
    """Versioned, tenant/query-bound HMAC cursor for stable risk ranking."""

    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("agent-risk cursor signing key must contain at least 32 bytes")
        self._key = hmac.digest(key, b"dusk-agent-risk-cursor-v1", "sha256")

    def encode(self, *, tenant_id: UUID, query: AgentRiskQuery, value: _RiskCursor) -> str:
        payload = {
            "v": _CURSOR_VERSION,
            "t": str(tenant_id),
            "f": _risk_fingerprint(query),
            "s": _utc_text(value.snapshot_at),
            "r": str(value.risk_score),
            "h": value.high_risk_count,
            "l": _utc_text(value.last_seen_at),
            "a": value.agent_id,
        }
        body = _canonical_bytes(payload)
        return f"{_base64url(body)}.{_base64url(hmac.digest(self._key, body, 'sha256'))}"

    def decode(self, value: str, *, tenant_id: UUID, query: AgentRiskQuery) -> _RiskCursor:
        try:
            encoded_body, encoded_signature = value.split(".", 1)
            body = _unbase64url(encoded_body)
            signature = _unbase64url(encoded_signature)
            if not hmac.compare_digest(signature, hmac.digest(self._key, body, "sha256")):
                raise ValueError
            payload = json.loads(body, object_pairs_hook=_unique_object)
            if not isinstance(payload, dict) or set(payload) != {
                "v",
                "t",
                "f",
                "s",
                "r",
                "h",
                "l",
                "a",
            }:
                raise ValueError
            if payload["v"] != _CURSOR_VERSION or payload["t"] != str(tenant_id):
                raise ValueError
            if payload["f"] != _risk_fingerprint(query):
                raise ValueError
            risk = Decimal(cast(str, payload["r"]))
            high = int(payload["h"])
            agent = payload["a"]
            if (
                not Decimal(0) <= risk <= Decimal(1)
                or high < 0
                or not isinstance(agent, str)
                or not agent
            ):
                raise ValueError
            return _RiskCursor(
                snapshot_at=_parse_utc(cast(str, payload["s"])),
                risk_score=risk,
                high_risk_count=high,
                last_seen_at=_parse_utc(cast(str, payload["l"])),
                agent_id=agent,
            )
        except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise InvalidAgentRiskCursorError from exc


class PostgresDashboardReader:
    """Compute bounded metrics directly from tenant-qualified source decisions."""

    def __init__(self, database: Database, cursor_codec: AgentRiskCursorCodec) -> None:
        self._database = database
        self._cursor_codec = cursor_codec

    async def summary(self, query: DashboardWindowQuery, principal: Principal) -> DashboardSummary:
        tenant_id = _tenant_uuid(principal)
        try:
            async with self._database.transaction() as session:
                snapshot = await _database_now(session)
                start = snapshot - query.window.duration
                previous_start = start - query.window.duration
                current = await _summary_row(session, tenant_id, start, snapshot)
                previous = await _summary_row(session, tenant_id, previous_start, start)
                freshness = _freshness(snapshot, current.last_seen, current.total)
                return DashboardSummary(
                    window=query.window,
                    window_start=start,
                    window_end=snapshot,
                    comparison_start=previous_start,
                    comparison_end=start,
                    decisions=_metric(current.total, previous.total),
                    blocked=_metric(current.blocked, previous.blocked),
                    would_block=_metric(current.would_block, previous.would_block),
                    allowed=_metric(current.allowed, previous.allowed),
                    active_agents=_metric(current.active_agents, previous.active_agents),
                    high_risk_decisions=_metric(current.high_risk, previous.high_risk),
                    evaluation_latency=LatencyMetric(
                        p95_ms=current.p95_ms, sample_count=current.latency_samples
                    ),
                    freshness=freshness,
                )
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DashboardQueryUnavailableError from exc

    async def decision_volume(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> DecisionVolume:
        tenant_id = _tenant_uuid(principal)
        try:
            async with self._database.transaction() as session:
                snapshot = await _database_now(session)
                start = snapshot - query.window.duration
                bucket = func.date_trunc(query.window.bucket, Decision.created_at)
                rows = (
                    await session.execute(
                        select(
                            bucket.label("bucket_start"),
                            func.count().filter(Decision.verdict == "ALLOW").label("allowed"),
                            func.count().filter(Decision.verdict == "WOULD-BLOCK").label("would"),
                            func.count().filter(Decision.verdict == "BLOCK").label("blocked"),
                            func.count().label("total"),
                        )
                        .where(
                            Decision.tenant_id == tenant_id,
                            Decision.created_at >= start,
                            Decision.created_at < snapshot,
                        )
                        .group_by(bucket)
                        .order_by(bucket)
                    )
                ).all()
                last_seen = await _last_seen(session, tenant_id, start, snapshot)
                return DecisionVolume(
                    window=query.window,
                    window_start=start,
                    window_end=snapshot,
                    bucket_granularity=query.window.bucket,
                    points=tuple(
                        DecisionVolumePoint(
                            bucket_start=row.bucket_start.astimezone(UTC),
                            allow=row.allowed,
                            would_block=row.would,
                            block=row.blocked,
                            total=row.total,
                        )
                        for row in rows
                    ),
                    freshness=_freshness(snapshot, last_seen, sum(row.total for row in rows)),
                )
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DashboardQueryUnavailableError from exc

    async def action_breakdown(
        self, query: DashboardWindowQuery, principal: Principal
    ) -> ActionBreakdown:
        tenant_id = _tenant_uuid(principal)
        try:
            async with self._database.transaction() as session:
                snapshot = await _database_now(session)
                start = snapshot - query.window.duration
                action_type = func.coalesce(
                    CanonicalAction.redacted_action["action_type"].as_string(), "unknown"
                )
                rows = (
                    await session.execute(
                        select(action_type.label("action_type"), func.count().label("count"))
                        .select_from(Decision)
                        .join(
                            CanonicalAction,
                            and_(
                                CanonicalAction.tenant_id == Decision.tenant_id,
                                CanonicalAction.id == Decision.action_id,
                            ),
                        )
                        .where(
                            Decision.tenant_id == tenant_id,
                            Decision.created_at >= start,
                            Decision.created_at < snapshot,
                        )
                        .group_by(action_type)
                        .order_by(func.count().desc(), action_type.asc())
                        .limit(100)
                    )
                ).all()
                total = (
                    await session.scalar(
                        select(func.count())
                        .select_from(Decision)
                        .where(
                            Decision.tenant_id == tenant_id,
                            Decision.created_at >= start,
                            Decision.created_at < snapshot,
                        )
                    )
                    or 0
                )
                last_seen = await _last_seen(session, tenant_id, start, snapshot)
                return ActionBreakdown(
                    window=query.window,
                    window_start=start,
                    window_end=snapshot,
                    items=tuple(
                        ActionBreakdownItem(
                            action_type=cast(str, row._mapping["action_type"]),
                            decision_count=cast(int, row._mapping["count"]),
                            share_percent=(
                                round(cast(int, row._mapping["count"]) * 100 / total, 4)
                                if total
                                else 0
                            ),
                        )
                        for row in rows
                    ),
                    freshness=_freshness(snapshot, last_seen, total),
                )
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DashboardQueryUnavailableError from exc

    async def agent_risk(self, query: AgentRiskQuery, principal: Principal) -> AgentRiskPage:
        tenant_id = _tenant_uuid(principal)
        try:
            cursor = (
                None
                if query.cursor is None
                else self._cursor_codec.decode(query.cursor, tenant_id=tenant_id, query=query)
            )
            async with self._database.transaction() as session:
                snapshot = (
                    cursor.snapshot_at if cursor is not None else await _database_now(session)
                )
                start = snapshot - query.window.duration
                ranked = _agent_rollup(tenant_id, start, snapshot).subquery()
                matching = ranked.c.risk_score >= query.minimum_risk_score
                statement = select(ranked).where(matching)
                source_count, source_last_seen = (
                    await session.execute(
                        select(func.count(), func.max(ranked.c.last_seen_at)).where(matching)
                    )
                ).one()
                if cursor is not None:
                    statement = statement.where(
                        or_(
                            ranked.c.risk_score < cursor.risk_score,
                            and_(
                                ranked.c.risk_score == cursor.risk_score,
                                ranked.c.high_risk_count < cursor.high_risk_count,
                            ),
                            and_(
                                ranked.c.risk_score == cursor.risk_score,
                                ranked.c.high_risk_count == cursor.high_risk_count,
                                ranked.c.last_seen_at < cursor.last_seen_at,
                            ),
                            and_(
                                ranked.c.risk_score == cursor.risk_score,
                                ranked.c.high_risk_count == cursor.high_risk_count,
                                ranked.c.last_seen_at == cursor.last_seen_at,
                                ranked.c.agent_id > cursor.agent_id,
                            ),
                        )
                    )
                rows = list(
                    (
                        await session.execute(
                            statement.order_by(
                                ranked.c.risk_score.desc(),
                                ranked.c.high_risk_count.desc(),
                                ranked.c.last_seen_at.desc(),
                                ranked.c.agent_id.asc(),
                            ).limit(query.limit + 1)
                        )
                    ).all()
                )
                visible = rows[: query.limit]
                next_cursor = None
                if len(rows) > query.limit and visible:
                    last = visible[-1]
                    next_cursor = self._cursor_codec.encode(
                        tenant_id=tenant_id,
                        query=query,
                        value=_RiskCursor(
                            snapshot_at=snapshot,
                            risk_score=cast(Decimal, last.risk_score),
                            high_risk_count=last.high_risk_count,
                            last_seen_at=last.last_seen_at,
                            agent_id=last.agent_id,
                        ),
                    )
                items = tuple(
                    _risk_item(cast(Mapping[str, object], row._mapping)) for row in visible
                )
                return AgentRiskPage(
                    window=query.window,
                    window_start=start,
                    window_end=snapshot,
                    items=items,
                    next_cursor=next_cursor,
                    freshness=_freshness(snapshot, source_last_seen, source_count),
                )
        except InvalidAgentRiskCursorError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DashboardQueryUnavailableError from exc

    async def agent_detail(
        self, agent_id: str, query: DashboardWindowQuery, principal: Principal
    ) -> AgentDetail:
        tenant_id = _tenant_uuid(principal)
        try:
            async with self._database.transaction() as session:
                snapshot = await _database_now(session)
                start = snapshot - query.window.duration
                ranked = _agent_rollup(tenant_id, start, snapshot).subquery()
                row = (
                    await session.execute(select(ranked).where(ranked.c.agent_id == agent_id))
                ).one_or_none()
                if row is None:
                    raise AgentNotFoundError
                recent = (
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
                            Decision.agent_id == agent_id,
                            Decision.created_at >= start,
                            Decision.created_at < snapshot,
                        )
                        .order_by(Decision.created_at.desc(), Decision.id.desc())
                        .limit(20)
                    )
                ).all()
                risk = _risk_item(cast(Mapping[str, object], row._mapping))
                return AgentDetail(
                    **risk.model_dump(),
                    window=query.window,
                    window_start=start,
                    window_end=snapshot,
                    first_seen_at=row.first_seen_at,
                    allow_count=row.allow_count,
                    evaluation_latency=LatencyMetric(
                        p95_ms=None if row.p95_ms is None else float(row.p95_ms),
                        sample_count=row.latency_samples,
                    ),
                    recent_decisions=tuple(
                        AgentDecisionReference(
                            trace_id=decision.trace_id,
                            created_at=decision.created_at,
                            verdict=cast(Verdict, decision.verdict),
                            behavioral_score=float(decision.behavioral_score),
                            action_type=_action_type(action),
                        )
                        for decision, action in recent
                    ),
                    freshness=_freshness(snapshot, risk.last_seen_at, risk.decision_count),
                )
        except AgentNotFoundError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise DashboardQueryUnavailableError from exc


@dataclass(frozen=True)
class _SummaryRow:
    total: int
    blocked: int
    would_block: int
    allowed: int
    active_agents: int
    high_risk: int
    last_seen: datetime | None
    p95_ms: float | None
    latency_samples: int


async def _summary_row(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> _SummaryRow:
    latency = _latency_expression()
    row = (
        await session.execute(
            select(
                func.count().label("total"),
                func.count().filter(Decision.verdict == "BLOCK").label("blocked"),
                func.count().filter(Decision.verdict == "WOULD-BLOCK").label("would_block"),
                func.count().filter(Decision.verdict == "ALLOW").label("allowed"),
                func.count(func.distinct(Decision.agent_id)).label("active_agents"),
                func.count()
                .filter(Decision.behavioral_score >= _HIGH_RISK_THRESHOLD)
                .label("high_risk"),
                func.max(Decision.created_at).label("last_seen"),
                func.percentile_cont(0.95).within_group(latency).label("p95_ms"),
                func.count(latency).label("latency_samples"),
            ).where(
                Decision.tenant_id == tenant_id,
                Decision.created_at >= start,
                Decision.created_at < end,
            )
        )
    ).one()
    return _SummaryRow(
        total=row.total,
        blocked=row.blocked,
        would_block=row.would_block,
        allowed=row.allowed,
        active_agents=row.active_agents,
        high_risk=row.high_risk,
        last_seen=row.last_seen,
        p95_ms=None if row.p95_ms is None else float(row.p95_ms),
        latency_samples=row.latency_samples,
    )


def _agent_rollup(
    tenant_id: UUID, start: datetime, end: datetime
) -> Select[tuple[str, Decimal, int, int, int, int, int, datetime, datetime, float | None, int]]:
    latency = _latency_expression()
    return (
        select(
            Decision.agent_id.label("agent_id"),
            func.max(Decision.behavioral_score).label("risk_score"),
            func.count().label("decision_count"),
            func.count()
            .filter(Decision.behavioral_score >= _HIGH_RISK_THRESHOLD)
            .label("high_risk_count"),
            func.count().filter(Decision.verdict == "BLOCK").label("block_count"),
            func.count().filter(Decision.verdict == "WOULD-BLOCK").label("would_block_count"),
            func.count().filter(Decision.verdict == "ALLOW").label("allow_count"),
            func.min(Decision.created_at).label("first_seen_at"),
            func.max(Decision.created_at).label("last_seen_at"),
            func.percentile_cont(0.95).within_group(latency).label("p95_ms"),
            func.count(latency).label("latency_samples"),
        )
        .where(
            Decision.tenant_id == tenant_id,
            Decision.created_at >= start,
            Decision.created_at < end,
        )
        .group_by(Decision.agent_id)
    )


def _latency_expression() -> ColumnElement[float | None]:
    return case(
        (
            Decision.pipeline_timings["total_ms"].as_string().op("~")(r"^[0-9]+(?:\.[0-9]+)?$"),
            sql_cast(Decision.pipeline_timings["total_ms"].as_string(), Float),
        ),
        else_=None,
    )


async def _last_seen(
    session: AsyncSession, tenant_id: UUID, start: datetime, end: datetime
) -> datetime | None:
    value = await session.scalar(
        select(func.max(Decision.created_at)).where(
            Decision.tenant_id == tenant_id,
            Decision.created_at >= start,
            Decision.created_at < end,
        )
    )
    return value


def _risk_item(row: Mapping[str, object]) -> AgentRiskItem:
    return AgentRiskItem(
        agent_id=cast(str, row["agent_id"]),
        risk_score=float(cast(Decimal, row["risk_score"])),
        decision_count=cast(int, row["decision_count"]),
        high_risk_count=cast(int, row["high_risk_count"]),
        block_count=cast(int, row["block_count"]),
        would_block_count=cast(int, row["would_block_count"]),
        last_seen_at=cast(datetime, row["last_seen_at"]),
    )


def _metric(value: int, previous: int) -> MetricValue:
    change = None if previous == 0 else round((value - previous) * 100 / previous, 4)
    return MetricValue(value=value, previous_value=previous, change_percent=change)


def _freshness(snapshot: datetime, last_seen: datetime | None, count: int) -> MetricFreshness:
    return MetricFreshness(
        state="empty" if count == 0 else "available",
        snapshot_at=snapshot,
        source_last_updated_at=last_seen,
    )


def _action_type(action: CanonicalAction) -> str | None:
    value = action.redacted_action
    action_type = value.get("action_type") if isinstance(value, dict) else None
    return action_type if isinstance(action_type, str) else None


def _tenant_uuid(principal: Principal) -> UUID:
    try:
        return UUID(principal.tenant_id)
    except ValueError as exc:
        raise DashboardQueryUnavailableError from exc


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(func.clock_timestamp())
    if not isinstance(value, datetime):
        raise DashboardQueryUnavailableError
    return value.astimezone(UTC)


def _risk_fingerprint(query: AgentRiskQuery) -> str:
    return hashlib.sha256(
        _canonical_bytes(
            {"window": query.window.value, "minimum_risk_score": query.minimum_risk_score}
        )
    ).hexdigest()


def _utc_text(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed.astimezone(UTC)


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unbase64url(value: str) -> bytes:
    if not value.isascii() or not all(
        character.isalnum() or character in "-_" for character in value
    ):
        raise ValueError
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if _base64url(decoded) != value:
        raise ValueError
    return decoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result
