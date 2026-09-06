"""Policy catalogue and measured operational-state read models."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections import Counter
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Literal, Protocol, cast
from uuid import UUID

from dusk.policies import PolicyPack
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, SQLAlchemyError

from dusk_control_plane.identity import Principal
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import AuditEvent, IntegrationHealth, OutboxDelivery

_CURSOR_VERSION = 1
_SAFE_DIAGNOSTICS = frozenset(
    {
        "AUTHENTICATION_FAILED",
        "CONFIGURATION_MISSING",
        "CONNECTION_FAILED",
        "DEAD_LETTER_PRESENT",
        "DEPENDENCY_UNAVAILABLE",
        "RATE_LIMITED",
        "STALE_MEASUREMENT",
        "TIMEOUT",
    }
)


class OperationsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OperationsQueryUnavailableError(Exception):
    """Measured operational data could not be read."""


class InvalidOperationsCursorError(Exception):
    """An operational-list cursor is invalid for the current tenant or filters."""


class PolicyListQuery(OperationsModel):
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    status: str | None = Field(default=None, pattern=r"^[a-z_]{1,32}$")
    category: str | None = Field(default=None, pattern=r"^[a-z0-9_.-]{1,64}$")
    severity: str | None = Field(default=None, pattern=r"^(low|medium|high|critical)$")


class PolicyRuleView(OperationsModel):
    id: str
    version: str
    title: str
    category: str
    severity: str
    decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    status: str
    owner: str
    frameworks: tuple[str, ...]
    prerequisites: tuple[str, ...]


class PolicyPage(OperationsModel):
    pack_name: str
    pack_version: str
    items: tuple[PolicyRuleView, ...]
    next_cursor: str | None


class PolicySummary(OperationsModel):
    pack_name: str
    pack_version: str
    default_decision: Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]
    total_rules: int = Field(ge=0)
    enforced_rules: int = Field(ge=0)
    planned_rules: int = Field(ge=0)
    counts_by_status: dict[str, int]


class IntegrationHealthQuery(OperationsModel):
    limit: int = Field(default=50, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN"] | None = None
    integration_kind: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_.-]{1,64}$")


class IntegrationHealthView(OperationsModel):
    integration_key: str
    integration_kind: str
    status: Literal["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN", "STALE"]
    checked_at: datetime
    latency_ms: int | None = Field(default=None, ge=0)
    diagnostic_code: str | None = None


class IntegrationHealthPage(OperationsModel):
    state: Literal["available", "empty"]
    snapshot_at: datetime
    items: tuple[IntegrationHealthView, ...]
    next_cursor: str | None


class ServiceComponent(OperationsModel):
    name: Literal["gate", "postgresql", "sie", "outbox", "audit", "adapters"]
    status: Literal["healthy", "degraded", "unavailable", "unmeasured"]
    measured_at: datetime | None = None
    latency_ms: float | None = Field(default=None, ge=0)
    diagnostic_code: str | None = None


class ServiceStatus(OperationsModel):
    status: Literal["healthy", "degraded", "unavailable"]
    measured_at: datetime
    components: tuple[ServiceComponent, ...]
    instrumented_pipeline_stages: tuple[str, ...]


class OperationsReader(Protocol):
    async def policies(self, query: PolicyListQuery, principal: Principal) -> PolicyPage: ...
    async def policy_summary(self, principal: Principal) -> PolicySummary: ...
    async def integration_health(
        self, query: IntegrationHealthQuery, principal: Principal
    ) -> IntegrationHealthPage: ...
    async def service_status(self, principal: Principal) -> ServiceStatus: ...


class OperationsCursorCodec:
    def __init__(self, key: bytes) -> None:
        if len(key) < 32:
            raise ValueError("operations cursor signing key must contain at least 32 bytes")
        self._key = hmac.digest(key, b"dusk-operations-cursor-v1", "sha256")

    def encode(self, *, tenant: str, kind: str, fingerprint: str, after: str) -> str:
        body = json.dumps(
            {"v": _CURSOR_VERSION, "t": tenant, "k": kind, "f": fingerprint, "a": after},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return f"{_b64(body)}.{_b64(hmac.digest(self._key, body, 'sha256'))}"

    def decode(self, value: str, *, tenant: str, kind: str, fingerprint: str) -> str:
        try:
            encoded, signature = value.split(".", 1)
            body = _unb64(encoded)
            if not hmac.compare_digest(_unb64(signature), hmac.digest(self._key, body, "sha256")):
                raise ValueError
            payload = json.loads(body)
            if payload != {
                "v": _CURSOR_VERSION,
                "t": tenant,
                "k": kind,
                "f": fingerprint,
                "a": payload.get("a"),
            } or not isinstance(payload["a"], str):
                raise ValueError
            return payload["a"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise InvalidOperationsCursorError from exc


class PostgresOperationsReader:
    def __init__(
        self,
        database: Database,
        pack: PolicyPack,
        cursor_codec: OperationsCursorCodec,
        *,
        stale_after: timedelta = timedelta(minutes=2),
        outbox_instrumented: bool = False,
        instrumented_pipeline_stages: Sequence[str] = (),
    ) -> None:
        self._database = database
        self._pack = pack
        self._cursor = cursor_codec
        self._stale_after = stale_after
        self._outbox_instrumented = outbox_instrumented
        self._stages = tuple(instrumented_pipeline_stages)

    async def policies(self, query: PolicyListQuery, principal: Principal) -> PolicyPage:
        rules = sorted(
            (
                rule
                for rule in self._pack.rules
                if (query.status is None or rule.status == query.status)
                and (query.category is None or rule.category == query.category)
                and (query.severity is None or rule.severity == query.severity)
            ),
            key=lambda rule: rule.id,
        )
        fingerprint = _fingerprint(query.model_dump(exclude={"cursor", "limit"}))
        after = None
        if query.cursor:
            after = self._cursor.decode(
                query.cursor, tenant=principal.tenant_id, kind="policy", fingerprint=fingerprint
            )
            rules = [rule for rule in rules if rule.id > after]
        visible = rules[: query.limit]
        next_cursor = None
        if len(rules) > query.limit and visible:
            next_cursor = self._cursor.encode(
                tenant=principal.tenant_id,
                kind="policy",
                fingerprint=fingerprint,
                after=visible[-1].id,
            )
        return PolicyPage(
            pack_name=self._pack.name,
            pack_version=self._pack.version,
            items=tuple(
                PolicyRuleView(
                    id=rule.id,
                    version=rule.version,
                    title=rule.title,
                    category=rule.category,
                    severity=rule.severity,
                    decision=cast(Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"], rule.decision.name),
                    status=rule.status,
                    owner=rule.owner,
                    frameworks=rule.frameworks,
                    prerequisites=rule.prerequisites,
                )
                for rule in visible
            ),
            next_cursor=next_cursor,
        )

    async def policy_summary(self, principal: Principal) -> PolicySummary:
        del principal
        counts = Counter(rule.status for rule in self._pack.rules)
        return PolicySummary(
            pack_name=self._pack.name,
            pack_version=self._pack.version,
            default_decision=cast(
                Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"], self._pack.default_decision.name
            ),
            total_rules=len(self._pack.rules),
            enforced_rules=counts["enforced"],
            planned_rules=counts["planned"],
            counts_by_status=dict(sorted(counts.items())),
        )

    async def integration_health(
        self, query: IntegrationHealthQuery, principal: Principal
    ) -> IntegrationHealthPage:
        tenant_id = _tenant_uuid(principal)
        fingerprint = _fingerprint(query.model_dump(exclude={"cursor", "limit"}))
        after = None
        if query.cursor:
            after = self._cursor.decode(
                query.cursor,
                tenant=principal.tenant_id,
                kind="integration",
                fingerprint=fingerprint,
            )
        try:
            async with self._database.transaction() as session:
                snapshot = await session.scalar(select(func.clock_timestamp()))
                if snapshot is None:
                    raise OperationsQueryUnavailableError
                statement = select(IntegrationHealth).where(
                    IntegrationHealth.tenant_id == tenant_id
                )
                if query.status is not None:
                    statement = statement.where(IntegrationHealth.status == query.status)
                if query.integration_kind is not None:
                    statement = statement.where(
                        IntegrationHealth.integration_kind == query.integration_kind
                    )
                if after is not None:
                    statement = statement.where(IntegrationHealth.integration_key > after)
                rows = list(
                    (
                        await session.scalars(
                            statement.order_by(IntegrationHealth.integration_key).limit(
                                query.limit + 1
                            )
                        )
                    ).all()
                )
            visible = rows[: query.limit]
            next_cursor = None
            if len(rows) > query.limit and visible:
                next_cursor = self._cursor.encode(
                    tenant=principal.tenant_id,
                    kind="integration",
                    fingerprint=fingerprint,
                    after=visible[-1].integration_key,
                )
            return IntegrationHealthPage(
                state="available" if visible else "empty",
                snapshot_at=snapshot,
                items=tuple(self._health_view(row, snapshot) for row in visible),
                next_cursor=next_cursor,
            )
        except InvalidOperationsCursorError:
            raise
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise OperationsQueryUnavailableError from exc

    async def service_status(self, principal: Principal) -> ServiceStatus:
        tenant_id = _tenant_uuid(principal)
        try:
            started = time.perf_counter()
            async with self._database.transaction() as session:
                measured_at = await session.scalar(select(func.clock_timestamp()))
                rows = list(
                    (
                        await session.scalars(
                            select(IntegrationHealth)
                            .where(IntegrationHealth.tenant_id == tenant_id)
                            .order_by(IntegrationHealth.integration_key)
                        )
                    ).all()
                )
                dead_letters = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(OutboxDelivery)
                        .where(
                            OutboxDelivery.tenant_id == tenant_id,
                            OutboxDelivery.state == "DEAD_LETTER",
                        )
                    )
                    or 0
                )
                latest_audit = await session.scalar(
                    select(func.max(AuditEvent.occurred_at)).where(
                        AuditEvent.tenant_id == tenant_id
                    )
                )
            if measured_at is None:
                raise OperationsQueryUnavailableError
        except (DBAPIError, SQLAlchemyError, TimeoutError) as exc:
            raise OperationsQueryUnavailableError from exc

        postgres = ServiceComponent(
            name="postgresql",
            status="healthy",
            measured_at=measured_at,
            latency_ms=(time.perf_counter() - started) * 1000,
        )
        by_kind: dict[str, list[IntegrationHealth]] = {}
        for row in rows:
            by_kind.setdefault(row.integration_kind.lower(), []).append(row)
        components = [
            self._component("gate", by_kind.get("gate", []), measured_at),
            postgres,
            self._component("sie", by_kind.get("sie", []), measured_at),
            ServiceComponent(
                name="outbox",
                status=("degraded" if dead_letters else "healthy")
                if self._outbox_instrumented
                else "unmeasured",
                measured_at=measured_at if self._outbox_instrumented else None,
                diagnostic_code=(
                    "DEAD_LETTER_PRESENT" if self._outbox_instrumented and dead_letters else None
                ),
            ),
            ServiceComponent(
                name="audit",
                status="healthy" if latest_audit is not None else "unmeasured",
                measured_at=latest_audit,
            ),
            self._component(
                "adapters",
                [row for row in rows if row.integration_kind.lower() not in {"gate", "sie"}],
                measured_at,
            ),
        ]
        statuses = {item.status for item in components}
        overall: Literal["healthy", "degraded", "unavailable"] = (
            "unavailable"
            if "unavailable" in statuses
            else "degraded"
            if statuses - {"healthy"}
            else "healthy"
        )
        return ServiceStatus(
            status=overall,
            measured_at=measured_at,
            components=tuple(components),
            instrumented_pipeline_stages=self._stages,
        )

    def _health_view(self, row: IntegrationHealth, now: datetime) -> IntegrationHealthView:
        stale = row.checked_at < now - self._stale_after
        return IntegrationHealthView(
            integration_key=row.integration_key,
            integration_kind=row.integration_kind,
            status=cast(
                Literal["HEALTHY", "DEGRADED", "UNAVAILABLE", "UNKNOWN", "STALE"],
                "STALE" if stale else row.status,
            ),
            checked_at=row.checked_at,
            latency_ms=row.latency_ms,
            diagnostic_code="STALE_MEASUREMENT" if stale else _safe_code(row.safe_diagnostic_code),
        )

    def _component(
        self, name: Literal["gate", "sie", "adapters"], rows: list[IntegrationHealth], now: datetime
    ) -> ServiceComponent:
        if not rows:
            return ServiceComponent(name=name, status="unmeasured")
        views = [self._health_view(row, now) for row in rows]
        if any(view.status in {"UNAVAILABLE", "STALE"} for view in views):
            status: Literal["healthy", "degraded", "unavailable", "unmeasured"] = "unavailable"
        elif any(view.status in {"DEGRADED", "UNKNOWN"} for view in views):
            status = "degraded"
        else:
            status = "healthy"
        latest = max(views, key=lambda view: view.checked_at)
        return ServiceComponent(
            name=name,
            status=status,
            measured_at=latest.checked_at,
            latency_ms=latest.latency_ms,
            diagnostic_code=latest.diagnostic_code,
        )


def _tenant_uuid(principal: Principal) -> UUID:
    try:
        return UUID(principal.tenant_id)
    except ValueError as exc:
        raise OperationsQueryUnavailableError from exc


def _safe_code(value: str | None) -> str | None:
    return value if value in _SAFE_DIAGNOSTICS else None


def _fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _unb64(value: str) -> bytes:
    if not value.isascii() or not all(
        character.isalnum() or character in "-_" for character in value
    ):
        raise ValueError
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if _b64(decoded) != value:
        raise ValueError
    return decoded
