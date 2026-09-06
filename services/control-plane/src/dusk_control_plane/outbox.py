"""Bounded transactional-outbox delivery with pinned-network destinations."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import logging
import math
import random as random_module
import re
import socket
import ssl
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Literal, Protocol, cast
from urllib.parse import SplitResult, urlsplit
from uuid import UUID, uuid4

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from dusk_control_plane.config import Settings
from dusk_control_plane.observability import Telemetry
from dusk_control_plane.storage.database import Database
from dusk_control_plane.storage.models import Decision, OutboxDelivery

logger = logging.getLogger(__name__)
_SAFE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")
_MAX_HEADER_BYTES = 16 * 1024
_MAX_PAYLOAD_BYTES = 64 * 1024
_RESERVED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "content-type",
        "host",
        "idempotency-key",
        "dusk-delivery-id",
    }
)


class DestinationKind(StrEnum):
    WEBHOOK = "WEBHOOK"
    ENFORCEMENT_BROKER = "ENFORCEMENT_BROKER"


@dataclass(frozen=True)
class DeliveryDestination:
    key: str
    kind: DestinationKind
    url: str


@dataclass(frozen=True)
class ResolvedDestination:
    destination: DeliveryDestination
    hostname: str
    port: int
    path: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class DeliveryClaim:
    id: UUID
    tenant_id: UUID
    decision_id: UUID
    delivery_id: UUID
    destination_key: str
    destination_kind: str
    delivery_kind: str
    redacted_payload: dict[str, object]
    attempt_count: int
    max_attempts: int
    state_version: int
    lease_owner: UUID


@dataclass(frozen=True)
class TransportResponse:
    status_code: int
    headers: Mapping[str, str]


@dataclass(frozen=True)
class BrokerAcknowledgement:
    version: Literal["dusk.broker-ack.v1"]
    tenant_id: UUID
    decision_id: UUID
    delivery_id: UUID
    outcome: Literal["EXECUTED", "REJECTED"]
    issued_at: datetime
    nonce: str
    key_id: str
    signature: bytes


@dataclass(frozen=True)
class WorkerRunStats:
    claimed: int = 0
    delivered: int = 0
    retried: int = 0
    dead_lettered: int = 0
    stale_results: int = 0


@dataclass(frozen=True)
class OutboxWorkerConfig:
    batch_size: int
    max_concurrency: int
    poll_interval_seconds: float
    lease_seconds: int
    connect_timeout_seconds: float
    response_timeout_seconds: float
    retry_base_seconds: float
    retry_max_seconds: float
    acknowledgement_max_age_seconds: int

    def __post_init__(self) -> None:
        if not 1 <= self.batch_size <= 200:
            raise ValueError("outbox batch size is invalid")
        if not 1 <= self.max_concurrency <= min(32, self.batch_size):
            raise ValueError("outbox concurrency is invalid")
        if (
            not 0.1 <= self.retry_base_seconds <= 60
            or not 1 <= self.retry_max_seconds <= 3600
            or self.retry_max_seconds < self.retry_base_seconds
        ):
            raise ValueError("outbox retry bounds are invalid")
        if not 0.1 <= self.poll_interval_seconds <= 60:
            raise ValueError("outbox polling interval is invalid")
        if not 0.1 <= self.connect_timeout_seconds <= 10:
            raise ValueError("outbox connect timeout is invalid")
        if not 0.1 <= self.response_timeout_seconds <= 30:
            raise ValueError("outbox response timeout is invalid")
        if not 30 <= self.acknowledgement_max_age_seconds <= 3600:
            raise ValueError("outbox acknowledgement age is invalid")
        if not 5 <= self.lease_seconds <= 600:
            raise ValueError("outbox lease is invalid")
        minimum_lease = (
            math.ceil(3 * self.connect_timeout_seconds + 2 * self.response_timeout_seconds) + 1
        )
        if self.lease_seconds < minimum_lease:
            raise ValueError("outbox lease does not cover a bounded delivery attempt")

    @classmethod
    def from_settings(cls, settings: Settings) -> OutboxWorkerConfig:
        return cls(
            batch_size=settings.outbox_batch_size,
            max_concurrency=settings.outbox_max_concurrency,
            poll_interval_seconds=settings.outbox_poll_interval_seconds,
            lease_seconds=settings.outbox_lease_seconds,
            connect_timeout_seconds=settings.outbox_connect_timeout_seconds,
            response_timeout_seconds=settings.outbox_response_timeout_seconds,
            retry_base_seconds=settings.outbox_retry_base_seconds,
            retry_max_seconds=settings.outbox_retry_max_seconds,
            acknowledgement_max_age_seconds=settings.outbox_acknowledgement_max_age_seconds,
        )


class DestinationRegistry(Protocol):
    def get(self, key: str) -> DeliveryDestination | None: ...


class DnsResolver(Protocol):
    async def resolve(self, hostname: str, port: int) -> Sequence[str]: ...


class CredentialProvider(Protocol):
    async def headers_for(self, destination_key: str) -> Mapping[str, str]: ...


class DeliveryTransport(Protocol):
    async def send(
        self,
        claim: DeliveryClaim,
        destination: ResolvedDestination,
        credential_headers: Mapping[str, str],
    ) -> TransportResponse: ...


class AcknowledgementVerifier(Protocol):
    async def verify(self, acknowledgement: BrokerAcknowledgement, payload: bytes) -> bool: ...


class DeliveryError(RuntimeError):
    """A delivery failed with a public, non-sensitive diagnostic code."""

    def __init__(
        self,
        code: str,
        *,
        permanent: bool = False,
        status_code: int | None = None,
    ) -> None:
        if not _SAFE_CODE.fullmatch(code):
            raise ValueError("delivery diagnostic code is invalid")
        self.code = code
        self.permanent = permanent
        self.status_code = (
            status_code if status_code is not None and 100 <= status_code <= 599 else None
        )
        super().__init__(code)


class StaticDestinationRegistry:
    """Immutable destinations loaded from trusted deployment configuration."""

    def __init__(self, destinations: Sequence[DeliveryDestination]) -> None:
        if len(destinations) > 256:
            raise ValueError("destination registry exceeds maximum size")
        values = {value.key: value for value in destinations}
        if len(values) != len(destinations):
            raise ValueError("destination keys must be unique")
        if any(not value.key or len(value.key) > 128 for value in destinations):
            raise ValueError("destination keys must contain 1 to 128 characters")
        self._values = values

    def get(self, key: str) -> DeliveryDestination | None:
        return self._values.get(key)


class SystemDnsResolver:
    """Resolve through the operating system without retaining stale answers."""

    def __init__(self, timeout_seconds: float = 3.0) -> None:
        if not 0.1 <= timeout_seconds <= 10.0:
            raise ValueError("DNS timeout must be between 0.1 and 10 seconds")
        self._timeout_seconds = timeout_seconds

    async def resolve(self, hostname: str, port: int) -> Sequence[str]:
        loop = asyncio.get_running_loop()
        try:
            records = await asyncio.wait_for(
                loop.getaddrinfo(
                    hostname,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=socket.IPPROTO_TCP,
                ),
                timeout=self._timeout_seconds,
            )
        except (OSError, TimeoutError) as exc:
            raise DeliveryError("DNS_UNAVAILABLE") from exc
        return tuple(dict.fromkeys(str(record[4][0]) for record in records))


class PinnedHttpsTransport:
    """Minimal HTTPS/1.1 transport that connects only to prevalidated IPs."""

    def __init__(
        self,
        *,
        connect_timeout_seconds: float,
        response_timeout_seconds: float,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if not 0.1 <= connect_timeout_seconds <= 10:
            raise ValueError("connect timeout must be between 0.1 and 10 seconds")
        if not 0.1 <= response_timeout_seconds <= 30:
            raise ValueError("response timeout must be between 0.1 and 30 seconds")
        self._connect_timeout = connect_timeout_seconds
        self._response_timeout = response_timeout_seconds
        self._ssl_context = ssl_context or ssl.create_default_context()

    async def send(
        self,
        claim: DeliveryClaim,
        destination: ResolvedDestination,
        credential_headers: Mapping[str, str],
    ) -> TransportResponse:
        payload = _canonical_bytes(claim.redacted_payload)
        if len(payload) > _MAX_PAYLOAD_BYTES:
            raise DeliveryError("PAYLOAD_TOO_LARGE", permanent=True)
        headers = _validated_credential_headers(credential_headers)
        host_header = destination.hostname
        try:
            if ipaddress.ip_address(destination.hostname).version == 6:
                host_header = f"[{destination.hostname}]"
        except ValueError:
            pass
        if destination.port != 443:
            host_header = f"{host_header}:{destination.port}"
        request_headers = {
            "Host": host_header,
            "Connection": "close",
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "Dusk-Delivery-ID": str(claim.delivery_id),
            "Idempotency-Key": str(claim.delivery_id),
            **headers,
        }
        encoded_headers = "".join(f"{key}: {value}\r\n" for key, value in request_headers.items())
        request = (
            f"POST {destination.path} HTTP/1.1\r\n{encoded_headers}\r\n".encode("ascii") + payload
        )
        last_error: BaseException | None = None
        for address in destination.addresses:
            writer: asyncio.StreamWriter | None = None
            try:
                reader, opened_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        address,
                        destination.port,
                        ssl=self._ssl_context,
                        server_hostname=destination.hostname,
                        limit=_MAX_HEADER_BYTES + 1,
                    ),
                    timeout=self._connect_timeout,
                )
                writer = opened_writer
                opened_writer.write(request)
                await asyncio.wait_for(opened_writer.drain(), timeout=self._response_timeout)
                header_block = await asyncio.wait_for(
                    reader.readuntil(b"\r\n\r\n"), timeout=self._response_timeout
                )
                return _parse_response_headers(header_block)
            except DeliveryError:
                raise
            except (
                OSError,
                TimeoutError,
                asyncio.IncompleteReadError,
                asyncio.LimitOverrunError,
            ) as exc:
                last_error = exc
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except OSError:
                        pass
        raise DeliveryError("TRANSPORT_UNAVAILABLE") from last_error


async def resolve_destination(
    destination: DeliveryDestination,
    resolver: DnsResolver,
) -> ResolvedDestination:
    parsed = _parse_destination_url(destination.url)
    if parsed.hostname is None:
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True)
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port or 443
    addresses = tuple(dict.fromkeys(await resolver.resolve(hostname, port)))
    if not addresses:
        raise DeliveryError("DNS_UNAVAILABLE")
    if len(addresses) > 4:
        raise DeliveryError("DNS_RESPONSE_INVALID", permanent=True)
    try:
        parsed_addresses = tuple(ipaddress.ip_address(value) for value in addresses)
    except ValueError as exc:
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True) from exc
    if any(
        not value.is_global
        or value.is_loopback
        or value.is_private
        or value.is_link_local
        or value.is_multicast
        or value.is_reserved
        or value.is_unspecified
        for value in parsed_addresses
    ):
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True)
    path = parsed.path or "/"
    return ResolvedDestination(
        destination=destination,
        hostname=hostname,
        port=port,
        path=path,
        addresses=tuple(str(value) for value in parsed_addresses),
    )


class OutboxWorker:
    """Claim, deliver, and finalize a bounded batch of durable intents."""

    def __init__(
        self,
        *,
        database: Database,
        destinations: DestinationRegistry,
        resolver: DnsResolver,
        credentials: CredentialProvider,
        transport: DeliveryTransport,
        acknowledgement_verifier: AcknowledgementVerifier,
        config: OutboxWorkerConfig,
        worker_id: UUID | None = None,
        random: Callable[[], float] = random_module.random,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        telemetry: Telemetry | None = None,
    ) -> None:
        self._database = database
        self._destinations = destinations
        self._resolver = resolver
        self._credentials = credentials
        self._transport = transport
        self._acknowledgement_verifier = acknowledgement_verifier
        self._config = config
        self._worker_id = worker_id or uuid4()
        self._random = random
        self._clock = clock
        self._telemetry = telemetry
        self._stopping = asyncio.Event()

    def with_telemetry(self, telemetry: Telemetry) -> OutboxWorker:
        return OutboxWorker(
            database=self._database,
            destinations=self._destinations,
            resolver=self._resolver,
            credentials=self._credentials,
            transport=self._transport,
            acknowledgement_verifier=self._acknowledgement_verifier,
            config=self._config,
            worker_id=self._worker_id,
            random=self._random,
            clock=self._clock,
            telemetry=telemetry,
        )

    async def run_once(self) -> WorkerRunStats:
        claims, exhausted = await self._claim_batch()
        if not claims:
            return WorkerRunStats(dead_lettered=exhausted)
        semaphore = asyncio.Semaphore(self._config.max_concurrency)

        async def deliver(claim: DeliveryClaim) -> WorkerRunStats:
            async with semaphore:
                return await self._deliver(claim)

        results = await asyncio.gather(*(deliver(claim) for claim in claims))
        return WorkerRunStats(
            claimed=len(claims),
            delivered=sum(value.delivered for value in results),
            retried=sum(value.retried for value in results),
            dead_lettered=exhausted + sum(value.dead_lettered for value in results),
            stale_results=sum(value.stale_results for value in results),
        )

    async def run_forever(self) -> None:
        while not self._stopping.is_set():
            try:
                stats = await self.run_once()
                if stats.claimed or stats.dead_lettered:
                    logger.info(
                        "outbox batch claimed=%d delivered=%d retried=%d "
                        "dead_lettered=%d stale_results=%d",
                        stats.claimed,
                        stats.delivered,
                        stats.retried,
                        stats.dead_lettered,
                        stats.stale_results,
                        extra={"event_code": "outbox.batch_completed"},
                    )
            except Exception:  # noqa: BLE001 - diagnostics must not expose provider details
                logger.error("outbox batch failed", extra={"event_code": "outbox.batch_failed"})
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=self._config.poll_interval_seconds
                )
            except TimeoutError:
                pass

    def stop(self) -> None:
        self._stopping.set()

    async def _claim_batch(self) -> tuple[list[DeliveryClaim], int]:
        async with self._database.transaction() as session:
            now = await _database_now(session)
            rows = list(
                (
                    await session.scalars(
                        select(OutboxDelivery)
                        .where(
                            or_(
                                (OutboxDelivery.state == "PENDING")
                                & (OutboxDelivery.next_attempt_at <= now),
                                (OutboxDelivery.state == "IN_FLIGHT")
                                & (OutboxDelivery.locked_until < now),
                            )
                        )
                        .order_by(OutboxDelivery.next_attempt_at, OutboxDelivery.id)
                        .limit(self._config.batch_size)
                        .with_for_update(skip_locked=True)
                    )
                ).all()
            )
            claims: list[DeliveryClaim] = []
            exhausted = 0
            for row in rows:
                if row.attempt_count >= row.max_attempts:
                    row.state = "DEAD_LETTER"
                    row.locked_until = None
                    row.lease_owner = None
                    row.safe_diagnostic_code = "ATTEMPTS_EXHAUSTED"
                    row.state_version += 1
                    await _refresh_decision_status(session, row.tenant_id, row.decision_id)
                    exhausted += 1
                    continue
                row.state = "IN_FLIGHT"
                row.attempt_count += 1
                row.last_attempt_at = now
                row.locked_until = now + timedelta(seconds=self._config.lease_seconds)
                row.lease_owner = self._worker_id
                row.state_version += 1
                row.safe_diagnostic_code = None
                row.last_http_status = None
                claims.append(_claim(row, self._worker_id))
            await session.flush()
            return claims, exhausted

    async def _deliver(self, claim: DeliveryClaim) -> WorkerRunStats:
        trace_id = claim.redacted_payload.get("trace_id")
        safe_trace_id = trace_id if isinstance(trace_id, str) and len(trace_id) <= 64 else None
        if self._telemetry is None:
            return await self._deliver_attempt(claim)
        with self._telemetry.stage(
            "outbox",
            decision_trace_id=safe_trace_id,
            decision_id=str(claim.decision_id),
            delivery_id=str(claim.delivery_id),
        ):
            return await self._deliver_attempt(claim)

    async def _deliver_attempt(self, claim: DeliveryClaim) -> WorkerRunStats:
        destination = self._destinations.get(claim.destination_key)
        if destination is None or destination.kind.value != claim.destination_kind:
            return await self._finalize_failure(
                claim, DeliveryError("DESTINATION_UNAVAILABLE", permanent=True)
            )
        try:
            resolved = await asyncio.wait_for(
                resolve_destination(destination, self._resolver),
                timeout=self._config.connect_timeout_seconds,
            )
            credential_headers = await asyncio.wait_for(
                self._credentials.headers_for(destination.key),
                timeout=self._config.connect_timeout_seconds,
            )
            response = await asyncio.wait_for(
                self._transport.send(claim, resolved, credential_headers),
                timeout=(
                    self._config.connect_timeout_seconds + self._config.response_timeout_seconds
                ),
            )
            if not 200 <= response.status_code < 300:
                raise DeliveryError("HTTP_REJECTED", status_code=response.status_code)
            acknowledgement: BrokerAcknowledgement | None = None
            if destination.kind is DestinationKind.ENFORCEMENT_BROKER:
                acknowledgement = _parse_acknowledgement(response.headers)
                self._validate_acknowledgement_binding(claim, acknowledgement)
                payload = acknowledgement_signing_payload(acknowledgement)
                if self._telemetry is None:
                    verified = await asyncio.wait_for(
                        self._acknowledgement_verifier.verify(acknowledgement, payload),
                        timeout=self._config.response_timeout_seconds,
                    )
                else:
                    trace_id = claim.redacted_payload.get("trace_id")
                    safe_trace_id = (
                        trace_id if isinstance(trace_id, str) and len(trace_id) <= 64 else None
                    )
                    with self._telemetry.stage(
                        "broker_acknowledgement",
                        decision_trace_id=safe_trace_id,
                        decision_id=str(claim.decision_id),
                        delivery_id=str(claim.delivery_id),
                    ):
                        verified = await asyncio.wait_for(
                            self._acknowledgement_verifier.verify(acknowledgement, payload),
                            timeout=self._config.response_timeout_seconds,
                        )
                if not verified:
                    raise DeliveryError("ACKNOWLEDGEMENT_INVALID")
            return await self._finalize_success(
                claim,
                status_code=response.status_code,
                acknowledgement=acknowledgement,
            )
        except DeliveryError as exc:
            return await self._finalize_failure(claim, exc)
        except Exception:  # noqa: BLE001 - credentials/providers stay behind a safe code
            return await self._finalize_failure(claim, DeliveryError("DELIVERY_UNAVAILABLE"))

    def _validate_acknowledgement_binding(
        self, claim: DeliveryClaim, acknowledgement: BrokerAcknowledgement
    ) -> None:
        if (
            acknowledgement.tenant_id != claim.tenant_id
            or acknowledgement.decision_id != claim.decision_id
            or acknowledgement.delivery_id != claim.delivery_id
        ):
            raise DeliveryError("ACKNOWLEDGEMENT_INVALID")

    def _validate_acknowledgement_freshness(
        self, acknowledgement: BrokerAcknowledgement, trusted_now: datetime
    ) -> None:
        age = (trusted_now - acknowledgement.issued_at).total_seconds()
        if age < -30 or age > self._config.acknowledgement_max_age_seconds:
            raise DeliveryError("ACKNOWLEDGEMENT_STALE")

    async def _finalize_success(
        self,
        claim: DeliveryClaim,
        *,
        status_code: int,
        acknowledgement: BrokerAcknowledgement | None,
    ) -> WorkerRunStats:
        async with self._database.transaction() as session:
            row = await _locked_claim(session, claim)
            if row is None:
                return WorkerRunStats(stale_results=1)
            now = await _database_now(session)
            if acknowledgement is not None:
                self._validate_acknowledgement_freshness(acknowledgement, now)
            row.state = "DELIVERED"
            row.delivered_at = now
            row.locked_until = None
            row.lease_owner = None
            row.last_http_status = status_code
            row.safe_diagnostic_code = None
            row.state_version += 1
            if acknowledgement is not None:
                evidence = acknowledgement_signing_payload(acknowledgement)
                row.acknowledgement_digest = hashlib.sha256(
                    evidence + acknowledgement.signature
                ).digest()
                row.acknowledgement_evidence = cast(dict[str, object], json.loads(evidence))
                row.acknowledgement_signature = acknowledgement.signature
                row.acknowledgement_outcome = acknowledgement.outcome
                row.acknowledged_at = now
            await _refresh_decision_status(session, claim.tenant_id, claim.decision_id)
            return WorkerRunStats(delivered=1)

    async def _finalize_failure(
        self, claim: DeliveryClaim, failure: DeliveryError
    ) -> WorkerRunStats:
        async with self._database.transaction() as session:
            row = await _locked_claim(session, claim)
            if row is None:
                return WorkerRunStats(stale_results=1)
            now = await _database_now(session)
            dead_letter = failure.permanent or row.attempt_count >= row.max_attempts
            row.state = "DEAD_LETTER" if dead_letter else "PENDING"
            row.locked_until = None
            row.lease_owner = None
            row.safe_diagnostic_code = failure.code
            row.last_http_status = failure.status_code
            row.state_version += 1
            if dead_letter:
                await _refresh_decision_status(session, claim.tenant_id, claim.decision_id)
                return WorkerRunStats(dead_lettered=1)
            row.next_attempt_at = now + timedelta(seconds=self._retry_delay(row.attempt_count))
            return WorkerRunStats(retried=1)

    def _retry_delay(self, attempt_count: int) -> float:
        return exponential_backoff_delay(
            attempt_count=attempt_count,
            base_seconds=self._config.retry_base_seconds,
            maximum_seconds=self._config.retry_max_seconds,
            random_value=self._random(),
        )


def exponential_backoff_delay(
    *,
    attempt_count: int,
    base_seconds: float,
    maximum_seconds: float,
    random_value: float,
) -> float:
    """Return bounded exponential delay with equal jitter."""
    if attempt_count < 1 or base_seconds <= 0 or maximum_seconds < base_seconds:
        raise ValueError("retry delay configuration is invalid")
    exponent = min(attempt_count - 1, 30)
    cap = min(maximum_seconds, base_seconds * (2**exponent))
    bounded_random = min(max(random_value, 0.0), 1.0)
    return float(cap * (0.5 + bounded_random * 0.5))


def acknowledgement_signing_payload(acknowledgement: BrokerAcknowledgement) -> bytes:
    return _canonical_bytes(
        {
            "version": acknowledgement.version,
            "tenant_id": str(acknowledgement.tenant_id),
            "decision_id": str(acknowledgement.decision_id),
            "delivery_id": str(acknowledgement.delivery_id),
            "outcome": acknowledgement.outcome,
            "issued_at": acknowledgement.issued_at.astimezone(UTC).isoformat(
                timespec="microseconds"
            ),
            "nonce": acknowledgement.nonce,
            "key_id": acknowledgement.key_id,
        }
    )


def _parse_destination_url(value: str) -> SplitResult:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True) from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\r" in value
        or "\n" in value
        or parsed.port == 0
    ):
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True)
    try:
        parsed.path.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True) from exc
    if any(ord(character) <= 32 or ord(character) == 127 for character in parsed.path):
        raise DeliveryError("DESTINATION_PROHIBITED", permanent=True)
    return parsed


def _validated_credential_headers(values: Mapping[str, str]) -> dict[str, str]:
    if len(values) > 16:
        raise DeliveryError("CREDENTIAL_HEADERS_INVALID", permanent=True)
    result: dict[str, str] = {}
    for key, value in values.items():
        if (
            not _HEADER_NAME.fullmatch(key)
            or key.lower() in _RESERVED_HEADERS
            or not value
            or len(value) > 8192
            or "\r" in value
            or "\n" in value
        ):
            raise DeliveryError("CREDENTIAL_HEADERS_INVALID", permanent=True)
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise DeliveryError("CREDENTIAL_HEADERS_INVALID", permanent=True) from exc
        result[key] = value
    return result


def _parse_response_headers(value: bytes) -> TransportResponse:
    if len(value) > _MAX_HEADER_BYTES or not value.endswith(b"\r\n\r\n"):
        raise DeliveryError("RESPONSE_HEADERS_INVALID")
    try:
        lines = value[:-4].decode("iso-8859-1").split("\r\n")
        status_parts = lines[0].split(" ", 2)
        status = int(status_parts[1])
    except (IndexError, ValueError) as exc:
        raise DeliveryError("RESPONSE_HEADERS_INVALID") from exc
    if len(status_parts) < 2 or not 100 <= status <= 599:
        raise DeliveryError("RESPONSE_HEADERS_INVALID")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            raise DeliveryError("RESPONSE_HEADERS_INVALID")
        key, item = line.split(":", 1)
        normalized = key.strip().lower()
        item = item.strip()
        if not _HEADER_NAME.fullmatch(normalized) or normalized in headers:
            raise DeliveryError("RESPONSE_HEADERS_INVALID")
        headers[normalized] = item
    return TransportResponse(status, headers)


def _parse_acknowledgement(headers: Mapping[str, str]) -> BrokerAcknowledgement:
    required = (
        "dusk-ack-version",
        "dusk-ack-tenant-id",
        "dusk-ack-decision-id",
        "dusk-ack-delivery-id",
        "dusk-ack-outcome",
        "dusk-ack-issued-at",
        "dusk-ack-nonce",
        "dusk-ack-key-id",
        "dusk-ack-signature",
    )
    try:
        if any(key not in headers for key in required):
            raise ValueError
        if headers["dusk-ack-version"] != "dusk.broker-ack.v1":
            raise ValueError
        outcome = headers["dusk-ack-outcome"]
        if outcome not in {"EXECUTED", "REJECTED"}:
            raise ValueError
        issued_at = datetime.fromisoformat(headers["dusk-ack-issued-at"].replace("Z", "+00:00"))
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError
        nonce = headers["dusk-ack-nonce"]
        key_id = headers["dusk-ack-key-id"]
        if (
            not 1 <= len(nonce) <= 256
            or not 1 <= len(key_id) <= 512
            or not nonce.isascii()
            or not key_id.isascii()
        ):
            raise ValueError
        encoded_signature = headers["dusk-ack-signature"]
        if not 1 <= len(encoded_signature) <= 10_924:
            raise ValueError
        signature = base64.b64decode(encoded_signature, altchars=b"-_", validate=True)
        if not signature or len(signature) > 8192:
            raise ValueError
        return BrokerAcknowledgement(
            version="dusk.broker-ack.v1",
            tenant_id=UUID(headers["dusk-ack-tenant-id"]),
            decision_id=UUID(headers["dusk-ack-decision-id"]),
            delivery_id=UUID(headers["dusk-ack-delivery-id"]),
            outcome=cast(Literal["EXECUTED", "REJECTED"], outcome),
            issued_at=issued_at.astimezone(UTC),
            nonce=nonce,
            key_id=key_id,
            signature=signature,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise DeliveryError("ACKNOWLEDGEMENT_INVALID") from exc


def _claim(row: OutboxDelivery, worker_id: UUID) -> DeliveryClaim:
    return DeliveryClaim(
        id=row.id,
        tenant_id=row.tenant_id,
        decision_id=row.decision_id,
        delivery_id=row.delivery_id,
        destination_key=row.destination_key,
        destination_kind=row.destination_kind,
        delivery_kind=row.delivery_kind,
        redacted_payload=cast(dict[str, object], row.redacted_payload),
        attempt_count=row.attempt_count,
        max_attempts=row.max_attempts,
        state_version=row.state_version,
        lease_owner=worker_id,
    )


async def _locked_claim(session: AsyncSession, claim: DeliveryClaim) -> OutboxDelivery | None:
    return cast(
        OutboxDelivery | None,
        await session.scalar(
            select(OutboxDelivery)
            .where(
                OutboxDelivery.id == claim.id,
                OutboxDelivery.tenant_id == claim.tenant_id,
                OutboxDelivery.state == "IN_FLIGHT",
                OutboxDelivery.lease_owner == claim.lease_owner,
                OutboxDelivery.state_version == claim.state_version,
            )
            .with_for_update()
        ),
    )


async def _refresh_decision_status(
    session: AsyncSession, tenant_id: UUID, decision_id: UUID
) -> None:
    decision = await session.scalar(
        select(Decision)
        .where(Decision.tenant_id == tenant_id, Decision.id == decision_id)
        .with_for_update()
    )
    if decision is None:
        raise RuntimeError("outbox decision is missing")
    deliveries = list(
        (
            await session.scalars(
                select(OutboxDelivery).where(
                    OutboxDelivery.tenant_id == tenant_id,
                    OutboxDelivery.decision_id == decision_id,
                )
            )
        ).all()
    )
    if any(
        value.destination_kind == DestinationKind.ENFORCEMENT_BROKER.value
        and value.acknowledgement_outcome == "EXECUTED"
        for value in deliveries
    ):
        decision.response_status = "EXECUTED"
    elif any(
        value.state == "DEAD_LETTER" or value.acknowledgement_outcome == "REJECTED"
        for value in deliveries
    ):
        decision.response_status = "FAILED"
    elif deliveries and all(value.state == "DELIVERED" for value in deliveries):
        decision.response_status = "DELIVERED"
    else:
        decision.response_status = "DELIVERY_PENDING"


async def _database_now(session: AsyncSession) -> datetime:
    value = await session.scalar(text("SELECT clock_timestamp()"))
    if not isinstance(value, datetime):
        raise RuntimeError("database clock unavailable")
    return value


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
