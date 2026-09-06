"""Destination security, pinned transport, and bounded retry unit tests."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest

from dusk_control_plane.outbox import (
    DeliveryClaim,
    DeliveryDestination,
    DeliveryError,
    DestinationKind,
    PinnedHttpsTransport,
    ResolvedDestination,
    TransportResponse,
    exponential_backoff_delay,
    resolve_destination,
)


@dataclass
class _Resolver:
    answers: list[tuple[str, ...]]
    calls: int = 0

    async def resolve(self, hostname: str, port: int):
        answer = self.answers[min(self.calls, len(self.answers) - 1)]
        self.calls += 1
        return answer


@pytest.mark.anyio
async def test_destination_requires_https_without_embedded_secrets_or_query() -> None:
    resolver = _Resolver([("8.8.8.8",)])
    invalid = (
        "http://hooks.example.test/path",
        "https://user:password@hooks.example.test/path",
        "https://hooks.example.test/path?token=secret",
        "https://hooks.example.test/path#fragment",
        "https://hooks.example.test/path\r\nInjected: yes",
        "https://hooks.example.test/path with space",
        "https://hooks.example.test:0/path",
    )
    for url in invalid:
        with pytest.raises(DeliveryError) as failure:
            await resolve_destination(
                DeliveryDestination("events", DestinationKind.WEBHOOK, url), resolver
            )
        assert failure.value.code == "DESTINATION_PROHIBITED"
        assert failure.value.permanent is True


@pytest.mark.anyio
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "224.0.0.1",
        "192.0.2.1",
    ],
)
async def test_destination_rejects_every_non_public_address(address: str) -> None:
    with pytest.raises(DeliveryError) as failure:
        await resolve_destination(
            DeliveryDestination(
                "events", DestinationKind.WEBHOOK, "https://hooks.example.test/events"
            ),
            _Resolver([(address,)]),
        )
    assert failure.value.code == "DESTINATION_PROHIBITED"


@pytest.mark.anyio
async def test_mixed_dns_answer_and_rebinding_are_rejected_on_each_attempt() -> None:
    resolver = _Resolver([("8.8.8.8",), ("8.8.8.8", "127.0.0.1")])
    destination = DeliveryDestination(
        "events", DestinationKind.WEBHOOK, "https://hooks.example.test/events"
    )
    resolved = await resolve_destination(destination, resolver)
    assert resolved.addresses == ("8.8.8.8",)
    with pytest.raises(DeliveryError, match="DESTINATION_PROHIBITED"):
        await resolve_destination(destination, resolver)
    assert resolver.calls == 2


def test_exponential_backoff_and_jitter_are_bounded() -> None:
    assert (
        exponential_backoff_delay(
            attempt_count=1, base_seconds=2, maximum_seconds=10, random_value=0
        )
        == 1
    )
    assert (
        exponential_backoff_delay(
            attempt_count=2, base_seconds=2, maximum_seconds=10, random_value=1
        )
        == 4
    )
    assert (
        exponential_backoff_delay(
            attempt_count=100, base_seconds=2, maximum_seconds=10, random_value=1
        )
        == 10
    )
    assert (
        exponential_backoff_delay(
            attempt_count=1, base_seconds=2, maximum_seconds=10, random_value=-1
        )
        == 1
    )
    with pytest.raises(ValueError):
        exponential_backoff_delay(
            attempt_count=0, base_seconds=2, maximum_seconds=10, random_value=0.5
        )


class _Reader:
    async def readuntil(self, separator: bytes) -> bytes:
        assert separator == b"\r\n\r\n"
        return b"HTTP/1.1 204 No Content\r\nX-Request-ID: safe\r\n\r\n"


class _Writer:
    def __init__(self) -> None:
        self.value = b""
        self.closed = False

    def write(self, value: bytes) -> None:
        self.value += value

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _claim() -> DeliveryClaim:
    return DeliveryClaim(
        id=uuid4(),
        tenant_id=uuid4(),
        decision_id=uuid4(),
        delivery_id=uuid4(),
        destination_key="events",
        destination_kind="WEBHOOK",
        delivery_kind="DECISION_RECORDED",
        redacted_payload={"verdict": "ALLOW"},
        attempt_count=1,
        max_attempts=3,
        state_version=2,
        lease_owner=uuid4(),
    )


@pytest.mark.anyio
async def test_transport_pins_validated_ip_preserves_tls_name_and_does_not_read_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    writer = _Writer()

    async def open_connection(host, port, **kwargs):
        calls.append((host, port, kwargs["server_hostname"], kwargs["ssl"]))
        return _Reader(), writer

    monkeypatch.setattr("dusk_control_plane.outbox.asyncio.open_connection", open_connection)
    destination = DeliveryDestination(
        "events", DestinationKind.WEBHOOK, "https://hooks.example.test/events"
    )
    response = await PinnedHttpsTransport(
        connect_timeout_seconds=1,
        response_timeout_seconds=1,
    ).send(
        _claim(),
        ResolvedDestination(destination, "hooks.example.test", 443, "/events", ("8.8.8.8",)),
        {"Authorization": "Bearer injected-at-send-time"},
    )
    assert response == TransportResponse(204, {"x-request-id": "safe"})
    assert calls[0][:3] == ("8.8.8.8", 443, "hooks.example.test")
    assert b"Dusk-Delivery-ID:" in writer.value
    assert b"Idempotency-Key:" in writer.value
    assert b"Bearer injected-at-send-time" in writer.value
    assert writer.closed is True


@pytest.mark.anyio
async def test_transport_rejects_header_injection_and_reserved_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def must_not_connect(*_args, **_kwargs):
        raise AssertionError("network must not be reached")

    monkeypatch.setattr("dusk_control_plane.outbox.asyncio.open_connection", must_not_connect)
    destination = DeliveryDestination(
        "events", DestinationKind.WEBHOOK, "https://hooks.example.test/events"
    )
    resolved = ResolvedDestination(destination, "hooks.example.test", 443, "/", ("8.8.8.8",))
    transport = PinnedHttpsTransport(connect_timeout_seconds=1, response_timeout_seconds=1)
    for headers in ({"Host": "internal"}, {"Authorization": "safe\r\nInjected: yes"}):
        with pytest.raises(DeliveryError) as failure:
            await transport.send(_claim(), resolved, headers)
        assert failure.value.code == "CREDENTIAL_HEADERS_INVALID"
