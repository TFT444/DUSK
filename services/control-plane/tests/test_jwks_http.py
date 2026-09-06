"""Bounded HTTPS JWKS transport tests using an isolated HTTP transport."""

from __future__ import annotations

import httpx2
import pytest

from dusk_control_plane.identity import HttpxJwksFetcher, IdentityProviderUnavailableError


def fetcher(handler: object, *, max_bytes: int = 1024) -> HttpxJwksFetcher:
    return HttpxJwksFetcher(
        uri="https://identity.example.test/.well-known/jwks.json",
        timeout_seconds=0.5,
        max_bytes=max_bytes,
        transport=httpx2.MockTransport(handler),
    )


@pytest.mark.anyio
async def test_fetcher_accepts_only_bounded_json_object() -> None:
    def response(_request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(200, json={"keys": [{"kid": "current"}]})

    assert await fetcher(response).fetch() == {"keys": [{"kid": "current"}]}


@pytest.mark.parametrize(
    "response",
    [
        httpx2.Response(302, headers={"Location": "https://redirect.example/jwks"}),
        httpx2.Response(503),
        httpx2.Response(200, content=b"not-json"),
        httpx2.Response(200, content=b'{"keys": [], "keys": []}'),
        httpx2.Response(200, json=[{"keys": []}]),
        httpx2.Response(200, headers={"Content-Length": "not-a-number"}, content=b"{}"),
        httpx2.Response(200, headers={"Content-Length": "2048"}, content=b"{}"),
        httpx2.Response(200, content=b"x" * 1025),
    ],
)
@pytest.mark.anyio
async def test_fetcher_rejects_redirects_errors_malformed_and_oversized_responses(
    response: httpx2.Response,
) -> None:
    def handler(request: httpx2.Request) -> httpx2.Response:
        response.request = request
        return response

    with pytest.raises(IdentityProviderUnavailableError):
        await fetcher(handler).fetch()


@pytest.mark.anyio
async def test_fetcher_maps_network_failure_to_provider_unavailable() -> None:
    def failure(request: httpx2.Request) -> httpx2.Response:
        raise httpx2.ConnectError("sensitive internal diagnostic", request=request)

    with pytest.raises(IdentityProviderUnavailableError) as captured:
        await fetcher(failure).fetch()
    assert "sensitive" not in str(captured.value)
