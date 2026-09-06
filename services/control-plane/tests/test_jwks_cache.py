"""JWKS rotation, outage, cache-bound, and concurrency tests."""

from __future__ import annotations

import asyncio

import pytest
from identity_helpers import SequenceFetcher, signing_key, unavailable

from dusk_control_plane.identity import (
    AuthenticationRejectedError,
    IdentityProviderUnavailableError,
    JwksCache,
)


class Clock:
    value = 0.0

    def __call__(self) -> float:
        return self.value


def cache(fetcher: SequenceFetcher, clock: Clock) -> JwksCache:
    return JwksCache(
        fetcher=fetcher,
        algorithms=("RS256",),
        ttl_seconds=30,
        min_refresh_seconds=1,
        max_keys=4,
        monotonic=clock,
    )


@pytest.mark.anyio
async def test_unknown_kid_refreshes_once_and_accepts_rotated_key() -> None:
    first = signing_key("first")
    rotated = signing_key("rotated")
    fetcher = SequenceFetcher([{"keys": [first.jwk]}, {"keys": [rotated.jwk]}])
    clock = Clock()
    jwks = cache(fetcher, clock)

    assert (await jwks.get("first")).key_id == "first"
    assert (await jwks.get("rotated")).key_id == "rotated"
    assert fetcher.calls == 2


@pytest.mark.anyio
async def test_expired_cache_never_falls_back_to_stale_key_during_outage() -> None:
    key = signing_key("current")
    fetcher = SequenceFetcher([{"keys": [key.jwk]}, unavailable()])
    clock = Clock()
    jwks = cache(fetcher, clock)

    await jwks.get("current")
    clock.value = 31
    with pytest.raises(IdentityProviderUnavailableError):
        await jwks.get("current")


@pytest.mark.anyio
async def test_identity_provider_recovery_revalidates_without_stale_bypass() -> None:
    first = signing_key("first")
    rotated = signing_key("rotated")
    fetcher = SequenceFetcher([{"keys": [first.jwk]}, unavailable(), {"keys": [rotated.jwk]}])
    clock = Clock()
    jwks = cache(fetcher, clock)

    assert (await jwks.get("first")).key_id == "first"
    clock.value = 31
    with pytest.raises(IdentityProviderUnavailableError):
        await jwks.get("first")
    with pytest.raises(AuthenticationRejectedError, match="unknown_key"):
        await jwks.get("first")
    assert (await jwks.get("rotated")).key_id == "rotated"
    assert fetcher.calls == 3


@pytest.mark.anyio
async def test_concurrent_unknown_key_requests_collapse_refresh() -> None:
    key = signing_key("current")
    fetcher = SequenceFetcher([{"keys": [key.jwk]}, {"keys": [key.jwk]}])
    clock = Clock()
    jwks = cache(fetcher, clock)
    await jwks.get("current")
    clock.value = 2

    results = await asyncio.gather(
        *(jwks.get("attacker-controlled") for _ in range(20)), return_exceptions=True
    )

    assert fetcher.calls == 2
    assert all(isinstance(result, AuthenticationRejectedError) for result in results)


@pytest.mark.anyio
async def test_single_algorithm_can_be_applied_to_jwk_without_alg_metadata() -> None:
    key = signing_key("generic-provider-key")
    key.jwk.pop("alg")
    jwks = cache(SequenceFetcher([{"keys": [key.jwk]}]), Clock())

    assert (await jwks.get(key.kid)).algorithm_name == "RS256"


@pytest.mark.parametrize(
    "document",
    [
        {},
        {"keys": []},
        {"keys": [{"kid": "bad", "alg": "HS256", "kty": "oct", "k": "AA"}]},
        {"keys": [{"kid": "duplicate"}, {"kid": "duplicate"}]},
    ],
)
@pytest.mark.anyio
async def test_malformed_or_unsupported_jwks_fails_closed(document: dict[str, object]) -> None:
    jwks = cache(SequenceFetcher([document]), Clock())
    with pytest.raises(IdentityProviderUnavailableError):
        await jwks.get("any")
