"""Cryptographic fixtures isolated to the OIDC contract tests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from dusk_control_plane.identity import IdentityProviderUnavailableError


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey
    jwk: dict[str, object]


def signing_key(kid: str) -> SigningKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    document = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    document.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return SigningKey(kid=kid, private_key=private_key, jwk=document)


def token(key: SigningKey, claims: Mapping[str, Any], *, algorithm: str = "RS256") -> str:
    return jwt.encode(
        dict(claims),
        key.private_key,
        algorithm=algorithm,
        headers={"kid": key.kid},
    )


@dataclass
class SequenceFetcher:
    results: list[Mapping[str, object] | Exception]
    calls: int = 0

    async def fetch(self) -> Mapping[str, object]:
        index = min(self.calls, len(self.results) - 1)
        self.calls += 1
        result = self.results[index]
        if isinstance(result, Exception):
            raise result
        return result


def unavailable() -> IdentityProviderUnavailableError:
    return IdentityProviderUnavailableError()
