"""Cloudflare AI Gateway adapter with a DUSK pre-forward decision gate."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any
from urllib.request import Request


class GatewayBlockedError(PermissionError):
    """Raised when DUSK refuses to forward an action to the Gateway."""


class GatewayError(IOError):
    """Raised when the Gateway request fails due to a network or server error."""


def _build_no_redirect_opener() -> urllib.request.OpenerDirector:
    """Build an opener that blocks HTTP redirects instead of following them.

    urlopen follows redirects by default. A gateway endpoint that redirects
    to an http:// URL would bypass the HTTPS-only constructor check. This
    opener raises GatewayBlockedError on any 3xx response instead.
    """

    class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self, _req: Request, _fp: object, _code: int, _msg: str, _headers: object, newurl: str
        ) -> None:
            raise GatewayBlockedError(
                f"Gateway redirect to {newurl!r} refused: HTTPS-only enforcement"
            )

    return urllib.request.build_opener(_NoRedirectHandler())


class CloudflareGatewayClient:
    def __init__(
        self,
        endpoint: str,
        api_token: str,
        *,
        timeout: float = 15.0,
        _opener: urllib.request.OpenerDirector | None = None,
    ) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("Cloudflare Gateway endpoint must use HTTPS")
        if not api_token or not api_token.strip():
            raise ValueError("Cloudflare Gateway API token is required")
        self._endpoint = endpoint.rstrip("/")
        self._api_token = api_token
        self._timeout = timeout
        self._opener = _opener or _build_no_redirect_opener()

    def forward(
        self,
        payload: dict[str, Any],
        *,
        action: dict[str, Any],
        gate: Callable[[dict[str, Any]], str],
    ) -> dict[str, Any]:
        decision = gate(action)
        if decision != "ALLOW":
            raise GatewayBlockedError(f"DUSK decision {decision} blocked Gateway request")
        # The constructor requires HTTPS and the default opener refuses redirects.
        request = Request(  # noqa: S310
            self._endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            raise GatewayError(f"Gateway returned HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise GatewayError(f"Gateway connection failed: {exc.reason}") from exc
        decoded = json.loads(body)
        if not isinstance(decoded, dict):
            raise ValueError("Cloudflare Gateway response must be a JSON object")
        return decoded
