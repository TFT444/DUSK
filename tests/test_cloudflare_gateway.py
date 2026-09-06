import json
import urllib.error
import urllib.request

import pytest

from dusk.integrations.cloudflare import (
    CloudflareGatewayClient,
    GatewayBlockedError,
    GatewayError,
    _build_no_redirect_opener,
)


@pytest.mark.parametrize("endpoint", ["http://gateway.example", "file:///etc/passwd", "ftp://host"])
def test_non_https_endpoints_are_rejected(endpoint: str) -> None:
    with pytest.raises(ValueError, match="HTTPS"):
        CloudflareGatewayClient(endpoint, "secret")


@pytest.mark.parametrize("destination", ["http://other.example", "https://other.example"])
def test_redirect_callback_refuses_forwarding(destination: str) -> None:
    opener = _build_no_redirect_opener()
    handler = next(h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler))
    with pytest.raises(GatewayBlockedError, match="redirect"):
        handler.redirect_request(
            urllib.request.Request("https://gateway.example"),
            None,
            302,
            "Found",
            {},
            destination,
        )


class _MockResponse:
    def __init__(self, body: bytes = b'{"id":"r1"}') -> None:
        self._body = body

    def __enter__(self) -> "_MockResponse":
        return self

    def __exit__(self, *args: object) -> None:
        pass

    def read(self) -> bytes:
        return self._body


class _MockOpener:
    def __init__(self, response: _MockResponse | None = None) -> None:
        self.calls: list[tuple[object, float]] = []
        self._response = response or _MockResponse()

    def open(self, request: object, timeout: float = 0) -> _MockResponse:
        self.calls.append((request, timeout))
        return self._response


def test_blocked_action_never_reaches_gateway() -> None:
    client = CloudflareGatewayClient("https://gateway.example/v1", "secret")
    with pytest.raises(GatewayBlockedError):
        client.forward(
            {"messages": [{"role": "user", "content": "unsafe"}]},
            action={"action_type": "firewall_rule_change"},
            gate=lambda _: "BLOCK",
        )


def test_would_block_decision_raises_gateway_blocked_error() -> None:
    client = CloudflareGatewayClient("https://gateway.example/v1", "secret")
    with pytest.raises(GatewayBlockedError, match="WOULD-BLOCK"):
        client.forward(
            {"messages": []},
            action={"action_type": "dangerous"},
            gate=lambda _: "WOULD-BLOCK",
        )


def test_allowed_action_is_forwarded_with_bearer_token() -> None:
    opener = _MockOpener()
    payload = {"messages": [{"role": "user", "content": "hello"}]}
    result = CloudflareGatewayClient(
        "https://gateway.example/v1", "secret", _opener=opener
    ).forward(payload, action={"action_type": "read"}, gate=lambda _: "ALLOW")

    request, _ = opener.calls[0]
    assert result == {"id": "r1"}
    assert request.get_header("Authorization") == "Bearer secret"
    assert json.loads(request.data) == payload


def test_http_error_raises_gateway_error() -> None:
    class _FailOpener:
        def open(self, request: object, timeout: float = 0) -> None:
            raise urllib.error.HTTPError(
                "https://gateway.example/v1", 429, "Too Many Requests", {}, None
            )

    with pytest.raises(GatewayError, match="HTTP 429"):
        CloudflareGatewayClient(
            "https://gateway.example/v1", "secret", _opener=_FailOpener()
        ).forward({"messages": []}, action={"action_type": "read"}, gate=lambda _: "ALLOW")


def test_url_error_raises_gateway_error() -> None:
    class _FailOpener:
        def open(self, request: object, timeout: float = 0) -> None:
            raise urllib.error.URLError("connection refused")

    with pytest.raises(GatewayError, match="connection failed"):
        CloudflareGatewayClient(
            "https://gateway.example/v1", "secret", _opener=_FailOpener()
        ).forward({"messages": []}, action={"action_type": "read"}, gate=lambda _: "ALLOW")


def test_whitespace_only_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="API token"):
        CloudflareGatewayClient("https://gateway.example/v1", "   ")
