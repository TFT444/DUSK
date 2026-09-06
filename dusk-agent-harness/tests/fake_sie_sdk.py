"""Minimal HTTP-speaking fake SIE SDK for transport-level fallback tests.

Inject into sys.modules["sie_sdk"] so that dusk.trace.vector._sie_client()
picks it up without the real sie_sdk package installed.  The client makes
actual HTTP POST requests to a thread-based stub server so tests exercise
real socket-level transport (timeout, refused connection, malformed response)
rather than exception injection.

Usage in tests::

    import fake_sie_sdk
    import types, sys

    fake_mod = types.ModuleType("sie_sdk")
    fake_mod.SIEClient = fake_sie_sdk.SIEClient
    monkeypatch.setitem(sys.modules, "sie_sdk", fake_mod)

    fake_types = types.ModuleType("sie_sdk.types")
    fake_types.Item = fake_sie_sdk.Item
    monkeypatch.setitem(sys.modules, "sie_sdk.types", fake_types)
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from typing import Any


class Item:
    """Minimal stand-in for sie_sdk.types.Item."""

    def __init__(
        self,
        text: str | None = None,
        id: str | None = None,  # noqa: A002
        **_kw: Any,
    ) -> None:
        self.text = text
        self.id = id

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.text is not None:
            d["text"] = self.text
        if self.id is not None:
            d["id"] = self.id
        return d


class SIEClient:
    """HTTP-speaking SIEClient that honours provision_timeout_s as the socket timeout.

    Mirrors the constructor signature expected by dusk.trace.vector._sie_client:
        SIEClient(base_url, api_key=None, timeout_s=10.0)
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        timeout_s: float = 10.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout_s = timeout_s

    def _post(self, path: str, body: dict[str, Any], timeout_s: float | None) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        data = json.dumps(body).encode("utf-8")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        req = urllib.request.Request(
            url,
            data=data,
            headers=headers,
            method="POST",
        )
        effective_timeout = timeout_s if timeout_s is not None else self._timeout_s
        try:
            with urllib.request.urlopen(req, timeout=effective_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except TimeoutError as exc:
            raise TimeoutError(f"SIE request timed out after {effective_timeout} s") from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, ConnectionRefusedError):
                raise ConnectionRefusedError(str(reason)) from exc
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise TimeoutError(f"SIE request timed out after {effective_timeout} s") from exc
            raise

    def encode(
        self,
        model: str,
        item: Item,
        wait_for_capacity: bool = False,
        provision_timeout_s: float | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/encode",
            {"model": model, "item": item.to_dict(), "wait_for_capacity": wait_for_capacity},
            provision_timeout_s,
        )

    def score(
        self,
        model: str,
        query: Item,
        candidates: list[Item],
        wait_for_capacity: bool = False,
        provision_timeout_s: float | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/score",
            {
                "model": model,
                "query": query.to_dict(),
                "candidates": [c.to_dict() for c in candidates],
                "wait_for_capacity": wait_for_capacity,
            },
            provision_timeout_s,
        )

    def extract(
        self,
        model: str,
        item: Item,
        labels: list[str] | None = None,
        wait_for_capacity: bool = False,
        provision_timeout_s: float | None = None,
    ) -> dict[str, Any]:
        return self._post(
            "/extract",
            {
                "model": model,
                "item": item.to_dict(),
                "labels": labels or [],
                "wait_for_capacity": wait_for_capacity,
            },
            provision_timeout_s,
        )
