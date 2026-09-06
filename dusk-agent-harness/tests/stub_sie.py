"""Configurable stub SIEClient for SIE failure-mode tests.

Injects into dusk.trace.vector._sie_client via monkeypatch.  Each instance
can be configured to simulate a distinct failure mode without spinning up an
HTTP server.
"""

from __future__ import annotations

from typing import Any, Literal

Mode = Literal["ok", "timeout", "malformed_dense", "connection_refused", "high_score"]


class StubSIEClient:
    """Drop-in stand-in that reproduces specific SIE failure modes.

    Attributes:
        mode: Controls which failure the client injects.  ``"ok"`` behaves as
            a healthy client returning minimal well-formed responses.
            ``"high_score"`` returns perfect similarity scores to exercise the
            property that high SIE scores must not lower a deterministic
            WOULD-BLOCK verdict.
        call_count: Counts invocations per method name; used by tests to prove
            the SIE path was actually exercised (not just the n-gram fallback).
    """

    def __init__(self, mode: Mode = "ok") -> None:
        self.mode = mode
        self.call_count: dict[str, int] = {"encode": 0, "score": 0, "extract": 0}

    def encode(self, _model: str, _item: Any, **_kwargs: Any) -> dict[str, Any]:
        self.call_count["encode"] += 1
        if self.mode == "timeout":
            raise TimeoutError("SIE encode: request timed out after 1.5 s")
        if self.mode == "connection_refused":
            raise ConnectionRefusedError("SIE encode: [Errno 111] Connection refused")
        if self.mode == "malformed_dense":
            return {"dense": None}
        if self.mode == "high_score":
            return {"dense": [1.0, 1.0, 1.0]}
        return {"dense": [1.0, 0.0, 0.0]}

    def score(self, _model: str, _query: Any, candidates: Any, **_kwargs: Any) -> dict[str, Any]:
        self.call_count["score"] += 1
        if self.mode == "timeout":
            raise TimeoutError("SIE score: request timed out after 1.5 s")
        if self.mode == "connection_refused":
            raise ConnectionRefusedError("SIE score: [Errno 111] Connection refused")
        score_val = 1.0 if self.mode == "high_score" else 0.5
        return {"scores": [{"item_id": str(i), "score": score_val} for i in range(len(candidates))]}

    def extract(self, _model: str, _item: Any, **_kwargs: Any) -> dict[str, Any]:
        self.call_count["extract"] += 1
        if self.mode == "timeout":
            raise TimeoutError("SIE extract: request timed out after 1.5 s")
        if self.mode == "connection_refused":
            raise ConnectionRefusedError("SIE extract: [Errno 111] Connection refused")
        return {"entities": [{"text": "owner", "label": "role", "score": 0.9}]}
