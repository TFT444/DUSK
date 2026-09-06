"""HTTP-level tests for the demo policy service.

Spins up DemoServer in a background thread; tests hit real TCP sockets.
Covers routing, authentication, and body-level validation at the HTTP layer.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Generator

import pytest

from dusk.demo_cloudflare import DemoServer

_SECRET = b"http-test-secret-32bytes-padding!"
_PORT = 18787  # distinct from default 8787 to avoid collisions


def _hmac_sig(method: str, path: str, timestamp: str, nonce: str, body: bytes) -> str:
    msg = f"{method}\n{path}\n{timestamp}\n{nonce}\n".encode() + body
    return _hmac.new(_SECRET, msg, hashlib.sha256).hexdigest()


def _post(
    path: str,
    body: bytes,
    *,
    sign: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    ts = str(int(time.time()))
    nonce = str(time.time_ns())
    sig = _hmac_sig("POST", path, ts, nonce, body) if sign else "bad"

    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Hmac-Signature": sig,
    }
    if extra_headers:
        headers.update(extra_headers)

    req = urllib.request.Request(
        f"http://127.0.0.1:{_PORT}{path}",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def _get(path: str) -> tuple[int, dict[str, object]]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{_PORT}{path}",
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@pytest.fixture(scope="module")
def server() -> Generator[DemoServer, None, None]:
    srv = DemoServer(port=_PORT, hmac_secret=_SECRET)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)  # allow bind to complete
    yield srv
    srv.shutdown()


# ---------------------------------------------------------------------------
# GET /healthz
# ---------------------------------------------------------------------------


def test_healthz_returns_ok(server: DemoServer) -> None:
    status, body = _get("/healthz")
    assert status == 200
    assert body["status"] == "ok"


def test_healthz_wrong_path_returns_404(server: DemoServer) -> None:
    status, body = _get("/unknown-path")
    assert status == 404


# ---------------------------------------------------------------------------
# Routing and method guards
# ---------------------------------------------------------------------------


def test_unknown_post_path_returns_404(server: DemoServer) -> None:
    body = json.dumps({"action": "demo.read_status"}).encode()
    status, _ = _post("/v1/demo/evaluate", body)  # old path, must not exist
    assert status == 404


def test_missing_hmac_headers_returns_401(server: DemoServer) -> None:
    body = json.dumps({"action": "demo.read_status", "risk_signal": "normal"}).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{_PORT}/v1/demo/authorize-and-execute",
        data=body,
        headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            status, resp = r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        status, resp = exc.code, json.loads(exc.read())
    assert status == 401
    assert "unauthorized" in resp.get("error", "")


def test_bad_hmac_signature_returns_401(server: DemoServer) -> None:
    body = json.dumps({"action": "demo.read_status"}).encode()
    status, resp = _post("/v1/demo/authorize-and-execute", body, sign=False)
    assert status == 401
    assert "unauthorized" in resp.get("error", "")


# ---------------------------------------------------------------------------
# Body validation
# ---------------------------------------------------------------------------


def test_malformed_json_returns_400(server: DemoServer) -> None:
    body = b"not-json{{{"
    status, resp = _post("/v1/demo/authorize-and-execute", body)
    assert status == 400
    assert "invalid json" in resp.get("error", "")


def test_oversized_body_returns_413(server: DemoServer) -> None:
    body = b"x" * 5000
    # The server sends 413 then closes the connection before reading the full body,
    # so the client may see either an HTTPError(413) or a ConnectionError.
    try:
        status, resp = _post("/v1/demo/authorize-and-execute", body)
        assert status == 413
        assert "body too large" in resp.get("error", "")
    except (ConnectionError, OSError):
        pass  # server closed early -- 413 was the intended response


# ---------------------------------------------------------------------------
# Full allow and block paths over HTTP
# ---------------------------------------------------------------------------


def test_allow_path_returns_executed_true(server: DemoServer) -> None:
    body = json.dumps(
        {
            "action": "demo.read_status",
            "risk_signal": "normal",
            "tenant_id": "demo-tenant",
            "agent_id": "demo-agent",
        }
    ).encode()
    status, resp = _post("/v1/demo/authorize-and-execute", body)
    assert status == 200
    assert resp["decision"] == "ALLOWED"
    assert resp["executed"] is True
    assert resp["permit_id"] is not None


def test_block_path_returns_executed_false(server: DemoServer) -> None:
    body = json.dumps(
        {
            "action": "demo.rotate_demo_key",
            "risk_signal": "prompt_injection",
            "tenant_id": "demo-tenant",
            "agent_id": "demo-agent",
        }
    ).encode()
    status, resp = _post("/v1/demo/authorize-and-execute", body)
    assert status == 200
    assert resp["decision"] == "BLOCKED"
    assert resp["executed"] is False
    assert resp["reason_code"] == "PROMPT_INJECTION_DETECTED"
    assert resp["permit_id"] is None
