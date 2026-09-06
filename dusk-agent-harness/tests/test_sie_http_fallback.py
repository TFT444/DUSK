"""SIE transport-level fallback tests using a real HTTP stub server.

Unlike test_sie_fallback.py (which injects exceptions directly into the
call stack via monkeypatch), these tests inject a minimal HTTP-speaking
fake SIE SDK (fake_sie_sdk.py) into sys.modules and point it at a
thread-based HTTP stub server.  Every SIE call goes through an actual
TCP connection, so the tests exercise:

  - Real socket-level timeout via provision_timeout_s (SIH-01)
  - Malformed HTTP 200 response missing all expected fields (SIH-02)
  - Connection refused at the OS level (SIH-03)
  - High SIE similarity score that must NOT lower a WOULD-BLOCK verdict (SIH-04)

No Docker, no external services.  The stub server is started on an
ephemeral port via http.server.HTTPServer(("127.0.0.1", 0), ...) and
served from a daemon thread that is shut down after each test.
"""

from __future__ import annotations

import http.server
import json
import socket
import sys
import threading
import time
import types
from pathlib import Path

import fake_sie_sdk
import pytest

from dusk import api
from dusk.config import reset_config
from dusk.trace import vector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _inject_fake_sdk(monkeypatch: pytest.MonkeyPatch, base_url: str) -> None:
    """Point vector._sie_client at fake_sie_sdk and set DUSK_SIE_ENDPOINT."""
    fake_mod = types.ModuleType("sie_sdk")
    fake_mod.SIEClient = fake_sie_sdk.SIEClient  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sie_sdk", fake_mod)

    fake_types = types.ModuleType("sie_sdk.types")
    fake_types.Item = fake_sie_sdk.Item  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "sie_sdk.types", fake_types)

    monkeypatch.setenv("DUSK_SIE_ENDPOINT", base_url)


def _make_handler(mode: str) -> type[http.server.BaseHTTPRequestHandler]:
    """Return a handler class configured for the given mode."""

    class _Handler(http.server.BaseHTTPRequestHandler):
        _mode = mode

        def log_message(self, _fmt: str, *_args: object) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            if self._mode == "timeout":
                # Sleep longer than _PROVISION_TIMEOUT_S (1.5 s) so the client
                # times out before receiving a response.
                time.sleep(3.0)
                self._send_json({"dense": []})

            elif self._mode == "malformed":
                # Well-formed HTTP 200 but none of the fields the SDK expects.
                self._send_json({"status": "ok", "model_warming_up": True})

            elif self._mode == "high_score":
                if self.path == "/encode":
                    self._send_json({"dense": [1.0, 1.0, 1.0, 1.0]})
                elif self.path == "/score":
                    try:
                        parsed = json.loads(body or b"{}")
                        n = max(len(parsed.get("candidates", [])), 1)
                    except Exception:  # noqa: BLE001
                        n = 1
                    scores = [{"item_id": str(i), "score": 10.0} for i in range(n)]
                    self._send_json({"scores": scores})
                else:
                    self._send_json(
                        {"entities": [{"text": "owner", "label": "role", "score": 0.99}]}
                    )

            else:
                self._send_json({"dense": [1.0, 0.0, 0.0]})

        def _send_json(self, payload: dict) -> None:
            data = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return _Handler


def _start_server(mode: str) -> tuple[http.server.HTTPServer, str]:
    """Start an HTTP stub server on an ephemeral port; return (server, base_url)."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _make_handler(mode))
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


def _refused_url() -> str:
    """Return a URL on a port with nothing listening (connection actively refused)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # Socket closed; no listener on this port.
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# SIH-01: timeout
# ---------------------------------------------------------------------------


def test_encode_returns_none_when_http_server_delays_beyond_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIH-01: server accepts connection but sleeps past provision_timeout_s (1.5 s).

    sie_encode must return None (n-gram fallback) and must complete within
    twice the provision timeout, not hang indefinitely.
    """
    server, base_url = _start_server("timeout")
    try:
        _inject_fake_sdk(monkeypatch, base_url)
        reset_config()

        t0 = time.monotonic()
        result = vector.sie_encode("firewall_rule_change fw-corp-https")
        elapsed = time.monotonic() - t0

        assert result is None, "HTTP timeout must cause sie_encode to return None (n-gram fallback)"
        # provision_timeout_s=1.5; allow 2× headroom for slow CI environments.
        assert elapsed < 4.0, f"Timeout must complete within 4 s; took {elapsed:.2f} s"
    finally:
        server.shutdown()
        reset_config()


# ---------------------------------------------------------------------------
# SIH-02: malformed
# ---------------------------------------------------------------------------


def test_encode_returns_none_when_http_response_lacks_dense_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SIH-02: HTTP 200 response missing all expected SIE fields must fall back to None.

    This models a model-warming or schema-mismatch response where the HTTP
    layer is healthy but the payload is unusable.
    """
    server, base_url = _start_server("malformed")
    try:
        _inject_fake_sdk(monkeypatch, base_url)
        reset_config()

        result = vector.sie_encode("firewall_rule_change fw-corp-https")

        assert result is None, (
            "Malformed HTTP response (missing 'dense') must cause sie_encode to return None"
        )
    finally:
        server.shutdown()
        reset_config()


# ---------------------------------------------------------------------------
# SIH-03: connection refused
# ---------------------------------------------------------------------------


def test_gate_returns_valid_verdict_when_sie_server_is_not_reachable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SIH-03: gate returns a valid verdict even when the SIE TCP connection is refused.

    This is the end-to-end transport test: the full request path
    (gate → analyse → embed_text → sie_encode → n-gram fallback) must not
    surface a ConnectionRefusedError as an HTTP 500.
    """
    refused = _refused_url()
    _inject_fake_sdk(monkeypatch, refused)

    fixtures = Path(__file__).resolve().parent / "fixtures"
    monkeypatch.setenv("DUSK_GATE_BASELINE_PATH", str(fixtures / "actions_normal.json"))
    monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
    monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offenses.json"))
    monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()

    api.app.config["TESTING"] = True
    with api.app.test_client() as client:
        r = client.post(
            "/v1/gate",
            json={
                "agent_id": "ghost-agent",
                "timestamp": "2023-11-14T22:20:00+00:00",
                "action_type": "firewall_rule_change",
                "target": "fw-restricted",
                "change": {"before": None, "after": {"port": 22}},
                "source": "generic",
                "raw_ref": "evt-sie-http-refused",
            },
        )

    assert r.status_code == 200, "Connection-refused SIE must not produce HTTP 500"
    data = r.get_json()
    assert data["verdict"] in {"ALLOW", "WOULD-BLOCK", "BLOCK"}
    assert isinstance(data["score"], float)

    reset_config()
    api.reset_gate_engine()
    api.reset_decision_history()


# ---------------------------------------------------------------------------
# SIH-04: high score does not lower WOULD-BLOCK
# ---------------------------------------------------------------------------


def test_high_score_from_stub_server_does_not_lower_would_block(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """SIH-04: perfect SIE similarity scores from the HTTP stub must not lower WOULD-BLOCK.

    When the stub returns score=10.0 (post-sigmoid ≈ 1.0) for every candidate,
    the gate's deterministic threshold still applies.  An unknown agent performing
    a sensitive role_assignment (owner, score 0.85) must remain WOULD-BLOCK or
    BLOCK regardless of what SIE reports.
    """
    server, base_url = _start_server("high_score")
    try:
        _inject_fake_sdk(monkeypatch, base_url)
        monkeypatch.setenv("DUSK_GATE_ALLOW_ANONYMOUS", "true")
        monkeypatch.setenv("DUSK_OFFENSE_MEMORY_PATH", str(tmp_path / "offenses.json"))
        monkeypatch.delenv("DUSK_GATE_API_KEY", raising=False)
        monkeypatch.delenv("DUSK_GATE_BASELINE_PATH", raising=False)
        reset_config()
        api.reset_gate_engine()
        api.reset_decision_history()

        api.app.config["TESTING"] = True
        with api.app.test_client() as client:
            r = client.post(
                "/v1/gate",
                json={
                    "agent_id": "sie-http-unknown-agent",
                    "timestamp": "2024-01-10T10:00:00+00:00",
                    "action_type": "role_assignment",
                    "target": "ra-owner-prod",
                    "change": {"before": {"role": "viewer"}, "after": {"role": "owner"}},
                    "source": "generic",
                    "raw_ref": "evt-sie-http-high-score",
                },
            )

        data = r.get_json()
        assert r.status_code == 200
        assert data["verdict"] in {"WOULD-BLOCK", "BLOCK"}, (
            "SIE high score from HTTP stub must not lower deterministic WOULD-BLOCK: "
            f"score={data['score']}, verdict={data['verdict']}"
        )
    finally:
        server.shutdown()
        reset_config()
        api.reset_gate_engine()
        api.reset_decision_history()
