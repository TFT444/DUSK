"""Known-legitimate "unused" code, per vulture's whitelist convention.

Referenced by name only, never imported or executed: this file exists to be
scanned by vulture (`vulture src/ tests/ scripts/vulture_whitelist.py`), not
to run. Every entry here was checked against a real cross-reference search
before being added -- this is not a blanket suppression file. Anything found
genuinely dead during that check got filed as its own issue instead of
whitelisted (see #76).

Categories:
- Public API consumed by dusk-agent-harness/ (a separate package
  vulture can't see when scoped to this repo's own src/), not by anything in
  this repo's own src/ or tests/.
- v0.2 stub classes (sensor/, detections/, respond/) that are deliberately
  registered but not yet wired into the live engine -- see tests/test_stubs.py.
- config.py's set_config(): a real public setter with no caller in this
  repo yet (tests use monkeypatch/env vars instead), kept for parity with
  get_config()/reset_config() as the documented override path.
- AgentHealer (heal.py): wired into `dusk gate --heal` in #65, open at the
  time this file was written. Remove this entry once #65 merges -- vulture
  will then see the real caller in cli.py and stop flagging it itself.
"""

from dusk.actions.heal import AgentHealer
from dusk.application.evaluator import DecisionWrite, EvaluationPrincipal, OffenseWrite
from dusk.config import set_config
from dusk.detections.lateral import LateralDetection
from dusk.detections.telemetry import TelemetryDetection
from dusk.respond.isolate import IsolateResponder
from dusk.sensor.base import PACKET_KEYS
from dusk.sensor.live import LiveSensor
from dusk.sensor.zeek import ZeekSensor
from dusk.trace.models import TraceDecision
from dusk.trace.vector import SimilarDecision, find_similar, find_similar_cached

# Public API only reached from dusk-agent-harness/'s api.py, not
# from anything in this repo's own src/ or tests/. TraceDecision's own dead
# fields (raw_prompt_snippet, tavily_enrichment, replay_count) were removed
# entirely rather than whitelisted -- see #76.
find_similar
find_similar_cached
SimilarDecision.similarity

# Canonical application-boundary data consumed structurally by persistence,
# identity, and legacy adapters. Vulture cannot follow Protocol-driven access.
EvaluationPrincipal.tenant_id
EvaluationPrincipal.principal_id
EvaluationPrincipal.identity_kind
OffenseWrite.occurred_at
DecisionWrite.occurred_at

set_config

# Wired into cli.py's `gate --heal` in #65 (open, not yet merged as of this
# writing) -- remove once #65 lands on dev.
AgentHealer
AgentHealer.is_quarantined
AgentHealer.heal

# v0.2 stub classes -- registered but not yet wired into the live engine.
LateralDetection
TelemetryDetection
IsolateResponder
LiveSensor
ZeekSensor
PACKET_KEYS
