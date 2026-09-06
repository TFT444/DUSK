"""Known-legitimate "unused" code, per vulture's whitelist convention.

Referenced by name only, never imported or executed: this file exists to be
scanned by vulture (`vulture src/ tests/ runtime/ mock-prod/
scripts/vulture_whitelist.py`), not to run. Every entry here was checked
against a real cross-reference search before being added.

- ActionGate.evaluate_all(): batch evaluation, used by the root repo's
  offline `dusk gate` CLI (a separate package -- this example's live
  /v1/gate handler processes one action per request via .evaluate(), so it
  never needs the batch method). Kept for parity with the root copy's
  public API, not dead code that was meant to be removed.
- config.py's set_config(): a real public setter with no caller in this
  package yet (tests use monkeypatch/env vars instead), kept for parity
  with get_config()/reset_config() as the documented override path.
- vector.py's SimilarDecision.similarity: set at construction (the
  cosine/rerank score each match was found at) but never read back by
  api.py, which only forwards each match's .id in similar_decision_ids.
  Kept on the dataclass as diagnostic data for a caller that wants the
  actual similarity score, not just which decisions matched.
- tests/real_llm/test_real_llm_gate.py: pytestmark is a pytest-recognised
  module-level variable that applies skip conditions to every test in the
  module; it is never explicitly called, so vulture flags it as unused.
- tests/test_sie_http_fallback.py: do_POST and log_message are
  BaseHTTPRequestHandler protocol methods invoked by http.server when an
  HTTP request arrives. The framework dispatches them by name; they are
  never called directly by test code, so vulture cannot see them as used.
"""

from dusk.actions.verdict import ActionGate
from dusk.application.evaluator import EvaluationOutput, EvaluationPrincipal
from dusk.config import set_config
from dusk.trace.vector import SimilarDecision

ActionGate.evaluate_all
set_config
SimilarDecision.similarity

# Canonical boundary values are accessed through Protocol-driven adapters or
# returned to production callers, which vulture cannot resolve statically.
EvaluationPrincipal.tenant_id
EvaluationPrincipal.principal_id
EvaluationOutput.delivery_intents

# pytest discovers this variable by name; it is not dead code.
pytestmark

# http.server dispatches these by name when an HTTP request arrives.
do_POST
log_message
