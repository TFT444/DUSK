# DUSK Production Agent Harness

Watching agent behaviour for what most tooling quietly misses, with
Superlinked surfacing the anomalies.

> This is a self-contained example from the
> [DUSK](https://github.com/ShieldTech-Ltd/DUSK) project. It has its own package,
> tests, sample data, and Docker Compose stack. See "What's in the box" for
> exactly what's bundled.

![architecture](docs/architecture.svg)

## What this shows

An AI agent proposes a control-plane action -- a firewall rule, a route
change, a role grant. DUSK's gate judges that **proposed action** itself,
not the prompt that led to it, against a per-agent behavioural baseline
built from the agent's own history. A hijacked agent still has valid
credentials, so anything that only checks "is this agent allowed to do
this" waves it through. Only *"does this agent normally do this"* catches
it -- and that's the question a credential check can't answer.

Two scenarios, both keyless by default:

- **Clean**: an agent proposes a routine action it makes every day. The
  gate allows it, and it reaches the downstream target.
- **Poisoned**: the agent's response is hijacked (a smuggled instruction in
  its context) into proposing an action well outside its own baseline --
  opening a firewall rule to `0.0.0.0/0` in a restricted segment. The gate
  flags it as anomalous immediately; in enforce mode it refuses the action
  before it ever reaches the downstream target (watch mode logs the same
  flag but lets it through -- see "What you'll see" below). The agent's
  credentials were real the whole time; only its behaviour gave the hijack
  away.

## Run it locally

> Security boundary: this Compose stack is a localhost-only demonstration. It
> intentionally uses keyless local services and must not be exposed to an
> untrusted network. Follow
> [production hardening](../docs/production-hardening.md) before using the
> gate on a real action path.

```bash
docker compose up
```

If either default localhost port is already in use, select unused host ports
without changing the container network:

```bash
DUSK_GATE_HOST_PORT=18000 MOCK_PROD_HOST_PORT=19000 docker compose up
```

Brings up the gate service (`dusk-gate`, the real `/v1/gate` HTTP endpoint), a
dummy downstream target and bounded webhook sink (`mock-prod`), and the agent
harness (`runtime`) on one internal network. The default stack uses the
deterministic gate, needs no API key, and makes no model request.

For local bearer authentication, set `DUSK_GATE_API_KEY` at runtime and send
`Authorization: Bearer <value>` to `/v1/gate`. CORS is disabled unless exact
trusted origins are supplied through `DUSK_CORS_ALLOWED_ORIGINS`. Never store a
real credential in `.env.example`, Compose, source control, or an image layer.

### Reproducible OWASP reviewer demo

Run both security modes through a cleanup-safe verifier:

```bash
./scripts/run_owasp_demo.sh watch
./scripts/run_owasp_demo.sh enforce
```

Each invocation builds the three project images, starts only the local gate and
mock target, runs both agent scenarios, verifies the exact verdict and applied
status, checks the downstream action count, then removes the local containers
and demo volume. The enforce override changes only `DUSK_ENFORCE`; all
localhost bindings and container restrictions remain inherited from
`compose.yml`.

To use SIE enrichment, install the `sie` extra and configure
`DUSK_SIE_ENDPOINT` for a separately maintained SIE deployment. Calls use short
timeouts and fall back to deterministic behavior when that endpoint is cold,
unavailable, or saturated.

Without Docker, run the pieces directly. The base install (`pip install -e .`)
works on Python 3.11+; the optional `sie` extra requires Python 3.12+ because
the SDK itself has that requirement:

```bash
# optional: start from the documented SIE settings
cp .env.example .env

# terminal 1: the gate
python -m dusk.api

# terminal 2: the dummy downstream target
python mock-prod/app.py

# terminal 3: the scenarios
python runtime/run_scenario.py
```

### What you'll see

By default the gate runs in **watch mode** (`DUSK_ENFORCE=false`), which is
observational: a poisoned action gets `WOULD-BLOCK` and the reason is
logged, but the action still proceeds -- an inline gate that wrongly blocks
a legitimate action can disrupt a network, so DUSK doesn't enforce until an
operator has built confidence in the baseline.

```
=== clean ===
verdict:  ALLOW
applied:  True
action:   { "agent_id": "netops-agent", "action_type": "route_change", "target": "rt-corp-prod", ... }

=== poisoned ===
verdict:  WOULD-BLOCK
applied:  True
reasons:  target introduces unseen terms ['restricted', 'segment'], change introduces unseen values ['0.0.0.0/0', 'allow'], newly introduces sensitive or privileged terms ['0.0.0.0/0', 'restricted']
action:   { "agent_id": "netops-agent", "action_type": "firewall_rule_change", "target": "fw-corp-restricted-segment", ... }
```

Check the downstream target's log directly (`curl http://localhost:9000/log`)
-- both actions are there in watch mode. The flagged reasons on the
poisoned one are the signal: an operator watching this log sees exactly
what an inline gate would have stopped, before ever trusting it to do so
automatically.

Set `DUSK_ENFORCE=true` on the `dusk-gate` service to switch to **enforce
mode**, where `BLOCK` actually stops the action before it reaches
`mock-prod`:

```
=== poisoned (enforce mode) ===
verdict:  BLOCK
applied:  False
reasons:  target introduces unseen terms ['restricted', 'segment'], change introduces unseen values ['0.0.0.0/0', 'allow'], newly introduces sensitive or privileged terms ['0.0.0.0/0', 'restricted']
```

Now `mock-prod`'s log shows only the clean action -- that absence is the
entire point of enforce mode, once watch mode has built enough confidence
to turn it on.

### Webhook integrations

Every verdict can fire `decision` and `report`; refused verdicts can also fire
`alert` through `src/dusk/trace/n8n_client.py`. The local Compose stack routes
these paths to the bounded metadata sink in `mock-prod`. Inspect received
events at `http://localhost:9000/webhook-log`.

The `n8n/dusk-webhooks.json` file can be imported into a separately maintained
n8n deployment. DUSK does not bundle an n8n runtime image because its large
third-party dependency tree must be patched and scanned on the operator's own
release cadence.

## Sample data

`sample-data/baseline.json` (15 known-good actions across three agents,
already mounted into `dusk-gate` at `DUSK_GATE_BASELINE_PATH`) and
`sample-data/check-mixed.json` (that same baseline plus 3 out-of-pattern
actions) let you exercise the gate directly with `docker compose up`
running, independent of the agent harness:

```bash
python -c "
import json, urllib.request
for action in json.load(open('sample-data/check-mixed.json')):
    req = urllib.request.Request(
        'http://localhost:8000/v1/gate',
        data=json.dumps(action).encode(),
        headers={'Content-Type': 'application/json'},
    )
    verdict = json.load(urllib.request.urlopen(req))
    print(action['target'], '->', verdict['verdict'])
"
```

This is the same fixture data used in DUSK's own test suite (a labelled
precision/recall benchmark asserts the gate catches every one of the 3
attacks with zero false alarms on the 15 routine actions).

## Model lineup

| Stage | Model | Size | Role |
|---|---|---|---|
| Encode | `BAAI/bge-m3` | ~568M params, MIT | Embeds each verdict once, when it's recorded, and embeds each new action once, when it's checked -- similarity between the two powers `similar_decision_ids`. |
| Score | `BAAI/bge-reranker-v2-m3` | ~568M params, Apache-2.0 | Reranks the encode-shortlisted history for `similar_decision_ids`, and separately reranks an agent's own baseline history to catch semantic novelty. |
| Extract | `urchade/gliner_multi-v2.1` | ~289M params, Apache-2.0 | Zero-shot NER for privileged terms (role, privilege, resource, segment, port), weighted by the model's own confidence rather than a flat yes/no. |

The optional client pins `sie-sdk==0.6.26`. DUSK does not bundle a server image;
operators select, patch, scan, and monitor the server appropriate to their
environment. Each model is a `Config` field and can be replaced through the
matching `DUSK_SIE_*_MODEL` environment variable when it exists in the target
SIE catalog.

## SIE features used

When an endpoint is configured, all three primitives run on the live
`/v1/gate` request path. Every signal is additive, so leaving SIE disabled does
not break gate decisions.

`/v1/gate`'s response carries the result directly: `similar_decision_ids`
is populated from a real per-agent decision history (embedded once at
record time, capped at 200 entries so lookup cost stays O(1) regardless of
how long the gate has been running -- see `src/dusk/api.py`), not
hardcoded. The optional live benchmark is skipped unless an endpoint and any
required credential are supplied at runtime. See `docs/sie-primitives.md` for
where each primitive is wired in.

## Why SIE specifically

One separately managed SIE cluster can provide encode, score, and extract
behind one client. Keeping it outside the default Compose stack lets operators
apply their own image policy and patch cadence without weakening the
deterministic local gate.

## Latency

The recorded full `agent-demo` -> gate -> `mock-prod` run used Superlinked's
hosted tester cluster, 20 requests per concurrency level, and a 20% poisoned /
80% clean mix:

| Concurrency | p50 | p95 | Errors |
|---|---|---|---|
| 1 | 294ms | 10008ms | 2/20 |
| 3 | 307ms | 474ms | 0/20 |
| 5 | 295ms | 317ms | 0/20 |

Every allowed action reached `mock-prod`, and every poisoned action was
flagged `WOULD-BLOCK`. See `docs/gate-latency-notes.md` for the methodology,
cold-start behavior, and limitations of this single small trial.

## Protected real-agent model validation

The dev qualification workflow runs one fixed Bedrock Mantle matrix through
the same successful Kimi path. It preserves the same token generator, OpenAI
compatible Mantle client, tool-call conversion, DUSK gate, Compose services,
prompts, and security assertions for these exact model IDs:

| Evidence slug | Model ID |
|---|---|
| `kimi-k2-5` | `moonshotai.kimi-k2.5` |
| `glm-5` | `zai.glm-5` |
| `qwen3-32b` | `qwen.qwen3-32b` |
| `gpt-oss-120b` | `openai.gpt-oss-120b` |

The workflow qualifies each exact ID through authenticated inference against the
London Mantle endpoint. It creates an isolated evidence directory and artifact
for each model. A valid manifest requires more than zero
tests, with zero failures, zero errors, and zero skips. The final matrix gate
fails unless every model job succeeds.

Each protected gate scenario exposes only its reviewed action schema and pins
the expected target. The real model generates the action arguments, then DUSK
must return the expected enforce-mode verdict. Missing calls, malformed actions,
incorrect targets, and incorrect verdicts fail the run.

The workflow selects the registered qualification job or full matrix. The
runtime registry in `models.registry.MODEL_PROFILES` enforces the supported
model IDs, and CI contract tests keep both workflow JSON branches synchronized
with that registry. The legacy `BEDROCK_MODEL_ID` value in the
`real-agent-dev` environment does not override or select a matrix entry. There
is no automatic fallback to Kimi or another model. Operators still approve the
protected `real-agent-dev` deployment, and the AWS OIDC role remains restricted
to that environment on `dev`.

## What's in the box

This example is self-contained and includes everything needed to run the
complete local flow:

- `Dockerfile`, `compose.yml` -- the deterministic gate service, mock-prod
  webhook sink, and runtime, wired on one internal network
- `contracts/gate.openapi.yaml` -- the frozen `/v1/gate` request/response
  contract
- `contracts/v1-gate-golden.json` -- deterministic response and side-effect
  snapshots protecting the frozen contract during refactoring; the documented
  normalization policy is in `docs/v1-gate-golden-contract.md`
- `src/dusk/` -- the gate itself: `actions/` (baseline, analyse, verdict),
  `trace/` (SIE client, n8n webhooks), `config.py`, and `api.py`. This example
  deliberately contains only the agent-action gate; network packet detection
  is outside its scope
- `runtime/` -- the Bedrock-or-mock agent harness, tool-call extraction,
  load driver
- `mock-prod/` -- the dummy downstream target
- `n8n/dusk-webhooks.json` -- an optional workflow asset for an external,
  separately patched n8n deployment
- `sample-data/` -- the baseline and mixed-check fixtures referenced above

## Extend it

- **Swap the baseline.** Point `DUSK_GATE_BASELINE_PATH` at your own
  known-good action history instead of `sample-data/baseline.json`, or
  select a different adapter (`azure`, `bedrock`, `generic`) with
  `DUSK_GATE_BASELINE_SOURCE`. `gate_block_threshold` will need
  re-tuning on your own labelled traffic, not just the synthetic
  fixture bundled here.
- **Try different models.** All three model IDs are `Config` fields,
  overridable via `DUSK_SIE_*_MODEL` env vars (see "Model lineup" above)
  -- no code change, provided the replacement is in your SIE catalog.
- **Add a fourth signal.** The deterministic score and every SIE signal
  compose additively in `analyse.py` -- a velocity check, a
  device-fingerprint rule, or another `extract` pass over a different
  field can be layered in the same way `_repeat_offense_signal` was.
- **Make `similar_decision_ids` durable across replicas.** The per-agent
  decision history in `api.py` is capped and in-process; swapping it for
  a shared store keeps it consistent when the gate runs as more than one
  instance.
- **Route verdicts elsewhere.** The three webhook destinations are plain HTTP
  POSTs. Point them at a reviewed SOAR, paging service, or SIEM endpoint.

## Known limits

- `/v1/gate` permits keyless local use when `DUSK_GATE_API_KEY` is unset.
  Compose binds it to localhost and CORS is disabled by default. A production
  deployment must configure authentication, TLS, rate limits, and network
  restrictions as described in `../docs/production-hardening.md`.
- If `DUSK_GATE_BASELINE_PATH` is set but the file fails to load, the gate
  still serves requests -- every agent just reads as unknown, which is a
  real degradation of what the gate actually catches, not just a startup
  error. `/health` reports `{"status": "degraded", "baseline_error": ...}`
  in this case; a real deployment should alert on that rather than only a
  log line.
- The baseline/attack fixtures are synthetic, not real production traffic.
- The deterministic feature checks in DUSK's gate do the primary anomaly
  scoring; SIE's three primitives are an enrichment layer on top of that,
  not a replacement for it -- the gate's core detection logic is not
  dependent on any AI model at runtime.
- SIE's rerank pass only reorders a small shortlist of candidates already
  retrieved by cosine similarity, not the full decision history.
- The extract model's privileged-term detection is zero-shot and has only
  been evaluated against the same synthetic fixtures used elsewhere, not an
  adversarial corpus designed to evade it specifically.
- Latency numbers are from a single 20-request-per-level trial against a
  shared tester cluster; enough to confirm the shape, not a high-confidence
  p95 at every level. See `docs/gate-latency-notes.md`.

## Built with

- [Superlinked SIE](https://github.com/superlinked/sie) (Apache-2.0): the
  inference engine hosting all three primitives
- [Flask](https://flask.palletsprojects.com/): the `/v1/gate` HTTP service and
  local bounded webhook sink
- [n8n](https://n8n.io/): optional external workflow automation using the
  provided import asset
- [BAAI/bge-m3](https://huggingface.co/BAAI/bge-m3) (MIT): encode
- [BAAI/bge-reranker-v2-m3](https://huggingface.co/BAAI/bge-reranker-v2-m3)
  (Apache-2.0): score
- [urchade/gliner_multi-v2.1](https://huggingface.co/urchade/gliner_multi-v2.1)
  (Apache-2.0): extract

## Credits

Built by Ritik Sah and Tanvir Farhad.
