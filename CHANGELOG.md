# Changelog

All notable changes to DUSK are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security

- Replaced long-lived AWS access-key secrets in the protected real-agent
  workflow with job-scoped GitHub OIDC role assumption. Bedrock validation now
  requires an approved environment, explicit role, region and model variables,
  and the DUSK gate secret.

### Added
- Cloud-neutral control-plane delivery assets: a locked multi-stage OCI build,
  keyless signing with SBOM and provenance, fail-closed image admission, a
  hardened Helm chart, external secret references, restricted networking,
  autoscaling, serialized bounded migrations, same-digest promotion evidence,
  and backward-compatible rollback guidance. Live cloud accounts remain
  deferred to #251 until backend/frontend localhost validation is complete.
- Production resilience qualification for the control plane, including
  concurrent idempotent evaluation serialization, real PostgreSQL connection-loss
  recovery, mixed-version migration rollback and retry, database-trusted broker
  acknowledgement time, and documented RTO/RPO recovery procedures.
- Production-ready AWS, Azure, and Kubernetes policy-evidence boundaries:
  `DUSK-CLOUD-001` through `DUSK-CLOUD-010`, strict native event
  normalization, tenant-bound Ed25519 evidence, durable PostgreSQL replay
  claims, allow-only enforcement-broker routing, and fail-closed release
  certification. Live provider qualification is deliberately deferred to
  issue #251 after backend/frontend localhost validation.
- Bounded, dry-run-first tenant retention enforcement with legal-hold locking,
  signed deletion evidence, preserved audit continuity, controlled compliance
  export, and defence-in-depth secret-value redaction.
- Default-off OpenTelemetry tracing and RED metrics with bounded OTLP export,
  allow-listed structured JSON logs, request/decision/audit/outbox correlation,
  and measured normalization, behavioral, policy, persistence, audit, response,
  delivery, and broker-acknowledgement stages.
- Tenant-scoped dashboard summary, decision-volume, action-breakdown, and
  agent-risk investigation APIs backed only by persisted PostgreSQL decisions,
  with UTC comparison windows, measured p95 latency, explicit freshness and
  empty states, signed stable-ranking cursors, and default-disabled activation.
- Tenant-scoped decision list and investigation endpoints with signed keyset
  cursors, PostgreSQL full-text search, redacted projections, policy and audit
  continuity, and default-disabled activation.
- Bounded transactional-outbox workers with leased PostgreSQL claims,
  at-least-once delivery IDs, exponential backoff with jitter, dead letters,
  DNS-rebinding-resistant pinned HTTPS delivery, safe diagnostics, and
  cryptographically bound enforcement acknowledgements. Only a verified broker
  outcome can establish `EXECUTED`; webhook delivery and Gate `ALLOW` cannot.
- Atomic v2 decision evidence persistence: redacted canonical action, decision,
  safe policy matches, tenant-scoped signed digest-chain event, and outbox intent
  now commit in one PostgreSQL transaction. Managed signer or database failure
  fails closed; trusted checkpoints detect mutation, deletion, reordering, and
  cross-tenant splicing. Additive migration and real PostgreSQL tests cover
  rollback, idempotent replay, concurrency, restart recovery, and redaction.
- Trusted policy integration for v2 evaluations, including verifier-confirmed
  provenance, freshness and digest checks, live-evidence activation guards,
  deterministic policy/behavioral precedence, safe matched-rule metadata, and
  measured pipeline timings. The authenticated route fails closed until a
  complete evaluation service is activated.
- Framework-neutral canonical evaluation orchestration with explicit identity,
  clock, trace, semantic-enrichment, behavioral-analysis, policy, offense-memory,
  persistence, and delivery ports. The frozen `/v1/gate` now uses legacy
  adapters, while isolated shadow evaluation performs no stateful or external
  effects.
- PostgreSQL persistence boundary for the production control plane, including
  tenant-qualified SQLAlchemy models and repositories, an Alembic baseline,
  bounded async connection management, critical readiness probing, a
  digest-pinned local database profile, and real PostgreSQL migration,
  isolation, idempotency, retention, and rollback tests.
- CloudFormation template for GitHub OIDC provider and least-privilege IAM role
  restricted to the `real-agent` environment, with only the model metadata and
  invocation permissions used by the workflow (`infra/aws/bedrock-real-agent/template.yaml`).
- PowerShell setup script (`scripts/setup-bedrock-oidc.ps1`) with read-only
  validation and deployment modes.
- Read-only validation wrapper (`scripts/test-bedrock-oidc-config.ps1`).
- Infrastructure and workflow tests (`tests/ci/test_real_agent_infra.py`).
- Operator documentation for Bedrock OIDC setup (`docs/bedrock-oidc-setup.md`).

- GPT OSS 120B (`openai.gpt-oss-120b`) support for the Bedrock Mantle agent
  harness, including a model-specific action-serialization contract, bounded
  corrective retry, and a fixed protected qualification workflow. The model
  remains outside the required dev matrix until two protected runs pass.
- Qwen3 32B (`qwen.qwen3-32b`) added to the required Bedrock Mantle dev
  validation matrix after two credentialed runs reported 26 passed, 0 failed,
  0 errors, and 0 skipped. A later protected matrix run exposed unrelated
  tool-routing variance, which is addressed by the scenario isolation below.
- Explicit model allowlist (`_MANTLE_V1_MODEL_IDS`) in `bedrock_client.py`
  prevents untrusted model IDs from routing silently to an unintended endpoint.
  `build_mantle_client` raises `ValueError` for any ID not in the allowlist.
- Bounded Mantle client configuration: `timeout=120` prevents unbounded
  inference hangs; `max_retries=0` prevents hidden SDK retry amplification;
  `max_completion_tokens=4096` prevents unbounded chain-of-thought output.
- Length-truncation retry in `MantleClient.chat_completions_create`: one
  additional call when `finish_reason='length'` with no tool call produced.
  Does not retry wrong-tool calls; an unexpected tool still fails the scenario.

### Removed
- NVIDIA Nemotron Super 3 120B (`nvidia.nemotron-super-3-120b`) removed from
  the required dev matrix. The model did not satisfy the deterministic tool-call
  contract: approximately 20 percent of calls produced wrong-tool reasoning on
  injection scenarios. The failure was not truncation and could not be resolved
  by retry logic. A model at that failure rate provides noise rather than
  security evidence.

### Changed
- Promoted the real-agent sandbox from the example tree to the production
  `dusk-agent-harness` root. Runtime, Docker, protected Bedrock workflows,
  evidence paths, model profiles, documentation, and repository policy now use
  the production path, with unknown model IDs failing closed.
- `real-agent-sandbox.yml`: added concurrency group, AWS caller identity
  verification step, and Bedrock model availability pre-check.
- `real-agent-sandbox-dev.yml`: required matrix updated to Kimi K2.5, GLM-5,
  and Qwen3 32B. Model qualification uses authenticated inference rather than
  the broader Mantle model-list permission. Each model produces separate JUnit
  evidence. The aggregate gate fails if any model job fails.
- Protected gate scenarios now expose only the action under test and constrain
  its target. This prevents unrelated model tool routing from obscuring whether
  DUSK enforced the required action while preserving real model inference.

## [0.2.0], 2026-08-05

### Added
- OWASP Incubator proposal, official ASI01 through ASI10 control mapping,
  governance, Code of Conduct, DCO validation, and separate CC BY-SA 4.0
  documentation licensing.
- Production-hardening guidance and optional constant-time bearer
  authentication for the example gate. Demo ports now bind to localhost and
  browser CORS is disabled unless exact origins are configured.
- Dependabot configuration, immutable GitHub Action pins, release SBOM,
  artifact checksums, and build provenance.
- Self-contained Superlinked submission packaging for `agent-action-monitor`,
  including an implementation-accurate architecture diagram, local environment
  template, and example-scoped ignore rules.
- Reproducible OWASP reviewer demo for watch and enforce modes, with exact
  verdict, forwarding, and downstream action-count verification.
- Agent action gate (v1.2 to v1.4): per-agent behavioural baseline
  (src/dusk/actions/baseline.py), an analyser that scores an action against the
  baseline into an anomaly score with reasons, MITRE ATT&CK + ATLAS mapping,
  blast radius, and predicted next stage (analyse.py), and a verdict layer that
  renders ALLOW / WOULD-BLOCK / BLOCK in watch or enforce mode (verdict.py). New
  `dusk gate --baseline --check [--enforce] [--json]` CLI command. Deterministic
  and dependency-free so a live demo is stable. A labelled benchmark in the test
  suite reports precision, recall, and false-positive rate (1.0 / 1.0 / 0.0 on
  the bundled fixtures).
- v1.1 agent action ingest layer: the controller-agnostic AgentAction event
  (timezone-aware timestamp, normalised action_type, target, before/after
  change, source, raw_ref) with strict validation and to_dict/from_dict
  round-tripping; a SourceAdapter base with AdapterError; Azure activity-log
  and generic adapters; a normaliser registry keyed by source name;
  ingest_file(path, source) reading a JSON list of records and skipping
  malformed ones; the `dusk actions --file --source [--json]` CLI command; a
  lab generator for the action fixtures; and docs/action-schema.md.
- Professional README with status badges, a CLI demo, a mermaid architecture
  diagram, a configuration reference, and a roadmap.
- README reference sections: table of contents, how it works, usage, JSON output,
  exit codes, use in CI, alerts, install from source, project layout, and
  references.
- Full threat model in docs/threat-model.md with MITRE ATT&CK, MITRE ATLAS, and
  OWASP Top 10 for Agentic Applications mappings.
- CONTRIBUTING.md documenting the branch model, issue-first rule, local checks,
  and how to add a detection.

### Security

- Rebased the gate, agent demo, and mock downstream containers on current
  digest-pinned Python Bookworm images after CI identified fixable
  HIGH-severity util-linux vulnerabilities in the previous Debian 13 images.

### Changed
- Reduced the default example to project-built, scanned services. SIE and n8n
  remain optional external integrations, and the deterministic gate plus
  bounded local webhook sink preserve the keyless demonstration path.
- Updated the optional SIE client to 0.6.26 and disabled it unless an endpoint
  is explicitly configured.
- Polished the `agent-action-monitor` README and SIE validation notes for
  upstream submission, correcting environment variables, fixture paths, and
  tested server/SDK compatibility guidance.
- Reconciled the root architecture and SIE documentation with the implemented
  gate boundary, removed broken document links, and corrected animated SVG
  timing and text layout.
- Replaced the legacy terminal-style demos with a unified branded visual system:
  a three-stage action journey, a decision-evidence comparison, and a responsive
  architecture walkthrough.
- Added a branded README hero and compact five-step workflow strip so new
  visitors can understand DUSK before reading the detailed documentation.
- Plain-text style across all docs, issue templates, alert panel, and code
  docstrings. Em dashes, en dashes, navigation arrows, and decorative emojis
  removed. No functional changes.
- Test runs force PYTHONIOENCODING=utf-8 (via pytest-env) so console capture
  cannot fall back to a platform default such as Windows cp1252.

## [0.1.0], 2026-06-05

### Added
- Sweep detection: machine-paced network scan identification (T1046)
- Boundary detection: port scan identification (T1590)
- pcap sensor via Scapy
- CLI: dusk scan --file [--json] [--verbose]
- Configuration system: dusk.yaml + DUSK_* environment variables
- Structured logging throughout
- Kill chain stage prediction
- Alert output: Rich terminal panel + dusk-alerts.json
- CI: lint, typecheck, security scan, test with coverage gate
- OWASP-oriented threat model in docs/threat-model.md
