# Security Self-Assessment

## Project purpose

DUSK evaluates AI agent actions and packet-derived events for behavioral
deviation. The root package is an offline CLI. The self-contained example adds
an HTTP gate and optional inference and workflow integrations.

## Assets

- trusted per-agent baseline data
- proposed agent actions and their identifiers
- gate verdicts, reasons, and trace identifiers
- optional offense memory and alert records
- deployment credentials supplied at runtime

## Trust boundaries

- input files and packet captures are untrusted
- HTTP gate requests are untrusted until authenticated by the deployment
- baseline files are trusted administrative input and remain read-only at runtime
- optional SIE and webhook endpoints are external dependencies
- downstream action targets must independently enforce identity and authorization

## Primary threats and controls

| Threat | Control |
|---|---|
| Malformed or oversized input | Schema validation, bounded recursion, request size cap, and explicit errors |
| Baseline poisoning | Live requests never update the trusted baseline |
| Unauthorized gate use | Optional constant-time bearer check plus required production ingress controls |
| Credential disclosure | Environment-based injection, private reporting, secret scanning, and log discipline |
| Dependency compromise | Dependency audit, Dependabot, immutable CI action pins, SBOM, and provenance |
| Unsafe default exposure | Localhost-only published demo ports, disabled default CORS, and production-hardening guidance |
| Silent degraded state | Health status reports baseline and persistence failures |
| Gate false positive | Watch mode by default, deterministic reasons, explicit enforcement opt-in |
| Gate false negative | Layered deterministic signals, optional enrichment, tests, and documented scope limits |

## Security-sensitive code

- `src/dusk/actions/` and the example copy implement baseline and verdict logic
- `src/dusk/sensor/pcap.py` parses untrusted packet captures
- `dusk-agent-harness/src/dusk/api.py` defines the HTTP boundary
- `dusk-agent-harness/src/dusk/trace/` handles optional outbound calls
- `.github/workflows/` defines build and release trust

## Known limitations

DUSK does not authenticate agent identities, secure inter-agent protocols,
sandbox generated code, or provide full ASI01 through ASI10 coverage. In-memory
decision history is not shared across replicas. The example bearer token is a
deployment aid, not a replacement for workload identity in a high-assurance
environment.

## Review cadence

Review this assessment for each security-sensitive release and whenever an
input, identity, storage, network, or release trust boundary changes.
