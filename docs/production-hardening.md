# Production Hardening

The DUSK Production Agent Harness is a runnable local validation stack, not a
production deployment template. Use the controls below before placing a DUSK
gate on a real action path.

## Required controls

1. Put the gate behind a production ingress or API gateway.
2. Terminate TLS with a trusted certificate and reject cleartext traffic.
3. Set a high-entropy `DUSK_GATE_API_KEY` through a secret manager.
4. Apply per-client rate and concurrency limits at the ingress.
5. Allow only known agent runners and orchestration services at the network
   boundary.
6. Leave browser CORS disabled unless a reviewed browser client requires it.
   If required, set only exact trusted origins through
   `DUSK_CORS_ALLOWED_ORIGINS`.
7. Run the container as a non-root user with a read-only root filesystem,
   dropped Linux capabilities, and a writable volume only for approved state.
8. Keep the trusted baseline read-only. Build it from reviewed data and never
   learn automatically from live requests.
9. Send verdicts and authentication failures to centralized, access-controlled
   logging without storing credentials or complete sensitive payloads.
10. Pin, scan, and regularly update container images and Python dependencies.
11. Back up offense memory only if the organization has approved its retention
    and privacy impact.
12. Test fail-open and fail-closed behavior for each integration before enabling
    enforcement.

## Vulnerability policy

CI blocks every fixable high or critical container finding and every detected
container secret. The scanner ignores advisories for which the distribution
has not published a fix so an upstream advisory cannot permanently disable the
build. Treat those advisories as accepted residual risk only after review,
rebuild images when fixes become available, and use an organization-approved
base image when policy requires a zero-finding report.

## Webhook destinations

`DUSK_N8N_ALERT_URL`, `DUSK_N8N_REPORT_URL`, and `DUSK_N8N_DECISION_URL` must resolve to public, trusted hosts. The gate rejects loopback addresses (`127.x.x.x`, `::1`, `localhost`), link-local addresses (`169.254.x.x`), and RFC1918 private ranges (`10.x.x.x`, `172.16-31.x.x`, `192.168.x.x`) at send time and logs a warning without making a network call. Set these variables to a real n8n instance or a monitored alerting endpoint. Leave them empty to disable that webhook entirely.

## Authentication

When `DUSK_GATE_API_KEY` is set, `/v1/gate` requires this header:

```text
Authorization: Bearer <secret supplied at runtime>
```

The service compares the presented value using a constant-time comparison. The
secret is never logged. Rotate it through the deployment platform and restart
instances safely. For multi-tenant or high-assurance deployments, replace this
shared-secret example with workload identity and authorization at the ingress.

## CORS

CORS is disabled by default because normal gate clients are server-side. Set a
comma-separated allowlist only when a browser client is required:

```text
DUSK_CORS_ALLOWED_ORIGINS=https://security-console.example
```

Do not use wildcard origins on an authenticated endpoint.

## Health information

The health endpoint intentionally returns operational status but no secret or
request data. Restrict it to the orchestrator and monitoring network in a real
deployment.
