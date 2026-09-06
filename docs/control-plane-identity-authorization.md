# Control-plane identity and authorization contract

This contract governs generic OIDC authentication and tenant-scoped authorization
for the production FastAPI control plane. The legacy Flask `/v1/gate` boundary is
not part of this service and remains unchanged.

## Trust configuration

Deployments pin an exact HTTPS issuer, audience, HTTPS JWKS URI, and asymmetric
signature-algorithm allow-list. The token header never selects an algorithm outside
that configuration. Authentication requires a valid signature and the `iss`, `aud`,
`sub`, `iat`, `nbf`, and `exp` claims.

Validated custom claims establish the tenant and identity class. A workload identity
also has a workload identifier and cannot carry console roles. A human identity has
recognized roles and cannot carry a workload identifier. Request bodies, query
parameters, and headers cannot select or override tenant, subject, identity class,
workload scope, or roles.

JWKS responses, cache lifetime, key count, response size, network timeout, and token
size are bounded. A new key ID causes one single-flight refresh. Expired keys are not
used when the identity provider is unavailable, and no path falls back to unverified
claims.

## Capabilities

Roles grant named capabilities; they are not an implicit privilege hierarchy.
Multiple human roles contribute the union of their explicit capabilities.

| Role | Capabilities |
|---|---|
| Viewer | Dashboard reads; decision-summary reads |
| Analyst | Viewer capabilities; decision detail; agent investigation; audit investigation |
| Operator | Analyst capabilities; service and integration operational status |
| Auditor | Audit investigation; immutable policy evidence |
| Administrator | Tenant and role administration only; corresponding mutation APIs are outside the first release |

## Route authorization matrix

The executable catalogue is `ROUTE_POLICIES` in `dusk_control_plane.identity`.
Future route implementations must resolve their dependency from that catalogue.

| Route | Identity | Required capability |
|---|---|---|
| `GET /livez` | Public | None |
| `GET /readyz` | Public | None |
| `POST /v2/evaluations` | Workload | Authenticated workload |
| Dashboard endpoints | Human | `dashboard:read` |
| `GET /v2/decisions` | Human | `decision-summary:read` |
| `GET /v2/decisions/{trace_id}` | Human | `decision-detail:read` |
| Agent endpoints | Human | `agent:investigate` |
| Policy endpoints | Human | `policy-evidence:read` |
| `GET /v2/integrations/health` | Human | `operations:read` |
| `GET /v2/audit-events` | Human | `audit:investigate` |
| `GET /v2/service/status` | Human | `operations:read` |

## Failure behavior

- Invalid, absent, or unverifiable credentials return `401 AUTHENTICATION_REQUIRED`.
- A verified identity-provider outage returns retryable
  `503 IDENTITY_PROVIDER_UNAVAILABLE`.
- An authenticated principal without the declared identity class or capability
  returns `403 FORBIDDEN`.
- Responses never distinguish subjects, tenants, roles, or key identifiers.
- Identity logs contain only the request ID and a bounded reason code. Tokens and raw
  or sensitive claims are never logged.
