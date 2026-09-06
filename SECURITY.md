# Security Policy

## Reporting a Vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email `ritiksah141@gmail.com` and `tanvirfarhad007@gmail.com` with the subject
`DUSK security report`. Include affected versions, reproduction steps, impact,
and any suggested remediation. You will receive acknowledgement within 72
hours.
We target a patch within 30 days for critical issues, 90 days for others.
We follow coordinated disclosure, we will notify you before public disclosure.

## Scope

In scope: bypass of detection logic, privilege escalation via the CLI,
dependency vulnerabilities, unsafe handling of pcap input.

Out of scope: theoretical attacks with no practical path, issues in lab/
scenarios (test code only).

## Supported Versions and Release Status

| Version | Release status | Security support |
|---------|----------------|------------------|
| 0.2.x   | Unreleased | Development branch only |
| 0.1.x   | Historical prototype | No |

DUSK does not currently have a published GitHub release. Until the first
release is published, accepted security fixes are applied to the development
branch and do not represent support for a released version. After publication,
this table will identify the supported released minor version.

## Deployment Boundary

The HTTP service under `dusk-agent-harness` is part of the DUSK Production Agent
Harness. Its default Compose configuration binds published ports to localhost.
It is not an internet-ready deployment and must not be exposed directly.

Production deployments must provide authentication, TLS, request rate limits,
network allowlists, restricted CORS, centralized audit logging, and a managed
WSGI server or equivalent ingress. Set `DUSK_GATE_API_KEY` to require bearer
authentication at the example gate. Store that value in a secret manager, not
in source control, image layers, Compose files, or shell history.

See [docs/production-hardening.md](docs/production-hardening.md) for the full
deployment checklist.
