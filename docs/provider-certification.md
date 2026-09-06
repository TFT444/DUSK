# Cloud and Kubernetes certification evidence

AWS, Azure, and Kubernetes launch claims require protected runs against approved
sandboxes. Unit tests, emulators, local clusters, recorded payloads, parsers, and
green CI jobs are not certification evidence.

`scripts/validate_provider_certification.py` validates the sanitized manifest
produced by a protected run. It fails closed unless one run contains all of the
following:

- OIDC-authenticated AWS, Azure, and Kubernetes identities represented only by
  SHA-256 digests;
- the complete malicious and benign scenario matrix in both watch and enforce
  modes;
- the immutable service image digest and successful provider commands, with
  command output stored only as a digest;
- trace, persisted decision, matched policy, tamper-evident audit, dashboard,
  and broker acknowledgement continuity;
- identical before/after resource-state digests for every blocked operation;
- successful teardown and restoration of each sandbox baseline; and
- a security reviewer, approval reference, and approval timestamp.

The reviewed manifest must certify the complete `DUSK-CLOUD-001` through
`DUSK-CLOUD-010` set. Partial rule activation is rejected so a deployment cannot
quietly omit a failed provider scenario.

The validator rejects evidence labelled as mocked or simulated and scans command
arguments for bearer tokens and AWS access-key identifiers. Protected runners
must additionally prevent all credentials and unrestricted provider responses
from entering artifacts or logs.

Run the structural check after downloading a protected artifact:

```console
python scripts/validate_provider_certification.py provider-certification.json
```

A successful structural check does not independently prove that assertions in a
manifest are truthful. Certification also requires the protected workflow run,
GitHub artifact attestation, approved sandbox change record, and human security
review. Evidence is valid only for the exact Git commit and service image digest
recorded in the manifest.

## Trusted telemetry boundary

Collectors normalize native provider records before submission and never send
the unrestricted source record to the control plane:

| Source | Required native identity | Canonical domains | Replay identifier |
| --- | --- | --- | --- |
| AWS CloudTrail management event | Event source plus provisioned collector identity | `action`, `cloud`, `infrastructure` | CloudTrail `eventID` |
| Azure Activity Log | Provisioned collector identity and subscription-qualified `resourceId` | `action`, `cloud`, `infrastructure` | `eventDataId` or `correlationId` |
| Kubernetes AdmissionReview `v1` | Admission webhook service account and cluster identity | `action`, `kubernetes` | Admission request `uid` |

Each canonical domain is independently signed using the versioned
`dusk-provider-evidence-v1` envelope. The source registry binds an Ed25519 key ID
to exactly one tenant, collector identity, and set of allowed domains. Rotation
adds a new key ID before retiring the old one. PostgreSQL atomically claims each
tenant/source/nonce tuple, so retries or concurrent replicas cannot evaluate the
same provider event twice.

Cloud evidence supplies account or subscription boundaries, deployment
environment, exposure semantics, control state, and workload-identity binding.
Kubernetes evidence supplies the admission operation, namespace, role,
privileged-container status, and service/ingress exposure. Infrastructure-plan
evidence supplies destructive changes and safeguards disabled by the plan.
Missing, stale, conflicted, unsigned, cross-tenant, or replayed evidence fails
closed for consequential actions.

## Required scenarios

| Platform | Malicious | Benign equivalent |
| --- | --- | --- |
| AWS | Privileged IAM escalation; destructive network action | Scoped IAM change; private network change |
| Azure | Privileged or cross-tenant role assignment | Tenant-scoped, least-privilege role assignment |
| Kubernetes | Cluster-admin grant; privileged workload; public exposure | Namespace RBAC; restricted workload; private service |

The protected runner must restore the baseline even when a scenario fails. A
failed cleanup invalidates the entire provider result and requires sandbox
recovery before another run.

## Deferred live gate

Cloud account provisioning and live execution are intentionally deferred until
the backend and frontend pass their localhost integration programme. The
repository therefore does not contain
`docs/evidence/provider-certification.json` yet. Pull-request CI does not require
that artifact, while the production release workflow does. A tag cannot pass
the release gate until a protected run produces the sanitized manifest, all ten
cloud rules are listed, and security review is recorded.

Live qualification is tracked by GitHub issue #251 and must not be closed by
this localhost-readiness change.

This is a sequencing decision, not evidence of provider validation. Until the
artifact is present and independently reviewed:

- production construction of the policy integration rejects all
  `DUSK-CLOUD-*` activation;
- no release may claim AWS, Azure, or managed-Kubernetes certification; and
- localhost or `kind` results remain development evidence only.
