# DUSK Compliance Control Catalogue

This catalogue tracks the security controls delivered in the first 50 percent
of the DUSK enterprise security plan. The source of truth is
[`src/dusk/policies/compliance-v1.yaml`](../src/dusk/policies/compliance-v1.yaml).

## Claim boundary

This is an implementation traceability map. It does not claim certification,
attestation, audit completion, or complete coverage of OWASP, NIST AI RMF,
NIST CSF, ISO 27001, SOC 2, or CIS Controls. A framework reference means that
the control is relevant to that framework, not that DUSK satisfies the whole
framework.

## Statuses

| Status | Meaning |
| --- | --- |
| `implemented` | A DUSK control exists and has repository evidence. |
| `partial` | Some control behaviour exists, but a required capability remains. |
| `planned` | The control is designed but is not enforced yet. |
| `blocked` | Work cannot proceed until a named dependency changes. |
| `unverified` | The control may exist, but current evidence is insufficient. |

## Evidence rules

Every control lists one or more evidence references. Implemented and partial
controls must point to files, tests, or protected-run documentation that can
be checked at a specific commit. Planned, blocked, and unverified controls
must keep their gaps visible. Evidence must not contain credentials, customer
data, raw bearer tokens, or sensitive provider payloads.

## Review process

When a rule or policy changes, update its control status and evidence in the
same pull request. Reviewers should confirm that the referenced test actually
exercises the control and that the wording does not overstate the result.
Protected model evidence must identify the model, commit, workflow run, test
counts, and evidence manifest.

## First 50 percent controls

The ten controls in the YAML catalogue cover authentication, permits, policy
scope, tenant isolation, evidence privacy, tamper resistance, downstream
blocking, least privilege, protected-run evidence, and incomplete-validation
detection. The catalogue intentionally leaves production certification,
global scale, and universal attack coverage outside its claim boundary.

## Related documents

- [Enterprise policy pack](enterprise-policy-pack.md)
- [Threat model](threat-model.md)
- [Production hardening](production-hardening.md)
- [OWASP technical evidence](owasp-technical-evidence.json)
- [First 50 percent implementation issues](https://github.com/ShieldTech-Ltd/DUSK/issues?q=is%3Aissue%20is%3Aopen%20label%3Asecurity)
