# DUSK OWASP New Project Request

This file is the copy-ready submission package for the OWASP service desk. It
does not claim that OWASP has approved, endorsed, or certified DUSK.

## Request details

**Request:** New OWASP Project

**Proposed project name:** DUSK

**Project type:** Tool

**Initial maturity:** Incubator

**Primary audience:** Defenders and builders

**Repository:** https://github.com/ShieldTech-Ltd/DUSK

**Code license:** Apache License 2.0

**Documentation license:** Creative Commons Attribution-ShareAlike 4.0

**Stable release:** [v0.2.0](https://github.com/ShieldTech-Ltd/DUSK/releases/tag/v0.2.0),
published from a signed tag on the reviewed `main` commit with a wheel, source
archive, SBOM, checksums, and build provenance.

**Working validation harness:** The reviewer implementation is available on
`main` at https://github.com/ShieldTech-Ltd/DUSK/tree/main/dusk-agent-harness.

## Project description

DUSK is a vendor-neutral, open-source runtime behavioral detection and policy
gate for autonomous agent actions. It learns reviewed known-good behavior per
agent and evaluates proposed control-plane actions and observed network
behavior for deviation. Its deterministic core runs without an LLM or paid
service, with optional semantic enrichment. DUSK produces explainable allow,
observe, or block verdicts and supporting evidence for enforcing integrations.
It is currently an Incubator-stage tool and is not presented as production
ready, certified, or complete coverage of the OWASP Top 10 for Agentic
Applications.

## Purpose and OWASP alignment

DUSK turns a documented subset of agentic security guidance into testable
runtime controls. It focuses on consequences after an agent proposes an action
and before a trusted integration applies that action. This complements the
OWASP GenAI Security Project rather than redefining its taxonomy.

The threat model maps shipped, partial, and unimplemented controls separately.
The mapping does not claim compliance or complete coverage.

## Uniqueness and related projects

DUSK differs from current related OWASP work:

- The OWASP GenAI Security Project provides taxonomies and guidance. DUSK is an
  implementation tool for a limited subset of runtime mitigations.
- The OWASP Agent Security Regression Harness executes test scenarios. DUSK
  evaluates proposed actions and network behavior during operation.
- OWASP Agent Memory Guard protects memory operations. DUSK does not inspect
  memory and instead focuses on action behavior and network evidence.

These projects are complementary. DUSK will coordinate with their maintainers
where shared fixtures or integrations are useful.

## Current project health

- Public repository with documented purpose, architecture, threat model, and
  roadmap
- Apache-2.0 code and CC BY-SA 4.0 documentation licensing
- Public contribution process, DCO enforcement, governance, and Code of Conduct
- Confidential vulnerability reporting with documented response targets
- Automated tests, coverage enforcement, typing, static analysis, dependency
  auditing, secret scanning, and container scanning
- Release automation for packages, SBOM, checksums, and provenance
- Reproducible watch and enforce demo with exact verdict and downstream checks
- Deterministic core that does not require a commercial service
- Optional integrations that do not control governance or core access

## Proposed leaders

The proposed leaders are:

- Tanvir Farhad, GitHub `TFT444`
- Ritik Sah, GitHub `ritiksah141`

Before filing, enter each leader's current email and active Individual or
Complimentary Membership evidence directly in the private service desk form.
Both leaders must confirm their willingness to follow OWASP policies and sign a
leader agreement within 30 days if the Foundation provides one.

Project leadership is personal and is not held on behalf of ShieldTech or any
other employer. Employer affiliations should be disclosed in the request. If
both proposed leaders share an employer, ask the Project Committee to review
the plan for adding independent leadership.

## Foundation platform and branding commitment

If the project is accepted, the leaders will move the project to OWASP's
official source platform unless the Foundation approves an exception. They
will create and maintain the OWASP project page, monitor the official contact
and support channels, and follow OWASP branding policy. DUSK will not identify
itself as an OWASP project before approval and will not imply Foundation
endorsement of a commercial product or service.

## Public evidence

- [Governance](../GOVERNANCE.md)
- [Code of Conduct](../CODE_OF_CONDUCT.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)
- [Threat model](threat-model.md)
- [Security self-assessment](security-self-assessment.md)
- [Production hardening boundary](production-hardening.md)
- [Architecture](ARCHITECTURE.md)
- [Roadmap](../README.md#roadmap)
- [Superlinked SIE accepted example](https://github.com/superlinked/sie/tree/main/examples/agent-action-monitor)
- [Reproducible OWASP reviewer validation](../README.md#owasp-reviewer-validation)
- [Machine-readable technical evidence](owasp-technical-evidence.json), checked
  on every pull request by `scripts/check_owasp_readiness.py`
- [Application readiness tracker](owasp-readiness-tracker.md)
- [GitHub administrator settings](github-owasp-settings.md)
- [v0.2.0 release evidence](https://github.com/ShieldTech-Ltd/DUSK/releases/tag/v0.2.0)
- [v0.2.0 reviewer recording](https://github.com/ShieldTech-Ltd/DUSK/releases/download/v0.2.0/dusk-owasp-demo-v0.2.0.mp4)

## Submission authorization checklist

Complete these private or external checks immediately before filing:

- [x] The OWASP reviewer harness and application package are promoted from `dev` to `main`
- [x] The signed v0.2.0 release and technical artifacts are published
- [x] The v0.2.0 demo recording is published and linked
- [x] The maintainers reviewed the existing pull request system and chose to
      preserve it for the application
- [ ] The GitHub repository has a concise description and relevant topics
- [ ] GitHub Discussions and the documented security settings are enabled
- [x] Both proposed leaders confirm active OWASP membership
- [ ] Both proposed leaders approve the submission and OWASP policy obligations
- [ ] Current leader emails are entered in the private request
- [ ] Employer affiliations and the leadership independence plan are included
- [ ] The submitter is logged into the OWASP service desk

Submit through the
[OWASP New Project Request](https://contact.owasp.org/). Foundation approval,
repository transfer, project-page creation, and any leader agreements occur
after submission or approval and are not pre-submission evidence.
