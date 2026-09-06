# OWASP Application Readiness Tracker

This tracker is the source of truth for DUSK's OWASP New Project Request. It
separates repository evidence from actions that require a maintainer or the
OWASP Foundation. It must be reviewed before submission and after any change to
the application package.

**Target:** OWASP Incubator, Tool project

**Last evidence review:** 21 August 2026

**Submission decision:** Not ready to submit

## Current decision

The repository has a strong Incubator-stage technical foundation, including a
clear purpose, open licenses, two proposed leaders, a public contribution
process, security documentation, a reproducible demo, and comprehensive CI.
The application should not be filed until every item in the mandatory gate
below is complete.

The most important remaining work is operational rather than architectural:
complete the public GitHub metadata and security settings, and provide the
required private leader details in the application.

## Mandatory submission gate

| Requirement | Status | Evidence or completion action |
|---|---|---|
| Public purpose and Incubator scope | Complete | [Application package](owasp-application.md) and [proposal](owasp-project-proposal.md) |
| Unique value and related-project review | Complete | [Proposal differentiation](owasp-project-proposal.md#related-owasp-work-and-differentiation) |
| OSI-approved code license | Complete | [Apache License 2.0](../LICENSE) |
| Open documentation license | Complete | [CC BY-SA 4.0](../LICENSE-docs.md) |
| Two proposed project leaders | Complete | [Governance](../GOVERNANCE.md#maintainers-and-proposed-owasp-project-leaders) |
| Public contribution process and DCO | Complete | [Contribution guide](../CONTRIBUTING.md) and CI DCO check |
| Code of Conduct | Complete | [Code of Conduct](../CODE_OF_CONDUCT.md) |
| Security reporting and threat boundaries | Complete | [Security policy](../SECURITY.md), [threat model](threat-model.md), and [self-assessment](security-self-assessment.md) |
| Reproducible reviewer validation | Complete | [Validation instructions](../README.md#owasp-reviewer-validation) and CI watch and enforce jobs |
| Version and package build | Complete | `v0.2.0` version consistency passed; wheel and source archive built and passed Twine metadata validation on 21 August 2026 |
| Stable release with SBOM, checksums, and provenance | Complete | [v0.2.0](https://github.com/ShieldTech-Ltd/DUSK/releases/tag/v0.2.0) uses a verified signed tag on `abb983e`; release workflow, checksums, and provenance verification passed |
| Public demo recording from the release tag | Complete | [90-second v0.2.0 reviewer recording](https://github.com/ShieldTech-Ltd/DUSK/releases/download/v0.2.0/dusk-owasp-demo-v0.2.0.mp4) |
| Pull request configuration | Maintainer decision | Preserve the current pull request system; no change is required for the Incubator application |
| Professional GitHub metadata | Administrator action | Apply the exact [repository profile settings](github-owasp-settings.md#1-repository-profile) |
| GitHub community support | Administrator action | Enable Discussions and create the documented `Q&A` and `Ideas` categories |
| GitHub security settings | Administrator action | Enable secret scanning, push protection, Dependabot features, and private vulnerability reporting |
| Leader membership | Complete | Both proposed leaders confirmed active OWASP membership on 21 August 2026; membership evidence remains private |
| Leader consent and affiliations | Private confirmation needed | Record both leaders' consent, current email addresses, employer affiliations, and independence plan in the service desk request |
| Final service desk submission | Not started | Submit only after all blocked and private-confirmation rows are complete |

## Incubator evidence review

The official OWASP maturity guidance requires an Incubator project website
that describes the project's intent and purpose. OWASP project policy also
requires open licensing, the official source platform after acceptance, at
least two leaders, DCO, and ongoing public activity.

| Review area | Assessment | Notes |
|---|---|---|
| Intent and purpose | Strong | The problem, audience, scope, and deployment boundary are explicit |
| Uniqueness | Strong | The proposal distinguishes DUSK from guidance, regression-harness, and memory-security projects |
| Vendor neutrality | Needs evidence | The deterministic core is service-independent; add independent community participation over time |
| Documentation | Strong | Quickstart, architecture, threat model, governance, security, CI, and hardening documentation exist |
| Technical quality | Strong | Tests, typing, linting, dependency audit, secret scanning, CodeQL, Semgrep, container scanning, and demo verification run in CI |
| Package quality | Strong | Version consistency, isolated builds, and package metadata validation are release-gated |
| Release maturity | Strong for Incubator | Signed v0.2.0 release includes wheel, source archive, SBOM, checksums, and build provenance |
| Community signal | Early | Two code contributors, no public stars, one fork, and three open roadmap issues at the last evidence review |
| Repository operations | Maintainer choice | CI is green and the maintainers chose to preserve the current pull request configuration |

## Competitive presentation priorities

These items are not formal Incubator acceptance requirements, but they improve
reviewer confidence and make the application easier to evaluate.

1. Lead with one precise problem statement and one reproducible proof.
2. Publish the release before filing so every technical claim points to an
   immutable tag rather than a moving branch.
3. Keep the demo under two minutes and show both watch and enforce outcomes.
4. Include the accepted Superlinked example as independent integration
   evidence without implying OWASP or Superlinked endorsement.
5. Avoid broad claims such as complete Agentic Top 10 coverage, production
   readiness, certification, or unique industry validation.
6. Recruit users and contributors outside the founding organization. Document
   feedback, adopted use cases, and external pull requests when they exist.
7. Keep the OWASP request concise. Link this evidence package instead of
   copying every implementation detail into the form.

## Release verification record

This table records the evidence verified on 21 August 2026.

| Evidence | Required value | Verified |
|---|---|---|
| Tag | `v0.2.0` points to the reviewed `main` commit | Yes |
| GitHub release | Public and non-draft | Yes |
| Python artifacts | Wheel and source distribution attached | Yes |
| SBOM | Release SBOM attached | Yes |
| Checksums | Checksums attached and verified | Yes |
| Provenance | Build provenance available for published artifacts | Yes |
| Demo recording | `dusk-owasp-demo-v0.2.0.mp4` attached | Yes |
| README | Release and recording links updated | Yes |

## Final sign-off

The submitter should record the final reviewed commit, release URL, recording
URL, and submission ticket privately. Do not add leader email addresses,
membership records, or service desk ticket contents to this public repository.

The application is ready only when the mandatory gate contains no `Blocked`,
`Administrator action`, `Private confirmation needed`, or `Not started` status.
