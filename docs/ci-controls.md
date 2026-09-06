# Enterprise CI controls

`ci/controls.yml` is the versioned source of truth for all 100 controls. Every entry records its ID,
description, tool, owning lane, blocking status, and permitted applicability. The initial contract is
PR-001–PR-048, SEC-001–SEC-034, CTR-001–CTR-010, and REL-001–REL-008. Removal requires a reviewed
replacement or written justification. CodeQL availability or licensing failures are failures, never
automatic skips.

## Enforcement and thresholds

| Lane | Controls | Gate | Budget | Trigger |
| --- | ---: | --- | ---: | --- |
| Pull request | 81 | `security-gate` | 12 minutes | PRs and pushes to `dev`/`main` |
| Deep security | 11 | `deep-security-gate` | 30 minutes | Monday 03:23 UTC or manual |
| Release | 8 | `release-gate` | 20 minutes | `v*` tags or manual dry run |

All controls block. Aggregation rejects failed, absent, duplicate, malformed, and unexpected results.
`NOT_APPLICABLE` is authorized only for CTR-001–CTR-010 with a non-empty documentation-only change
set. Cancelled or skipped upstream jobs fail the gate.

Line and branch coverage must be at least 70%. Trivy and Grype reject fixable high or critical
vulnerabilities; Bandit uses medium-or-higher severity; gitleaks rejects any finding. Sandbox latency
must remain below 50 ms p50 and 200 ms p95. Two independent release builds must be byte-identical.

## Local reproduction

```sh
python -m pip install -e '.[dev]' vulture openapi-spec-validator pip-audit semgrep detect-secrets
python scripts/ci/control.py validate
sh scripts/ci/pr_correctness.sh origin/dev HEAD
sh scripts/ci/pr_security.sh origin/dev HEAD
sh scripts/ci/container_controls.sh
```

Weekly and release lanes use `scripts/ci/deep_controls.sh` and `scripts/ci/release_controls.sh`.
The deep runner accepts `general`, `policy-mutation`, `auth-mutation`, and `scorecard` groups; the
workflow runs those groups in parallel and aggregates their independent evidence. Mutation testing
is deliberately limited to the fail-closed policy-evidence classifier and gate-authentication
boundary. Their direct boundary suites must kill every generated non-equivalent mutant; surviving
or suspicious mutants fail SEC-032 or SEC-033. This keeps the control security-relevant and avoids
repeatedly mutating unrelated parsing, logging, and API setup code.
Scanner additions require a deliberately failing fixture and a test proving detection.

To reproduce the two mutation controls locally:

```sh
sh scripts/ci/deep_controls.sh policy-mutation
sh scripts/ci/deep_controls.sh auth-mutation
```

## Suppressions, ownership, and evidence

CI Platform owns PR-001–PR-048, SEC-011–SEC-034, CTR-001–CTR-010, and REL-001–REL-008. Security
Engineering owns SEC-001–SEC-010. CODEOWNERS applies to workflows, catalogue, scripts, and
suppressions.

Suppressions exist only in `ci/suppressions.yml`. Each requires a control, specific reason,
accountable owner, and ISO expiry date. SEC-034 rejects expired or incomplete entries. Result and
scanner artifacts are retained for 30 days; evidence must not contain credentials or raw findings.

## Hosted-runner measurements

The PR remains draft until at least three hosted-runner measurements are recorded and all maxima are
within budget. Jobs over budget must be optimized with sharding, manifest-keyed caches, or reuse of
exact artifacts—not by weakening or skipping controls.

| Run | Commit | PR lane | Deep lane | Release dry run |
| --- | --- | ---: | ---: | ---: |
| 1 | `aa1dba6` / `7cac999` | 3m30s ([run 32745875080](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32745875080)) | Pending administrator token | 1m11s ([run 32744086308](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32744086308)) |
| 2 | `f9aa701` / `aa1dba6` | 4m03s ([run 32748254239](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32748254239)) | Pending administrator token | 1m16s ([run 32746335783](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32746335783)) |
| 3 | `2c33aa4` / `e343dda` | 4m22s ([run 32748727611](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32748727611)) | Pending final parallel validation | 1m10s ([run 32751635453](https://github.com/ShieldTech-Ltd/DUSK/actions/runs/32751635453)) |

For a release dry run, dispatch Release against an existing verified annotated tag with
`publish=false`. Publishing is allowed only after `release-gate`; it downloads the exact bytes built,
checked, checksummed, SBOM-generated, and attested upstream. Scheduled and release failures cannot
silently continue. CodeQL and attestation temporarily capture tool outcomes solely to emit explicit
`FAIL` evidence before their gates reject the run.

## Administrator handoff

The following repository settings cannot be committed in a pull request and must be applied by a
repository administrator before this PR is marked ready:

1. Create a fine-grained token limited to `ShieldTech-Ltd/DUSK` with `Administration: read` and
   `Metadata: read`, then add it as the Actions repository secret `SCORECARD_TOKEN`. Re-run **Deep
   security** and require `deep-security-gate` to pass.
2. In **Settings → Code security → Code scanning**, disable CodeQL default setup. Retain the custom
   `codeql` job in `.github/workflows/dusk.yml`; it runs `security-extended` and is aggregated into
   `security-gate`.
3. Protect `dev` and `main` (classic protection or repository ruleset). Require only
   `security-gate` as the CI status, at least one approving review, dismissal of stale approvals,
   conversation resolution, and no force pushes or branch deletion.
4. Confirm Actions permissions default to read-only and that workflows from forks require approval.
   No PR job references `SCORECARD_TOKEN`; it is available only to trusted scheduled/manual deep
   runs.

After applying the settings, run the PR lane three times, **Deep security** three times, and the
Release dry run three times with `publish=false`. Replace the pending deep timings above with links
to successful runs and keep the PR draft until every documented maximum is met.
