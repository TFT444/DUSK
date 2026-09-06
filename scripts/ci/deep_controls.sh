#!/bin/sh
# Run every deep control independently so one failure cannot hide later evidence.
set -u

group=${1:-all}
results="results/deep-$group"
evidence="deep-evidence/$group"
failed=0
mkdir -p "$results" "$evidence"

record_run() {
  control=$1
  shift
  started=$(date +%s)
  if "$@"; then
    status=PASS
    rc=0
  else
    rc=$?
    status=FAIL
    failed=1
  fi
  elapsed=$(($(date +%s) - started))
  python scripts/ci/control.py record \
    --control "$control" --status "$status" \
    --output "$results/$control.json" \
    --details "exit=$rc duration_seconds=$elapsed command=$*"
}

full_history_secrets() {
  docker run --rm -v "$PWD:/repo" -w /repo \
    ghcr.io/gitleaks/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854 \
    git /repo --no-banner --redact --exit-code 1 --report-format json \
    --report-path "$evidence/gitleaks.json"
}

osv_root() {
  docker run --rm -v "$PWD:/src" -w /src \
    ghcr.io/google/osv-scanner@sha256:385ff9dd9d50a573766fc226f24da1d61cd5843542ff7e04c563561bbd918e30 \
    scan source --lockfile=requirements.txt:/src/ci/requirements.lock
}

osv_example() {
  docker run --rm -v "$PWD:/src" -w /src \
    ghcr.io/google/osv-scanner@sha256:385ff9dd9d50a573766fc226f24da1d61cd5843542ff7e04c563561bbd918e30 \
    scan source --lockfile=requirements.txt:/src/ci/example-requirements.lock
}

refresh_and_build() {
  docker pull \
    ghcr.io/google/osv-scanner@sha256:385ff9dd9d50a573766fc226f24da1d61cd5843542ff7e04c563561bbd918e30 &&
    DUSK_ENFORCE=false DUSK_GATE_API_KEY=deep-ci \
    docker compose --project-name agent-action-monitor \
      -f dusk-agent-harness/compose.yml \
      -f dusk-agent-harness/compose.ci.yml \
      build --pull --no-cache dusk-gate runtime mock-prod
}

extended_properties() {
  HYPOTHESIS_PROFILE=ci python -m pytest -q &&
    (
      cd dusk-agent-harness || return
      HYPOTHESIS_PROFILE=ci PYTHONPATH=.:src:runtime python -m pytest -q
    )
}

parser_fuzz() {
  python scripts/ci/parser_fuzz_smoke.py
}

root_mutation() {
  PYTHONPATH=src mutmut run --paths-to-mutate src/dusk/policies/evidence.py \
    --test-time-base 1 \
    --runner 'env PYTHONPATH=src python -m pytest -q tests/test_policy_evidence_mutation.py'
  rc=$?
  mutmut results > "$evidence/root-mutation.txt" 2>&1 || true
  mv .mutmut-cache "$evidence/root-mutmut-cache"
  return "$rc"
}

auth_mutation() {
  PYTHONPATH=dusk-agent-harness/src mutmut run \
    --paths-to-mutate dusk-agent-harness/src/dusk/auth.py \
    --test-time-base 1 \
    --runner 'env PYTHONPATH=dusk-agent-harness/src python -m pytest -q dusk-agent-harness/tests/test_auth.py'
  rc=$?
  mutmut results > "$evidence/auth-mutation.txt" 2>&1 || true
  mv .mutmut-cache "$evidence/auth-mutmut-cache"
  return "$rc"
}

scorecard() {
  # Invoke the official action entrypoint directly so its documented
  # INPUT_REPO_TOKEN mapping works on manual feature-branch validation too.
  # GITHUB_REF is set to the repository default because the action wrapper
  # otherwise rejects non-default refs; file_mode=git still scans this checkout.
  INPUT_REPO_TOKEN=$SCORECARD_TOKEN
  export INPUT_REPO_TOKEN
  docker run --rm \
    -e INPUT_REPO_TOKEN \
    -e INPUT_RESULTS_FILE="$evidence/scorecard.json" \
    -e INPUT_RESULTS_FORMAT=json \
    -e INPUT_PUBLISH_RESULTS=false \
    -e INPUT_FILE_MODE=git \
    -e GITHUB_REPOSITORY \
    -e GITHUB_SHA \
    -e GITHUB_REF=refs/heads/main \
    -e GITHUB_EVENT_NAME=schedule \
    -e GITHUB_EVENT_PATH=/github/workflow/event.json \
    -e GITHUB_WORKSPACE=/github/workspace \
    -v "$GITHUB_EVENT_PATH:/github/workflow/event.json:ro" \
    -v "$PWD:/github/workspace" -w /github/workspace \
    ghcr.io/ossf/scorecard-action@sha256:ae5104dd3cc28466ebeb11144354be4cac4b7ff829654f9fab89021d71c46670
}

case "$group" in
  general)
    record_run SEC-027 full_history_secrets
    record_run SEC-015 osv_root
    record_run SEC-016 osv_example
    record_run SEC-019 python scripts/ci/license_policy.py
    record_run SEC-028 refresh_and_build
    record_run SEC-030 extended_properties
    record_run SEC-031 parser_fuzz
    record_run SEC-034 python scripts/ci/suppression_policy.py
    ;;
  policy-mutation)
    record_run SEC-032 root_mutation
    ;;
  auth-mutation)
    record_run SEC-033 auth_mutation
    ;;
  scorecard)
    record_run SEC-029 scorecard
    ;;
  all)
    record_run SEC-027 full_history_secrets
    record_run SEC-015 osv_root
    record_run SEC-016 osv_example
    record_run SEC-019 python scripts/ci/license_policy.py
    record_run SEC-028 refresh_and_build
    record_run SEC-030 extended_properties
    record_run SEC-031 parser_fuzz
    record_run SEC-032 root_mutation
    record_run SEC-033 auth_mutation
    record_run SEC-029 scorecard
    record_run SEC-034 python scripts/ci/suppression_policy.py
    ;;
  *)
    echo "unknown deep-control group: $group" >&2
    exit 2
    ;;
esac

exit "$failed"
