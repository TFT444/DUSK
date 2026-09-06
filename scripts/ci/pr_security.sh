#!/bin/sh
# Emit scanner-family evidence independently and continue to expose all failures.
set -u

bandit_scan() {
  bandit -r src dusk-agent-harness/src dusk-agent-harness/runtime \
    dusk-agent-harness/mock-prod \
    dusk-agent-harness/scripts/verify_ci_sandbox.py \
    services/control-plane/src -ll -x '*/test_*.py'
}

semgrep_scan() {
  semgrep scan --config .semgrep.yml --error --metrics=off src \
    dusk-agent-harness services/control-plane
}

example_audit() {
  pip-audit -r dusk-agent-harness/runtime/requirements.txt &&
    pip-audit -r dusk-agent-harness/mock-prod/requirements.txt &&
    pip-audit -r services/control-plane/requirements.txt
}

workflow_analysis() {
  zizmor --min-severity high .github/workflows/
}

gitleaks_range() {
  base_sha=$1
  head_sha=$2
  docker run --rm -v "$PWD:/repo" -w /repo \
    ghcr.io/gitleaks/gitleaks@sha256:cdbb7c955abce02001a9f6c9f602fb195b7fadc1e812065883f695d1eeaba854 \
    git /repo --no-banner --redact --exit-code 1 --log-opts="$base_sha..$head_sha"
}

if [ "${1:-}" = "--task" ]; then
  shift
  task=${1:-}
  shift || true
  case "$task" in
    bandit_scan | semgrep_scan | example_audit | workflow_analysis)
      "$task"
      ;;
    gitleaks_range)
      gitleaks_range "$@"
      ;;
    *)
      echo "unknown security task: ${task:-<missing>}" >&2
      exit 2
      ;;
  esac
  exit
fi

base_sha=${1:-HEAD^}
head_sha=${2:-HEAD}
results=results/security
failed=0
mkdir -p "$results"

run_controls() {
  controls=$1
  shift
  if python scripts/ci/run_group.py --results "$results" --controls $controls -- "$@"; then
    :
  else
    failed=1
  fi
}

run_controls "SEC-002" sh "$0" --task bandit_scan
run_controls "SEC-003 SEC-004 SEC-005 SEC-006 SEC-007 SEC-008 SEC-009 SEC-010" sh "$0" --task semgrep_scan
run_controls "SEC-012" detect-secrets scan --baseline .secrets.baseline
run_controls "SEC-013" pip-audit -r requirements.txt
run_controls "SEC-014" sh "$0" --task example_audit
run_controls "SEC-017 SEC-018 SEC-020" python scripts/ci/lock_policy.py
run_controls "SEC-021 SEC-022 SEC-023 SEC-025 SEC-026" python scripts/ci/workflow_policy.py
run_controls "PR-045" actionlint
run_controls "PR-046 SEC-024" sh "$0" --task workflow_analysis
run_controls "PR-047" python scripts/ci/control.py validate
run_controls "PR-048" python -m pytest -q --confcutdir=tests/ci tests/ci/test_control.py
run_controls "SEC-011" sh "$0" --task gitleaks_range "$base_sha" "$head_sha"

exit "$failed"
