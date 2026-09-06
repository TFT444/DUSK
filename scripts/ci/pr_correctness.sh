#!/bin/sh
# Emit evidence per logical control family and continue to expose all failures.
set -u

ruff_check() {
  ruff check src tests scripts dusk-agent-harness/src \
    dusk-agent-harness/tests dusk-agent-harness/runtime \
    dusk-agent-harness/mock-prod dusk-agent-harness/lab \
    dusk-agent-harness/scripts services/control-plane/src \
    services/control-plane/tests services/control-plane/scripts
}

ruff_format() {
  ruff format --check src tests scripts dusk-agent-harness/src \
    dusk-agent-harness/tests dusk-agent-harness/runtime \
    dusk-agent-harness/mock-prod dusk-agent-harness/lab \
    dusk-agent-harness/scripts services/control-plane/src \
    services/control-plane/tests services/control-plane/scripts
}

mypy_services() {
  (
    cd dusk-agent-harness || return
    mypy src/dusk runtime/bedrock_client.py runtime/mock_bedrock.py \
      runtime/harness.py runtime/load_driver.py runtime/run_scenario.py \
      runtime/stub_gate.py mock-prod/app.py scripts/verify_ci_sandbox.py \
      --ignore-missing-imports
  ) && (
    cd services/control-plane || return
    mypy src/dusk_control_plane
  )
}

vulture_root() {
  vulture src tests scripts/vulture_whitelist.py --min-confidence 60 \
    --ignore-decorators '@main.command,@click.*,@app.route,@app.get,@app.post,@*.fixture' \
    --ignore-names return_value,side_effect
}

vulture_example() {
  (
    cd dusk-agent-harness || return
    vulture src tests runtime mock-prod scripts/vulture_whitelist.py \
      scripts/verify_ci_sandbox.py --min-confidence 60 \
      --ignore-decorators '@app.route,@app.get,@app.post,@click.*,@*.fixture' \
      --ignore-names return_value,side_effect,testing
  )
}

vulture_all() {
  vulture_root && vulture_example &&
    vulture services/control-plane/src services/control-plane/tests \
      services/control-plane/scripts/vulture_whitelist.py \
      --min-confidence 60 \
      --ignore-decorators '@app.get,@app.middleware,@*.fixture' \
      --ignore-names testing,model_config,service,version,DEVELOPMENT,\
protect_non_local_deployments,validation_error,http_error,unhandled_error,fail_for_test,\
authentication_error,identity_unavailable,authorization_error,require_route_policy,\
evaluate,operations,protected,consequential
}

documentation_contracts() {
  python scripts/check_config_docs.py &&
    python scripts/check_release_version.py &&
    python scripts/check_owasp_readiness.py
}

compose_contract() {
  DUSK_ENFORCE=false DUSK_GATE_API_KEY=contract-check \
    docker compose -f dusk-agent-harness/compose.yml \
      -f dusk-agent-harness/compose.ci.yml config --quiet &&
    docker compose -f services/control-plane/compose.yml \
      --profile control-plane config --quiet
}

openapi_contracts() {
  openapi-spec-validator dusk-agent-harness/contracts/gate.openapi.yaml &&
    openapi-spec-validator services/control-plane/contracts/openapi.json &&
    (cd services/control-plane && python scripts/export_openapi.py --check)
}

root_tests() {
  pytest -n auto --dist loadscope --cov=src/dusk --cov-branch --cov-fail-under=70
}

example_tests() {
  (
    cd dusk-agent-harness || return
    PYTHONPATH=.:src:runtime pytest -n auto --dist loadscope
  ) &&
    pytest -n auto --dist loadscope services/control-plane/tests
}

# Shell functions are not child-process executables. Dispatch them through this
# script so run_group.py can execute each family and record independent evidence.
if [ "${1:-}" = "--task" ]; then
  shift
  case "${1:-}" in
    ruff_check | ruff_format | mypy_services | vulture_all | \
      documentation_contracts | compose_contract | openapi_contracts | root_tests | \
      example_tests)
      "$1"
      ;;
    *)
      echo "unknown correctness task: ${1:-<missing>}" >&2
      exit 2
      ;;
  esac
  exit
fi

base_sha=${1:-HEAD^}
head_sha=${2:-HEAD}
results=results/correctness
failed=0
mkdir -p "$results"

run_controls() {
  controls=$1
  shift
  # Control IDs are a static, space-delimited list owned by this script.
  if python scripts/ci/run_group.py --results "$results" --controls $controls -- "$@"; then
    :
  else
    failed=1
  fi
}

run_controls "PR-001" python scripts/check_dco.py "$base_sha" "$head_sha"
run_controls "PR-002 PR-003 PR-004 PR-005 PR-006 PR-007 PR-008 PR-009 PR-010 PR-018 PR-020" \
  python scripts/ci/repository_checks.py
run_controls "PR-011 PR-012 PR-013 PR-014 PR-016 PR-017" sh "$0" --task ruff_check
run_controls "PR-015" sh "$0" --task ruff_format
run_controls "PR-021" mypy src/dusk
run_controls "PR-022" sh "$0" --task mypy_services
run_controls "PR-023" python -m compileall -q src dusk-agent-harness/src \
  services/control-plane/src
run_controls "PR-019" sh "$0" --task vulture_all
run_controls "PR-024" sh "$0" --task openapi_contracts
run_controls "PR-025" sh "$0" --task compose_contract
run_controls "PR-028" sh "$0" --task documentation_contracts
run_controls "PR-029" python scripts/ci/public_api_check.py "$base_sha"
run_controls "PR-026 PR-027 PR-030 PR-039 PR-041 PR-042" sh "$0" --task root_tests
run_controls "PR-031 PR-032 PR-033 PR-034 PR-035 PR-036 PR-037 PR-038" sh "$0" --task example_tests
run_controls "PR-040" python scripts/ci/parser_fuzz_smoke.py

exit "$failed"
