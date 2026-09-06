#!/bin/sh
# Atheris 3 exits with status 1 after a bounded -atheris_runs completion.
# Accept only that terminal state, never fuzzing errors or uncaught exceptions.
set -u

python_bin=${PYTHON_BIN:-python}
output=$("$python_bin" scripts/ci/parser_fuzz_smoke.py 2>&1)
status=$?
printf '%s\n' "$output"

if [ "$status" -eq 0 ]; then
  exit 0
fi

completion_count=$(printf '%s\n' "$output" | grep -c 'Done 2000 in ' || true)
failure_count=$(printf '%s\n' "$output" | grep -Ec 'ERROR:|Uncaught Python exception|AddressSanitizer|UndefinedBehaviorSanitizer' || true)

if [ "$status" -eq 1 ] && [ "$completion_count" -gt 0 ] && [ "$failure_count" -eq 0 ]; then
  echo 'Atheris bounded fuzz completion accepted.'
  exit 0
fi

exit "$status"
