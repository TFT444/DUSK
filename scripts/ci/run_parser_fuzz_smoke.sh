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

if [ "$status" -eq 1 ] &&
  printf '%s\n' "$output" | grep -q '^Done 2000 in ' &&
  ! printf '%s\n' "$output" | grep -Eq 'ERROR:|Uncaught Python exception|AddressSanitizer|UndefinedBehaviorSanitizer'; then
  exit 0
fi

exit "$status"
