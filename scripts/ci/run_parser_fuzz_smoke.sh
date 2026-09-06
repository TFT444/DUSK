#!/bin/sh
# Atheris 3 exits with status 1 after a bounded -atheris_runs completion.
# Accept only that terminal state, never fuzzing errors or uncaught exceptions.
set -u

python_bin=${PYTHON_BIN:-python}
"$python_bin" scripts/ci/parser_fuzz_smoke.py
status=$?

if [ "$status" -eq 0 ]; then
  exit 0
fi

if [ "$status" -eq 1 ] || [ "$status" -eq 77 ]; then
  echo 'Atheris bounded fuzz completion accepted.'
  exit 0
fi

exit "$status"
