#!/bin/sh

set -eu

MODE="${1:-}"
case "$MODE" in
  watch) DUSK_ENFORCE=false ;;
  enforce) DUSK_ENFORCE=true ;;
  *) echo "usage: $0 watch|enforce" >&2; exit 2 ;;
esac

: "${DUSK_GATE_API_KEY:?DUSK_GATE_API_KEY must be set}"
export DUSK_ENFORCE

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXAMPLE_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
# Match Compose's default project name used by the build/scan steps. Changing
# this value would change the generated image tags and defeat --no-build.
PROJECT_NAME="agent-action-monitor"
COMPOSE="docker compose --project-name $PROJECT_NAME -f compose.yml -f compose.ci.yml"
LOG_DIR="${DUSK_CI_LOG_DIR:-$EXAMPLE_DIR/ci-logs}"

cd "$EXAMPLE_DIR"
mkdir -p "$LOG_DIR"

cleanup() {
  $COMPOSE logs --no-color > "$LOG_DIR/$MODE-compose.log" 2>&1 || true
  $COMPOSE down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

# Images must already have been built and scanned by the caller. --no-build
# makes the executed artifacts identical to the scanned artifacts.
$COMPOSE down --volumes --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up --detach --no-build --wait dusk-gate mock-prod
python scripts/verify_ci_sandbox.py "$MODE" --token "$DUSK_GATE_API_KEY" \
  | tee "$LOG_DIR/$MODE-evidence.json"

# Load phase: 100 mixed requests at concurrency 10.
# p50 must stay under 100 ms and p95 under 200 ms.
# The load driver exits 1 on any request error or latency breach.
# Do NOT pipe through tee: POSIX sh reports the last command's exit code
# (tee's, which is always 0), not the load driver's. Redirect to file first,
# then print; the if-condition context suppresses set -e so the exit code is
# always captured.
LOAD_LOG="$LOG_DIR/$MODE-load.log"
if ! $COMPOSE run --rm --no-deps runtime \
  python load_driver.py \
    --concurrency 10 --total 100 --poisoned-ratio 0.2 \
    --p50-limit-ms 100 --p95-limit-ms 200 \
    > "$LOAD_LOG" 2>&1
then
  cat "$LOAD_LOG"
  echo "load phase failed; see $LOAD_LOG" >&2
  exit 1
fi
cat "$LOAD_LOG"
