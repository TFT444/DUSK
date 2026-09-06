#!/bin/sh
set -eu

harness=dusk-agent-harness
control_plane=services/control-plane
project=agent-action-monitor
compose="docker compose --project-name $project -f $harness/compose.yml -f $harness/compose.ci.yml"

# Build each image once. Every later operation addresses the immutable local ID.
DUSK_ENFORCE=false DUSK_GATE_API_KEY=ci-control $compose build dusk-gate runtime mock-prod
docker build --tag dusk-control-plane:ci --file "$control_plane/Dockerfile" .
gate_id=$(docker image inspect --format '{{.Id}}' "$project-dusk-gate")
runtime_id=$(docker image inspect --format '{{.Id}}' "$project-runtime")
mock_id=$(docker image inspect --format '{{.Id}}' "$project-mock-prod")
control_plane_id=$(docker image inspect --format '{{.Id}}' dusk-control-plane:ci)

# Exercise the installed console script and packaged Alembic migrations against
# the same real PostgreSQL version used by the deployment integration suite.
test -n "${DUSK_TEST_DATABASE_URL:-}"
docker run --rm --network host \
  -e "DUSK_CP_DATABASE_URL=$DUSK_TEST_DATABASE_URL" \
  -e DUSK_CP_MIGRATION_LOCK_TIMEOUT_MS=1000 \
  -e DUSK_CP_MIGRATION_STATEMENT_TIMEOUT_MS=30000 \
  "$control_plane_id" dusk-control-plane-migrate
mkdir -p container-evidence
cp ci/grype.yml container-evidence/grype.yaml
printf '%s\n%s\n%s\n%s\n' "$gate_id" "$runtime_id" "$mock_id" "$control_plane_id" \
  > container-evidence/image-ids.txt

for dockerfile in "$harness/Dockerfile" "$harness/runtime/Dockerfile" \
  "$harness/mock-prod/Dockerfile" "$control_plane/Dockerfile"; do
  docker run --rm -i hadolint/hadolint:v2.12.0-alpine hadolint - < "$dockerfile"
done

for image_id in "$gate_id" "$runtime_id" "$mock_id" "$control_plane_id"; do
  test "$(docker image inspect --format '{{.Config.User}}' "$image_id")" != ""
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.58.2 \
    image --exit-code 1 --ignore-unfixed \
    --severity HIGH,CRITICAL --scanners vuln,secret,misconfig "$image_id"
  name=$(printf '%s' "$image_id" | cut -c8-19)
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/container-evidence:/out" \
    anchore/syft@sha256:b8c170b8e51bfc4779ec3ef4399942c57290f5ce76a9c3af564c9d00d4946a6b \
    "$image_id" -o cyclonedx-json="/out/$name.cdx.json"
  docker run --rm -v "$PWD/container-evidence:/out" anchore/grype:v0.86.1 \
    "sbom:/out/$name.cdx.json" --config /out/grype.yaml --fail-on high
done

# Compose carries read-only roots, ALL capability drops and no-new-privileges.
DUSK_ENFORCE=false DUSK_GATE_API_KEY=ci-control $compose config > container-evidence/compose.json
docker compose -f "$control_plane/compose.yml" --profile control-plane config \
  > container-evidence/control-plane-compose.json
grep -q 'read_only: true' container-evidence/compose.json
grep -q 'cap_drop:' container-evidence/compose.json
grep -q 'read_only: true' container-evidence/control-plane-compose.json
grep -q 'cap_drop:' container-evidence/control-plane-compose.json
for image_id in "$gate_id" "$mock_id" "$control_plane_id"; do
  test "$(docker image inspect --format '{{json .Config.Healthcheck}}' "$image_id")" != "null"
done
for image_id in "$gate_id" "$runtime_id" "$mock_id" "$control_plane_id"; do
  ! docker run --rm --entrypoint sh "$image_id" -c 'command -v pip || command -v gcc || command -v make'
done

# --no-build in the harness guarantees sandbox execution uses the IDs above.
(cd "$harness" && DUSK_GATE_API_KEY=ci-control sh scripts/run_ci_sandbox.sh watch)
(cd "$harness" && DUSK_GATE_API_KEY=ci-control sh scripts/run_ci_sandbox.sh enforce)
test "$gate_id" = "$(docker image inspect --format '{{.Id}}' "$project-dusk-gate")"
test "$runtime_id" = "$(docker image inspect --format '{{.Id}}' "$project-runtime")"
test "$mock_id" = "$(docker image inspect --format '{{.Id}}' "$project-mock-prod")"
