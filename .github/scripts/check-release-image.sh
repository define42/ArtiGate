#!/usr/bin/env bash
# Smoke-test the exact local image ID that the release job will publish.
set -euo pipefail

image=${1:?image ID required}
version=${2:?expected version required}
identity=$(docker run --rm "$image" version)
case "$identity" in
  "artigate $version (manifest format "*) ;;
  *) echo "Unexpected release identity: $identity" >&2; exit 1 ;;
esac

volume=$(docker volume create)
containers=()
cleanup() {
  local status=$?
  for container in "${containers[@]}"; do
    if [ "$status" -ne 0 ]; then
      docker logs "$container" >&2 || true
    fi
    docker rm -f "$container" >/dev/null || true
  done
  docker volume rm "$volume" >/dev/null || true
  exit "$status"
}
trap cleanup EXIT

docker run --rm -v "$volume:/keys" "$image" keygen \
  --private /keys/low.ed25519 --public /keys/high.ed25519.pub
for role in low high; do
  args=("$role" --listen 127.0.0.1:8080 --root /var/lib/artigate)
  if [ "$role" = low ]; then
    args+=(--private-key /keys/low.ed25519 --export-dir /var/spool/diode-out --watch-interval 0)
  else
    args+=(--public-key /keys/high.ed25519.pub --landing /var/spool/diode-in)
  fi
  container=$(docker run -d --network none -v "$volume:/keys:ro" "$image" "${args[@]}")
  containers+=("$container")
  healthy=false
  for ((attempt=0; attempt<30; attempt++)); do
    if docker exec "$container" wget -q -T 2 -O - http://127.0.0.1:8080/healthz >/dev/null; then
      healthy=true
      break
    fi
    test "$(docker inspect --format '{{.State.Running}}' "$container")" = true
    sleep 1
  done
  if [ "$healthy" != true ]; then
    echo "$role did not become healthy" >&2
    exit 1
  fi
  docker exec "$container" wget -q -T 2 -O - http://127.0.0.1:8080/readyz >/dev/null
  docker exec "$container" wget -q -T 2 -O - http://127.0.0.1:8080/metrics \
    | grep -F "artigate_build_info{side=\"$role\",version=\"$version\""
  docker stop --time 15 "$container" >/dev/null
  test "$(docker inspect --format '{{.State.ExitCode}}' "$container")" = 0
done
