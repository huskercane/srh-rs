#!/usr/bin/env bash
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly NETWORK=srh-phase9
readonly REDIS=redis-phase9
readonly PROXY=srh-phase9
readonly IMAGE=srh-rs:phase9

cleanup() {
  docker kill --signal CONT "$REDIS" >/dev/null 2>&1 || true
  docker rm --force "$PROXY" "$REDIS" >/dev/null 2>&1 || true
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}

finish() {
  if [[ "${PHASE9_KEEP_CONTAINERS:-0}" != "1" ]]; then
    cleanup
  fi
}

failed() {
  docker logs --tail 100 "$PROXY" 2>/dev/null || true
}

trap failed ERR
trap finish EXIT
cleanup

if [[ "${PHASE9_SKIP_BUILD:-0}" != "1" ]]; then
  docker build --tag "$IMAGE" "$ROOT"
fi
docker network create "$NETWORK" >/dev/null
docker run --detach --name "$REDIS" --network "$NETWORK" --network-alias redis \
  redis:7-alpine redis-server --save '' --appendonly no >/dev/null
docker run --detach --name "$PROXY" --network "$NETWORK" \
  --publish 127.0.0.1:18080:80 \
  --publish 127.0.0.1:19090:9090 \
  --env SRH_MODE=file \
  --env SRH_CONFIG_PATH=/etc/srh-rs/phase9.json \
  --env RUST_LOG=warn \
  --volume "$ROOT/load/phase9-config.json:/etc/srh-rs/phase9.json:ro" \
  "$IMAGE" >/dev/null

for _ in $(seq 1 60); do
  if curl --fail --silent http://127.0.0.1:18080/health >/dev/null; then
    break
  fi
  sleep 1
done
curl --fail --silent http://127.0.0.1:18080/health >/dev/null
docker run --rm --network "container:$PROXY" curlimages/curl:8.14.1 \
  --fail --silent http://127.0.0.1/ready >/dev/null

common=(--proxy-container "$PROXY" --redis-container "$REDIS")
profile="${PHASE9_PROFILE:-all}"
if [[ "$profile" == "all" || "$profile" == "overload" ]]; then
  if [[ "${PHASE9_SMOKE:-0}" == "1" ]]; then
    python3 "$ROOT/scripts/phase9-load.py" overload "${common[@]}" --duration 10 --concurrency 16
  else
    python3 "$ROOT/scripts/phase9-load.py" overload "${common[@]}"
  fi
fi
if [[ "$profile" == "all" || "$profile" == "backend-death" ]]; then
  if [[ "${PHASE9_SMOKE:-0}" == "1" ]]; then
    python3 "$ROOT/scripts/phase9-load.py" backend-death "${common[@]}" \
      --duration 12 --stop-at 4 --continue-at 8 --concurrency 16
  else
    python3 "$ROOT/scripts/phase9-load.py" backend-death "${common[@]}"
  fi
fi
if [[ "$profile" == "all" || "$profile" == "slow-client" ]]; then
  python3 "$ROOT/scripts/phase9-load.py" slow-client "${common[@]}"
fi
if [[ "$profile" != "all" && "$profile" != "overload" && "$profile" != "backend-death" && "$profile" != "slow-client" ]]; then
  echo "unknown PHASE9_PROFILE: $profile" >&2
  exit 2
fi

docker run --rm --network "container:$PROXY" curlimages/curl:8.14.1 \
  --fail --silent http://127.0.0.1/ready >/dev/null
