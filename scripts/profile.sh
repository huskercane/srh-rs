#!/usr/bin/env bash
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly OUTPUT_DIR="${PROFILE_OUTPUT_DIR:-$ROOT/target/profiling}"
readonly PERF_DATA="$OUTPUT_DIR/perf.data"
readonly FLAMEGRAPH="$OUTPUT_DIR/flamegraph.svg"
readonly REPORT="$OUTPUT_DIR/perf-report.txt"
readonly LOAD_LOG="$OUTPUT_DIR/load.txt"
readonly REDIS_CONTAINER="srh-profile-redis-${BASHPID}"
readonly DURATION="${PROFILE_DURATION:-30}"
readonly CONCURRENCY="${PROFILE_CONCURRENCY:-32}"

perf_pid=""
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid" 2>/dev/null || true
  fi
  if [[ -n "$perf_pid" ]] && kill -0 "$perf_pid" 2>/dev/null; then
    kill -INT "$perf_pid" 2>/dev/null || true
    wait "$perf_pid" 2>/dev/null || true
  fi
  docker rm --force "$REDIS_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for command in cargo curl docker flamegraph perf python3; do
  if ! command -v "$command" >/dev/null; then
    echo "missing profiling prerequisite: $command" >&2
    exit 1
  fi
done

mkdir -p "$OUTPUT_DIR"
docker run --detach --name "$REDIS_CONTAINER" --publish 127.0.0.1:16379:6379 \
  redis:7-alpine redis-server --save '' --appendonly no >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$REDIS_CONTAINER" redis-cli ping 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 0.1
done
docker exec "$REDIS_CONTAINER" redis-cli ping | grep -q PONG

RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes" \
  cargo build --locked --profile profiling --manifest-path "$ROOT/Cargo.toml"

SRH_MODE=file \
SRH_CONFIG_PATH="$ROOT/profiling/config.json" \
RUST_LOG=warn \
  "$ROOT/target/profiling/srh-rs" &
server_pid=$!

for _ in $(seq 1 100); do
  if curl --fail --silent http://127.0.0.1:18080/health >/dev/null; then
    break
  fi
  sleep 0.1
done
curl --fail --silent http://127.0.0.1:18080/health >/dev/null

# Establish the full connection envelope before sampling one-time pool initialization.
python3 "$ROOT/scripts/phase9-load.py" cpu \
  --duration 2 --concurrency "$CONCURRENCY" --warm-duration 0 >/dev/null

perf record -F 997 -g --call-graph fp -o "$PERF_DATA" -p "$server_pid" &
perf_pid=$!
sleep 0.25

# CPU totals are only comparable per request: a closed-loop generator makes a slower
# build look cheaper by serving less. Persist the throughput line next to perf.data so
# a capture can be normalized later, not just while it is still on someone's terminal.
python3 "$ROOT/scripts/phase9-load.py" cpu \
  --duration "$DURATION" --concurrency "$CONCURRENCY" --warm-duration 0 \
  | tee "$LOAD_LOG"

kill -INT "$perf_pid"
set +e
wait "$perf_pid"
perf_status=$?
set -e
if [[ "$perf_status" -ne 0 && "$perf_status" -ne 130 ]]; then
  echo "perf record failed with status $perf_status" >&2
  exit "$perf_status"
fi
perf_pid=""
kill -TERM "$server_pid"
wait "$server_pid"
server_pid=""

flamegraph --no-inline --deterministic --perfdata "$PERF_DATA" \
  --title "srh-rs canonical GET workload" -o "$FLAMEGRAPH"
perf report --stdio --no-children --call-graph none --sort comm,dso,symbol \
  -i "$PERF_DATA" >"$REPORT"

echo "CPU flame graph: $FLAMEGRAPH"
echo "perf report:     $REPORT"
echo "raw capture:     $PERF_DATA"
echo "load result:     $LOAD_LOG"
