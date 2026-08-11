#!/usr/bin/env bash
# Network-free CPU profile of the proxy's own work.
#
# `profile.sh` measures the deployed shape end to end, and about a third of its samples land
# in the kernel: loopback TCP for the client hop, loopback TCP for the Redis hop, and the
# syscalls around both. That cost is real but it is not ours, and it crowds out the code we
# can change. This harness serves the same Hyper + Axum + domain stack over an in-memory
# duplex transport against a constant-reply executor, so the capture is ~5% kernel instead.
#
# Use this to attribute proxy CPU and allocation cost. Use `profile.sh` for the end-to-end
# number; throughput here is not comparable to it.
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly OUTPUT_DIR="${PROFILE_OUTPUT_DIR:-$ROOT/target/profiling-inproc}"
readonly PERF_DATA="$OUTPUT_DIR/perf.data"
readonly FLAMEGRAPH="$OUTPUT_DIR/flamegraph.svg"
readonly REPORT="$OUTPUT_DIR/perf-report.txt"
readonly DURATION="${PROFILE_DURATION:-20}"
readonly CONCURRENCY="${PROFILE_CONCURRENCY:-32}"

for command in cargo perf; do
  if ! command -v "$command" >/dev/null; then
    echo "missing profiling prerequisite: $command" >&2
    exit 1
  fi
done

mkdir -p "$OUTPUT_DIR"
RUSTFLAGS="${RUSTFLAGS:-} -C force-frame-pointers=yes" \
  cargo build --locked --profile profiling --bin profile-inproc --manifest-path "$ROOT/Cargo.toml"

# Cycles per request first. Closed-loop throughput on a machine that is doing anything else
# swings ±15% run to run, which is wider than most changes worth making; per-request cost
# holds to about ±2%, so it is what an A/B should be judged on.
echo "Cycles per request (median of 5):"
for _ in 1 2 3 4 5; do
  measured=$(perf stat -e cycles -x, "$ROOT/target/profiling/profile-inproc" \
    --duration 5 --connections "$CONCURRENCY" "$@" 2>&1)
  requests=$(printf '%s' "$measured" | grep -oE 'requests=[0-9]+' | cut -d= -f2)
  cycles=$(printf '%s' "$measured" | grep -oE '^[0-9]+,,cycles' | cut -d, -f1)
  echo $((cycles / requests))
done | sort -n | awk '{v[NR]=$1} END {printf "  %s cycles/req  (%s .. %s)\n", v[int((NR+1)/2)], v[1], v[NR]}'

# The load generator runs on its own runtime with its threads named `srh-loadgen`, so its
# cost is attributable and is filtered out of the report below rather than guessed at.
perf record -F 997 -g --call-graph fp -o "$PERF_DATA" -- \
  "$ROOT/target/profiling/profile-inproc" \
  --duration "$DURATION" --connections "$CONCURRENCY" "$@"

perf report --stdio --no-children --call-graph none --sort dso,symbol \
  --comms srh-server -i "$PERF_DATA" >"$REPORT"

if command -v flamegraph >/dev/null; then
  flamegraph --no-inline --deterministic --perfdata "$PERF_DATA" \
    --title "srh-rs in-process (server threads)" -o "$FLAMEGRAPH"
  echo "CPU flame graph: $FLAMEGRAPH"
fi

echo "perf report:     $REPORT   (server threads only)"
echo "raw capture:     $PERF_DATA"
echo
echo "Kernel share of the server threads:"
grep -E '^ +[0-9]+\.[0-9]+%' "$REPORT" | awk '{p=$1; sub("%","",p); if ($2 ~ /kernel|vdso|^\[/) k+=p; t+=p} END {printf "  %.1f%% of %.1f%% accounted\n", k, t}'
