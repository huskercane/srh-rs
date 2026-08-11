#!/usr/bin/env bash
set -euo pipefail

# Two release targets, deliberately:
#   musl — fully static. Required by the distroless image, whose base ships no libc,
#          and portable to any host regardless of its glibc version.
#   gnu  — dynamically linked, for the systemd deployment. This workload spends roughly
#          a tenth of its CPU in the allocator and musl's mallocng contends far worse
#          across threads than glibc's, so this is the faster native-host artifact.
readonly TARGETS=(x86_64-unknown-linux-musl x86_64-unknown-linux-gnu)
readonly BIN_NAME=srh-rs

for target in "${TARGETS[@]}"; do
  rustup target add "$target"
  cargo build --release --locked --target "$target"
  binary="target/$target/release/$BIN_NAME"
  strip "$binary"
  file "$binary"
  if [[ "$target" == *-gnu ]]; then
    # The glibc floor is invisible until someone deploys onto an older host, so state it
    # here. Build in a container matching your oldest target distro to lower it.
    floor=$(objdump -T "$binary" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sort -uV | tail -1 || true)
    echo "$binary requires ${floor:-an undetermined glibc version} or newer"
  fi
done
