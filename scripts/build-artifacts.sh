#!/usr/bin/env bash
set -euo pipefail

readonly TARGET=x86_64-unknown-linux-musl
rustup target add "$TARGET"
cargo build --release --locked --target "$TARGET"
strip "target/$TARGET/release/srh-rs"
file "target/$TARGET/release/srh-rs"
