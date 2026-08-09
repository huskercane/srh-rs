FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY rust-toolchain.toml .
RUN apt-get update \
    && apt-get install --yes --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked --target x86_64-unknown-linux-musl \
    && strip target/x86_64-unknown-linux-musl/release/srh-rs

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/srh-rs /usr/local/bin/srh-rs
ENV SRH_BIND=0.0.0.0
EXPOSE 80
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/srh-rs"]
