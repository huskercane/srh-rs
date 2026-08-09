# Repository Guidelines

## Project Structure & Module Organization

This Rust 2024 crate implements an Upstash-compatible Redis HTTP proxy. Keep the hexagonal architecture described in `srh-rust-spec.md`:

- `src/domain/` contains pure business types and rules.
- `src/ports/` defines traits used at architectural boundaries.
- `src/adapters/` contains outbound implementations such as Redis and authentication clients.
- `src/http/` contains Axum handlers and inbound request processing.
- `src/testsupport/` provides feature-gated fakes for tests.
- `src/main.rs` is the composition root; `src/lib.rs` exposes application modules and shared state.
- `tests/` holds integration and architecture tests. Build artifacts belong in `target/` and must not be committed.

Preserve the dependency rule: `domain` and `ports` must not import Axum, Fred, Reqwest, Hyper, or Tower. Concrete adapter types should be named only in their module and in `main.rs`.

## Dependency Policy

Use `hyper` and `hyper-util` directly for all outbound HTTP work, including the Phase 6 JWKS and introspection adapters. Do not add `reqwest` to dependencies, dev-dependencies, tests, or source code. Keep TLS on the existing rustls `ring` provider and verify feature unification with `cargo tree -e features -i rustls` after changing networking dependencies. Use the standalone `url` crate when URL parsing is needed.

## Build, Test, and Development Commands

The pinned Rust 1.97 toolchain is selected through `rust-toolchain.toml`.

- `cargo build` compiles the library and binary.
- `cargo run` starts the local binary (the server entry point is still being implemented).
- `cargo test` runs unit and integration tests, including `tests/dependency_rule.rs`.
- `cargo test --features testsupport` exposes reusable fakes to feature-dependent tests.
- `cargo fmt --all -- --check` verifies standard Rust formatting.
- `cargo clippy --all-targets --all-features -- -D warnings` treats lint warnings as failures.

Run formatting, Clippy, and tests before opening a pull request.

## Coding Style & Naming Conventions

Use `rustfmt` defaults (four-space indentation) and keep `#![forbid(unsafe_code)]`. Follow Rust conventions: `snake_case` for modules, functions, and tests; `UpperCamelCase` for types and traits; `SCREAMING_SNAKE_CASE` for constants. Prefer small port traits wired as `Arc<dyn Trait>` and `async_trait` for async ports. Keep business decisions out of HTTP handlers and hand-write fakes rather than adding a mocking framework.

## Testing Guidelines

Place focused unit tests beside their implementation and cross-module behavior in `tests/`. Give tests behavior-oriented names such as `domain_and_ports_do_not_import_adapter_dependencies`. Add contract tests when multiple implementations of a port must share semantics. Integration tests may use `testcontainers` for Redis and `wiremock` for HTTP dependencies.

### Mutation sweep before a release tag

A green suite is necessary, not sufficient. `tests/mutation_guard.rs` breaks one invariant at a time in a scratch copy of the crate and asserts the suite notices. It is `#[ignore]`d, so CI's `cargo test --all-features` skips it; run it by hand before tagging a release:

```bash
cargo test --test mutation_guard -- --ignored --nocapture
```

It takes about eight minutes on a warm cache, needs no Docker, and never touches the working tree — the scratch copy and its build artifacts live under `target/mutation-guard/`.

When you add a regression lock, add the mutation it is supposed to kill. Three rules keep the sweep honest:

- A mutation whose search text no longer matches **exactly once** is a hard failure, not a pass. A silent no-op reads as "this invariant is covered" when nothing ran. Locks that repeat production data verbatim — the `HARD_DENY` literal list — need `Mutation::region` to disambiguate.
- A mutation that fails to compile proves nothing and is rejected rather than counted as a kill.
- Surviving mutations must be declared as `Equivalent` (behaviour-preserving) or `KnownGap` (a real, recorded hole), each with a reason. The assertion is set equality, so fixing a `KnownGap` fails the sweep until its entry is deleted — deliberately, so recorded gaps cannot rot into permanent excuses.

## Commit & Pull Request Guidelines

History uses Conventional Commit subjects such as `chore: scaffold Rust project`. Continue with concise, imperative prefixes (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Keep each commit scoped to one logical change. Pull requests should summarize behavior, identify the implementation-spec phase or linked issue, call out configuration/security effects, and list verification commands. Include request/response examples for wire-protocol changes; screenshots are generally unnecessary for this API service.
