# Development

## Layout

```text
crates/core/        advisory-watch-core: parsing, matching, RPC client, reports (no I/O)
crates/cli/         advisory-watch binary: argument parsing, HTTP, files
  tests/cli.rs      end-to-end tests, including a mock RPC server
advisories/         bundled OSV records and annotations
fixtures/contracts/ source of the test contracts (not part of the workspace)
fixtures/wasm/      the built test contracts
examples/           sample inventory, cached Wasm and the Hubble query
docs/               this site (mdBook)
```

## Build and test

Requires Rust 1.88 or later.

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

The tests do not use the network. RPC behaviour is tested against a local mock server that speaks JSON-RPC over HTTP.

## Docs site

```bash
cargo install mdbook --version 0.5.4 --locked
mdbook serve docs
```

## Rebuilding fixtures

Only needed if you change a fixture contract. You need the `wasm32v1-none` target:

```bash
rustup target add wasm32v1-none
cd fixtures/contracts/sdk-25-0-1
cargo build --target wasm32v1-none --release
cp target/wasm32v1-none/release/fixture_sdk_25_0_1.wasm ../../wasm/sdk-25-0-1.wasm
```

A different rustc version changes `rsver` and the hash. Update the constants at the top of `crates/cli/tests/cli.rs` and the files in `examples/wasm/`.

## CI

`.github/workflows/ci.yml` runs these jobs on every pull request:

| Job | What it runs |
|---|---|
| `fmt` | `cargo fmt --all --check` |
| `clippy` | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| `test (ubuntu-latest)`, `test (macos-latest)`, `test (windows-latest)` | `cargo test --workspace --locked` |
| `msrv (1.88)` | the tests on Rust 1.88 |
| `docs` | `mdbook build docs` and `cargo doc` with warnings as errors |

## Releasing

1. Update the version in `Cargo.toml` and add a section to `CHANGELOG.md`.
2. Merge to `main`.
3. Tag: `git tag v0.1.0 && git push origin v0.1.0`.

`.github/workflows/release.yml` builds binaries for four targets, writes `SHA256SUMS` and creates the GitHub release with the changelog section as notes.
