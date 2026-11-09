# Contributing

Thanks for helping. This guide covers how work is assigned, how to set up, and what a pull request needs.

## Drips Stellar Wave

This repository takes part in the [Drips Stellar Wave Program](https://www.drips.network/wave/stellar).

1. Find an open issue. Issues labelled `good first issue` are scoped for newcomers.
2. Apply to the issue through Drips.
3. **Wait until a maintainer assigns you.** Pull requests for unassigned issues may be closed.
4. If you can no longer work on an issue, say so in the issue so it can be reassigned.

Comment on the issue if anything in it is unclear before you start.

## Setup

You need Rust 1.88 or later.

```bash
git clone https://github.com/soroban-advisory-watch/soroban-advisory-watch
cd soroban-advisory-watch
cargo test --workspace
```

Tests do not use the network. Rebuilding the fixture contracts also needs `rustup target add wasm32v1-none`; see `fixtures/wasm/README.md`.

## Before you open a pull request

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs the same commands, plus the tests on macOS, Windows and Rust 1.88, and a docs build.

## Pull request rules

- One issue per pull request. Put `Closes #<number>` in the description.
- Keep the change to what the issue asks. Open a new issue for anything else you notice.
- Add or update tests. A bug fix needs a test that fails without the fix.
- Update the docs in `docs/src/` if behaviour or output changes. Update `CHANGELOG.md` under `Unreleased`.
- Do not edit files in `advisories/osv/` by hand. They are copies of upstream records. Our notes go in `advisories/annotations.toml`.
- Do not add a network call to the core crate. Networking belongs in `crates/cli`, behind the `Transport` trait.
- Do not change a result's status based on a heuristic. Heuristics are signals: context, never a verdict.

## Writing style

Docs, messages and output are read by people deciding whether a contract is safe. Write plainly:

- Short sentences. Say what happens, not how good it is.
- Real numbers and versions, not "many" or "recent".
- Never call a contract `vulnerable` or `safe`.

## Commit messages

Imperative mood, under 72 characters for the first line: `Add SARIF output for scan`. Add a body if the reason is not obvious.

## Code of conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
