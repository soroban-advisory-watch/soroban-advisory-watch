# soroban-advisory-watch

[![CI](https://github.com/soroban-advisory-watch/soroban-advisory-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/soroban-advisory-watch/soroban-advisory-watch/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mdBook-blue)](https://soroban-advisory-watch.github.io/soroban-advisory-watch/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org)
[![Drips Stellar Wave](https://img.shields.io/badge/Drips-Stellar%20Wave-6f42c1)](https://www.drips.network/wave/stellar)

Find deployed Soroban contracts that may be affected when a security advisory is published for `soroban-sdk`.

Advisory databases list affected crate versions. They do not list contracts. `soroban-advisory-watch` reads the build metadata that `soroban-sdk` writes into every contract's Wasm, matches it against advisories, and tells you which contracts to look at.

```text
$ advisory-watch scan --wasm fixtures/wasm/sdk-25-0-1.wasm --advisory CVE-2026-24889
fixtures/wasm/sdk-25-0-1.wasm
  wasm hash:   d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0
  sdk version: 25.0.1#941448079eccf95627d2ffea13ba268e305a9077
  protocol:    25
  status:      possible

  [possible (high confidence)] GHSA-96xm-fv9w-pf3f / CVE-2026-24889
    soroban-sdk has overflow in Bytes::slice, Vec::slice, GenRange::gen_range for u64
    Built with soroban-sdk 25.0.1, which is in an affected range; fixed in 25.0.2.
    Condition: Only contracts built with `overflow-checks = false` are affected, ...
```

## Why

Three advisories were published against the Soroban Rust SDK between January and March 2026:

| Advisory | Crate | Fixed in |
|---|---|---|
| [GHSA-96xm-fv9w-pf3f](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-96xm-fv9w-pf3f) / CVE-2026-24889: overflow in `Bytes::slice`, `Vec::slice`, `Prng::gen_range` | `soroban-sdk` | 22.0.9, 23.5.1, 25.0.2 |
| [GHSA-4chv-4c6w-w254](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-4chv-4c6w-w254) / CVE-2026-26267: `#[contractimpl]` calls the inherent function instead of the trait function | `soroban-sdk-macros` | 22.0.10, 23.5.2, 25.1.1 |
| [GHSA-x2hw-px52-wp4m](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-x2hw-px52-wp4m) / CVE-2026-32322: `Fr` equality skips modular reduction | `soroban-sdk` | 22.0.11, 23.5.3, 25.3.0 |

A fixed SDK release does not fix a deployed contract. Someone has to find the contracts built with the old version.

## How it works

1. `soroban-sdk` writes `rssdkver` (its version) and `rsver` (rustc version) into the Wasm `contractmetav0` custom section.
2. The tool reads that section from a local file, or downloads a deployed contract's Wasm over Soroban RPC and checks its hash.
3. It matches the version against OSV advisory records copied from the GitHub Advisory Database.
4. Each advisory gets a status, a reason, the advisory's own conditions, and any related evidence from the Wasm (for example, BLS12-381 host imports for the `Fr` advisory).

| Status | Meaning |
|---|---|
| `possible` | The recorded version is in an affected range. The advisory's other conditions have not been checked. |
| `unknown` | The version needed to decide is not recorded in the Wasm. |
| `not-matched` | The recorded version is outside every affected range. Not a safety guarantee. |
| `not-applicable` | Stellar Asset Contract (built-in host code, no Wasm). |

There is no `vulnerable` and no `safe`. Details: [How it works](https://soroban-advisory-watch.github.io/soroban-advisory-watch/how-it-works.html).

## Quick start

```bash
cargo install --git https://github.com/soroban-advisory-watch/soroban-advisory-watch soroban-advisory-watch --locked
```

```bash
# A local build, failing CI on a match
advisory-watch scan --wasm target/wasm32v1-none/release/my_contract.wasm --fail-on possible

# A deployed contract (mainnet needs your own RPC endpoint)
advisory-watch scan --contract-id CA... --network mainnet --rpc-url https://your-rpc.example

# Every contract in an inventory, grouped by Wasm
advisory-watch report --inventory contracts.csv --wasm-dir ./wasm-cache --advisory GHSA-96xm-fv9w-pf3f

# Print the raw metadata
advisory-watch meta --wasm my_contract.wasm

# What the tool knows about
advisory-watch advisories list
```

Try it without a network using the bundled example:

```bash
advisory-watch report --offline --inventory examples/inventory.jsonl --wasm-dir examples/wasm
```

## What it does not do

- **It does not confirm vulnerabilities.** Each advisory has conditions the Wasm cannot show, such as the `overflow-checks` setting.
- **It only sees `soroban-sdk`.** For `soroban-sdk-macros` it knows a lower bound. Third-party crates such as `soroban-fixed-point-math` show as `unknown`. Run `cargo audit` on your `Cargo.lock` as well.
- **It trusts metadata it cannot verify.** `contractmetav0` can be stripped or edited. Missing metadata gives `unknown`, never `not-matched`.
- **It skips host advisories.** Bugs in `soroban-env-host` are fixed by network upgrades, not contract rebuilds.
- **It cannot list every contract by itself.** Soroban RPC has no "list contracts" call. Network reports take an inventory, for example from Stellar's Hubble dataset ([guide](https://soroban-advisory-watch.github.io/soroban-advisory-watch/guides/network-report.html)).

## Repository layout

| Path | Contents |
|---|---|
| [`crates/core`](crates/core) | `advisory-watch-core`: Wasm metadata parsing, advisory matching, RPC client, inventory and report types. No I/O. |
| [`crates/cli`](crates/cli) | The `advisory-watch` binary. |
| [`advisories`](advisories) | Bundled OSV records (unchanged upstream copies) and this project's annotations. |
| [`fixtures`](fixtures) | Test contracts built with soroban-sdk 25.0.1 and 25.3.0, and their Wasm. |
| [`examples`](examples) | Example inventory, cached Wasm and the Hubble query. |
| [`docs`](docs) | Documentation site source (mdBook). |

## Documentation

Full documentation: **https://soroban-advisory-watch.github.io/soroban-advisory-watch/**

- [Check your own contract in CI](https://soroban-advisory-watch.github.io/soroban-advisory-watch/guides/ci.html)
- [Check a deployed contract](https://soroban-advisory-watch.github.io/soroban-advisory-watch/guides/deployed-contract.html)
- [Build a network-wide report](https://soroban-advisory-watch.github.io/soroban-advisory-watch/guides/network-report.html)
- [Respond to a new advisory](https://soroban-advisory-watch.github.io/soroban-advisory-watch/guides/new-advisory.html)
- [JSON output reference](https://soroban-advisory-watch.github.io/soroban-advisory-watch/reference/output.html)

## Development

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Tests run offline against real contract Wasm and a mock RPC server. See [Development](https://soroban-advisory-watch.github.io/soroban-advisory-watch/development.html).

## Contributing

This project takes part in the [Drips Stellar Wave Program](https://www.drips.network/wave/stellar). Read [CONTRIBUTING.md](CONTRIBUTING.md), pick an open issue, apply through Drips, and wait for assignment before starting work. Issues for newcomers are labelled [`good first issue`](https://github.com/soroban-advisory-watch/soroban-advisory-watch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

Found a security problem in this tool? Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Maintainers

| Maintainer | GitHub |
|---|---|
| cisco_91 | [@ciscokwiz](https://github.com/ciscokwiz) |

Questions and ideas: [GitHub issues](https://github.com/soroban-advisory-watch/soroban-advisory-watch/issues).

## Contributors

<a href="https://github.com/soroban-advisory-watch/soroban-advisory-watch/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=soroban-advisory-watch/soroban-advisory-watch" alt="Contributors" />
</a>

## License

[MIT](LICENSE). Advisory records in `advisories/osv/` come from the [GitHub Advisory Database](https://github.com/github/advisory-database) under [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/).
