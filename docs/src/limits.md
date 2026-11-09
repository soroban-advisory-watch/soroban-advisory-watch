# Limits

Read this before publishing or acting on results.

## A version match is not a vulnerability

Each bundled advisory has extra conditions:

- GHSA-96xm-fv9w-pf3f only matters with `overflow-checks = false`. Stellar's templates set it to `true`, and the Wasm does not record the flag.
- GHSA-x2hw-px52-wp4m only matters if the contract compares caller-supplied `Fr` values with `==`.
- GHSA-4chv-4c6w-w254 only matters if a trait impl and an inherent impl share a function name.

So most `possible` results will turn out not to be affected. The tool cannot tell which.

## Metadata can be missing or wrong

- `contractmetav0` is optional. Tools such as `wasm-opt` or custom strip steps can remove it.
- Contracts built with non-Rust SDKs have no `rssdkver`.
- Anyone can write any value into the section. It is a build record, not a signature.

Missing metadata gives `unknown`, never `not-matched`.

## Only `soroban-sdk` is recorded

The Wasm records the `soroban-sdk` version. For `soroban-sdk-macros` and `soroban-spec` it gives only a lower bound (see [How it works](how-it-works.md)). For every other crate it gives nothing. A contract that depends on an affected third-party crate shows that advisory as `unknown`.

The lower-bound rule was checked against crates.io for `soroban-sdk` 22.0.0, 22.0.8, 23.0.0, 23.5.0, 25.0.0, 25.3.0, 26.0.0 and 29.0.1. All of them require the macros crate with `^<own version>`. If a future release pins it differently, the rule needs updating.

## Results are point-in-time

Upgradeable contracts can change their Wasm. Scan results record the Wasm hash and, for RPC scans, the ledger. Re-run before relying on old results.

## Archived contracts

Soroban archives ledger entries whose rent runs out. Soroban RPC does not return archived instance or code entries, so the tool reports them as not found. Hubble may still list them.

## Network reports depend on the inventory

The report is only as complete as the inventory. The Hubble query in this repository has not been run by the maintainers yet.
