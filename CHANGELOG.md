# Changelog

All notable changes to this project are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-09

First release.

### Added

- `advisory-watch scan` for local Wasm files (`--wasm`) and deployed contracts (`--contract-id`) over Soroban RPC.
- `advisory-watch report` for inventories in JSON Lines or CSV, including Hubble `contract_data_xdr` rows. Contracts are grouped by Wasm hash, and Wasm is cached in `--wasm-dir`.
- `advisory-watch meta` to print `contractmetav0` entries, protocol version and import count.
- `advisory-watch advisories list|show`.
- Bundled advisories: GHSA-96xm-fv9w-pf3f, GHSA-x2hw-px52-wp4m, GHSA-4chv-4c6w-w254, GHSA-x5m4-43jf-hh65 and GHSA-pm4j-7r4q-ccg8 (host, skipped).
- `--osv` to load extra or newer OSV records.
- Lower-bound matching for `soroban-sdk-macros` and `soroban-spec`.
- Signal `imports-pairing-curve-host-functions` for the `Fr` advisory.
- Text and JSON output, `--fail-on possible|unknown|never` exit codes.
- Network passphrase check before RPC use, and SHA-256 check of downloaded Wasm.
- `advisory-watch-core` library crate.
- Documentation site (mdBook).

[Unreleased]: https://github.com/soroban-advisory-watch/soroban-advisory-watch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/soroban-advisory-watch/soroban-advisory-watch/releases/tag/v0.1.0
