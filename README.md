# soroban-advisory-watch

Find out which deployed Soroban contracts may be affected when a vulnerability is published in `soroban-sdk`.

## The problem

When an advisory is published for `soroban-sdk`, advisory databases list the affected crate versions. They do not list the contracts on mainnet that were built with those versions. Auditors, explorers, wallets and protocol teams have no easy way to answer: "Which live contracts should we look at?"

Recent examples:

| Advisory | Crate | Issue | Fixed in |
|---|---|---|---|
| [GHSA-96xm-fv9w-pf3f](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-96xm-fv9w-pf3f) / CVE-2026-24889 | `soroban-sdk` | Overflow in `Bytes::slice`, `Vec::slice`, `Prng::gen_range` (u64). Only matters when `overflow-checks` is off. | 22.0.9, 23.5.1, 25.0.2 |
| [GHSA-x2hw-px52-wp4m](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-x2hw-px52-wp4m) / CVE-2026-32322 | `soroban-sdk` | `Fr` (BN254, BLS12-381) equality compares unreduced values. Only matters for contracts that compare user-supplied `Fr` values. | 22.0.11, 23.5.3, 25.3.0 |
| [GHSA-4chv-4c6w-w254](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-4chv-4c6w-w254) / CVE-2026-26267 | `soroban-sdk-macros` | `#[contractimpl]` calls the inherent function instead of the trait function when names collide. | 22.0.10, 23.5.2, 25.1.1 |

Always check the linked GitHub advisory for the authoritative version ranges.

## How it works

1. Contracts built with the Rust SDK embed `rsver` (rustc version) and `rssdkver` (`soroban-sdk` version and git revision) in the Wasm `contractmetav0` custom section. You can see it with `stellar contract info meta`.
2. The tool reads that section from a local Wasm file, or fetches a deployed contract's Wasm through Soroban RPC.
3. It matches the `soroban-sdk` version against advisories from the GitHub Advisory Database / OSV.
4. It reports each match with the advisory, the reason, the Wasm hash, the ledger it was read at, and a confidence level.

Many contracts share the same Wasm (factories, clones). The tool scans each unique Wasm hash once and then lists every contract instance that uses it.

## Planned usage

```
# One deployed contract
advisory-watch scan --contract-id C... --network mainnet

# A local build
advisory-watch scan --wasm target/wasm32v1-none/release/my_contract.wasm

# Network-wide report for one advisory (needs a list of all deployed Wasm; see "Data sources")
advisory-watch report --advisory GHSA-96xm-fv9w-pf3f --format json
```

For your own source code in CI, run `cargo audit` or Dependabot on `Cargo.lock` as well. They see every crate in the build. This tool sees only what the Wasm metadata records.

## Results

| Status | Meaning |
|---|---|
| `possible` | The recorded `soroban-sdk` version is in an affected range. The advisory's other conditions have not been ruled out. |
| `not-matched` | The recorded version is outside every affected range. This is not a safety guarantee. |
| `unknown` | No `rssdkver` (metadata stripped, or a non-Rust SDK). |
| `not-applicable` | The contract is a Stellar Asset Contract, which runs built-in host code, not Wasm. |

Where the Wasm gives a signal related to an advisory's condition (for example, whether it imports the BLS12-381 or BN254 host functions), the report includes that signal as context. Each such check is documented with its limits. None of them confirms or rules out a vulnerability.

## What it does not do

- **A version match is not a confirmed vulnerability.** Some advisories only matter under certain build flags or when specific functions are used. Results say `possible`, never `vulnerable`.
- **It sees only the `soroban-sdk` version.** Metadata does not record `soroban-sdk-macros` (which `soroban-sdk` depends on with a caret range, not an exact version) or third-party crates such as `soroban-fixed-point-math`. Advisories for those crates are reported with lower confidence, or not at all.
- **Metadata is self-reported.** Anyone can strip or edit `contractmetav0`. Treat it as a hint, not proof.
- **Host advisories are out of scope.** Bugs in `soroban-env-host` affect validators, not contract builds, and are fixed by a network upgrade.
- It does not execute contracts or replace an audit.

## Data sources

- GitHub Advisory Database / OSV for crate advisories
- Soroban RPC (`getLedgerEntries`) to read a contract instance and its Wasm
- For network-wide reports: a list of every deployed Wasm hash and the contracts that use it. Soroban RPC cannot list all contracts. Candidate sources are Stellar's Hubble dataset on BigQuery (`contract_code` / `contract_data` tables) or our own ledger ingestion. Choosing between them is an open issue.

Contracts can be upgraded, so a report is only valid at the ledger it was taken at.

## Status

Early. No code yet. See the open issues for the roadmap. Good first issues are labelled `good first issue`.

## Contributing

We take part in the Drips Stellar Wave Program. Read `CONTRIBUTING.md`, apply to an issue through Drips, and wait for assignment before starting work.

## License

MIT. See [LICENSE](LICENSE).
