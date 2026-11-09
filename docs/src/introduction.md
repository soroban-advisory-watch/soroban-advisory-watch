# Introduction

`soroban-advisory-watch` answers one question: **when a security advisory is published for `soroban-sdk`, which deployed contracts should someone look at?**

Advisory databases list affected crate versions. They do not list contracts. A Soroban contract is a Wasm file on the ledger, and nothing in the advisory tells you which Wasm files were built with the affected versions. This tool closes that gap by reading the build metadata that `soroban-sdk` writes into every contract.

## Why this matters now

Between January and March 2026, three advisories were published against the Soroban Rust SDK and its macros crate:

| Advisory | Crate | Severity (GitHub) | Affected | Fixed in |
|---|---|---|---|---|
| [GHSA-96xm-fv9w-pf3f](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-96xm-fv9w-pf3f) (CVE-2026-24889) | `soroban-sdk` | moderate | `<22.0.9`, `>=23.0.0 <23.5.1`, `>=25.0.0 <25.0.2` | 22.0.9, 23.5.1, 25.0.2 |
| [GHSA-4chv-4c6w-w254](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-4chv-4c6w-w254) (CVE-2026-26267) | `soroban-sdk-macros` | high | `<22.0.10`, `>=23.0.0 <23.5.2`, `>=25.0.0 <25.1.1` | 22.0.10, 23.5.2, 25.1.1 |
| [GHSA-x2hw-px52-wp4m](https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-x2hw-px52-wp4m) (CVE-2026-32322) | `soroban-sdk` | moderate | `<22.0.11`, `>=23.0.0 <23.5.3`, `>=25.0.0 <25.3.0` | 22.0.11, 23.5.3, 25.3.0 |

A fixed SDK release does not fix a deployed contract. The contract has to be rebuilt and, if it is upgradeable, upgraded. If it is not upgradeable, users need to know so they can decide whether to keep using it.

## Who it is for

- **Contract teams** checking their own builds in CI before deploying.
- **Auditors and security teams** checking a specific contract during a review or incident.
- **Explorers, wallets and indexers** that want to flag contracts built with affected versions across the whole network.

## What a result means

Every result is one of four statuses:

- `possible`: the recorded SDK version is in an affected range. The advisory's other conditions have not been checked.
- `unknown`: the version needed to decide is not in the Wasm.
- `not-matched`: the recorded version is outside every affected range.
- `not-applicable`: the contract is a Stellar Asset Contract, which runs built-in host code.

There is no `vulnerable` and no `safe`. A version match is a reason to look, not a finding. Read [How it works](how-it-works.md) and [Limits](limits.md) before acting on a result.
