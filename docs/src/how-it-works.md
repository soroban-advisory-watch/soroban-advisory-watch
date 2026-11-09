# How it works

## 1. Read the Wasm

When `soroban-sdk` builds a contract, it writes key/value pairs into a Wasm custom section named `contractmetav0`. Two keys matter here:

| Key | Value | Example |
|---|---|---|
| `rssdkver` | `soroban-sdk` crate version, `#`, git revision | `25.0.1#941448079eccf95627d2ffea13ba268e305a9077` |
| `rsver` | rustc version | `1.97.0` |

The tool also reads:

- `contractenvmetav0`, which holds the protocol (interface) version the contract was built for, for example `25`.
- The import section, which lists the host functions the contract calls.
- The SHA-256 of the whole file. This is the Wasm hash the ledger uses to store contract code, and the key the tool uses to group contracts.

You can see the same metadata with the Stellar CLI: `stellar contract info meta --wasm contract.wasm`.

## 2. Get the Wasm

| Input | How the Wasm is found |
|---|---|
| `--wasm file.wasm` | Read from disk. |
| `--contract-id C...` | Soroban RPC `getLedgerEntries` for the contract's instance entry, which names a Wasm hash, then `getLedgerEntries` for that contract code entry. The downloaded bytes are hashed and must match. |
| `report --inventory` | The inventory lists contract ids and Wasm hashes. Each unique hash is read from `--wasm-dir` or downloaded once over RPC. |

Before any RPC call, the tool asks the server for its network passphrase (`getNetwork`) and stops if it does not match `--network`. This prevents a testnet endpoint from producing a "mainnet" report.

## 3. Match advisories

Advisories are stored in the [OSV format](https://ossf.github.io/osv-schema/), copied unchanged from the GitHub Advisory Database. Each affected crate is put into one of four groups, according to what the Wasm can tell us about it:

| Group | Crates | What the Wasm tells us | Possible result |
|---|---|---|---|
| Direct | `soroban-sdk` | The exact version (`rssdkver`). | `possible` (high confidence) or `not-matched` |
| SDK caret | `soroban-sdk-macros`, `soroban-spec` | A lower bound. Every `soroban-sdk` release from 22.0.0 to 29.0.1 requires these crates as `^<its own version>`, so the compiled-in version is at least the SDK version and in the same major. | `possible` (low confidence) or `not-matched` |
| Host | `soroban-env-host` | Nothing. This code runs in validators, not in the contract, and is fixed by a network upgrade. | Skipped |
| Not recorded | everything else, e.g. `soroban-fixed-point-math` | Nothing. | `unknown` |

### Worked example: the macros advisory

GHSA-4chv-4c6w-w254 affects `soroban-sdk-macros` `>=25.0.0 <25.1.1`.

- A contract built with `soroban-sdk 25.0.1` could have any macros version from 25.0.1 up to (not including) 26.0.0. Part of that span (25.0.1 to 25.1.0) is affected, so the result is `possible`, low confidence.
- A contract built with `soroban-sdk 25.1.1` has macros 25.1.1 or later. None of those are affected, so the result is `not-matched`.

## 4. Decide the overall status

A contract's overall status is the most urgent status among advisories whose crate version the Wasm records (Direct and SDK caret). Findings for crates the Wasm never records are still listed, as `unknown`, but they do not decide the overall status. Otherwise every contract would be `unknown` because of a third-party crate it may not even use.

If the Wasm has no `rssdkver`, every finding is `unknown` and so is the contract.

## 5. Add signals

Some advisories only matter if the contract uses a specific feature. Where the Wasm shows something related, the finding includes a *signal*:

| Signal | Used for | What it checks |
|---|---|---|
| `imports-pairing-curve-host-functions` | GHSA-x2hw-px52-wp4m (`Fr` equality) | Whether the Wasm imports any BLS12-381 or BN254 host function (30 functions in module `c`, from `soroban-env-common/env.json`). |

Signals never change a status. A contract can create and compare `Fr` values without calling any BLS12-381 host function, so a missing import does not rule the advisory out.
