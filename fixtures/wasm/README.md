# Wasm fixtures

Real contract builds used by the tests. Do not deploy them.

| File | Built from | soroban-sdk | soroban-sdk-macros | Notes |
|---|---|---|---|---|
| `sdk-25-0-1.wasm` | `fixtures/contracts/sdk-25-0-1` | 25.0.1 | 25.0.1 | In the affected ranges of GHSA-96xm-fv9w-pf3f, GHSA-x2hw-px52-wp4m and GHSA-4chv-4c6w-w254. Imports `c.h` (`bls12_381_fr_add`). |
| `sdk-25-3-0.wasm` | `fixtures/contracts/sdk-25-3-0` | 25.3.0 | 25.3.0 | Outside every bundled affected range. |
| `no-meta.wasm` | `sdk-25-3-0.wasm` with the `contractmetav0` section removed | - | - | Simulates stripped metadata. |

Rebuild with rustc 1.97.0 and the `wasm32v1-none` target:

```bash
cd fixtures/contracts/sdk-25-0-1 && cargo build --target wasm32v1-none --release
```

The lock files pin `soroban-sdk-macros` to the same version as `soroban-sdk`.
A rebuild with a different rustc changes the `rsver` value and the Wasm hash,
so update the hashes in `crates/cli/tests/cli.rs` if you rebuild.
