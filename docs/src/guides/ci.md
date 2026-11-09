# Check your own contract in CI

Use this if you build Soroban contracts and want CI to stop a build that uses an affected `soroban-sdk` version.

## Run it on the built Wasm

```bash
stellar contract build
advisory-watch scan --wasm target/wasm32v1-none/release/my_contract.wasm --fail-on possible
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No result at or above the `--fail-on` level. |
| 1 | At least one result at or above the `--fail-on` level. |
| 2 | The tool could not run (bad file, bad arguments, RPC failure). |

`--fail-on unknown` also fails when the SDK version is missing, which is useful if your build process is supposed to keep metadata.

## GitHub Actions example

```yaml
- name: Install advisory-watch
  run: cargo install --git https://github.com/soroban-advisory-watch/soroban-advisory-watch soroban-advisory-watch --locked
- name: Check SDK advisories
  run: advisory-watch scan --wasm target/wasm32v1-none/release/my_contract.wasm --fail-on possible
```

## Also run `cargo audit`

In CI you have the source and `Cargo.lock`, which list every crate in the build. [`cargo audit`](https://crates.io/crates/cargo-audit) and Dependabot read those and cover crates this tool cannot see, such as `soroban-fixed-point-math`. Run both:

- `cargo audit` checks the dependency tree.
- `advisory-watch scan --wasm` checks the file you are about to deploy, which catches a build made from a different lock file or machine.

## What the output looks like

```text
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

The fix is to update `soroban-sdk` to a fixed release, rebuild, and scan again.
