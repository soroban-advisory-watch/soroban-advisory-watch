# Check a deployed contract

Use this during an audit, an incident, or before integrating a contract.

## Scan by contract id

```bash
export ADVISORY_WATCH_RPC_URL=https://your-mainnet-rpc.example
advisory-watch scan --contract-id CA... --network mainnet
```

On testnet the default endpoint is used:

```bash
advisory-watch scan --contract-id CA... --network testnet
```

What happens:

1. `getNetwork` checks the endpoint's passphrase matches `--network`.
2. `getLedgerEntries` reads the contract's instance entry. It names either a Wasm hash or the Stellar Asset Contract.
3. For Wasm, `getLedgerEntries` downloads the contract code. Its SHA-256 must equal the hash from step 2.
4. The Wasm is matched as in [How it works](../how-it-works.md).

The report includes the ledger number the RPC server returned. Contracts can be upgraded, so a result is only true for that ledger.

## See the raw metadata

```bash
advisory-watch meta --contract-id CA... --network mainnet
```

```text
wasm hash: d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0
size:      389 bytes
protocol:  25
contractmetav0:
  rsver = 1.97.0
  rssdkver = 25.0.1#941448079eccf95627d2ffea13ba268e305a9077
host imports: 1
```

## Reading a `possible` result

For each `possible` finding, check the advisory's condition against the contract source:

- **GHSA-96xm-fv9w-pf3f**: was the release profile built with `overflow-checks = false`? Does the contract pass caller-controlled bounds to `Bytes::slice`, `Vec::slice` or `Prng::gen_range`?
- **GHSA-x2hw-px52-wp4m**: does the contract accept `Fr` values from callers and compare them with `==`?
- **GHSA-4chv-4c6w-w254**: does the contract apply `#[contractimpl]` to a trait impl and also define an inherent function with the same name? Which `soroban-sdk-macros` version is in its `Cargo.lock`?

If the source is not public, the result tells you to ask the team, not that the contract is broken.

## Errors you may see

| Error | Cause |
|---|---|
| `contract instance ... not found` | Wrong network, never deployed, or the instance entry is archived. |
| `RPC network passphrase is ...` | `--rpc-url` points at a different network than `--network`. |
| `mainnet has no default RPC endpoint` | Pass `--rpc-url` or set `ADVISORY_WATCH_RPC_URL`. |
