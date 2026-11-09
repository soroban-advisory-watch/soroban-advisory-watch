# Build a network-wide report

Use this to answer "which live contracts may be affected by this advisory?" across a whole network.

Soroban RPC cannot list every contract, so a network report has two steps:

1. Get an **inventory**: every contract id and what it runs.
2. Run `advisory-watch report` on it.

## Step 1: get an inventory from Hubble

Stellar publishes ledger data to BigQuery as the Hubble dataset. The `contract_data` table has one row per change to a contract data entry. Instance entries carry the contract's executable in `contract_data_xdr` (a base64 `ContractDataEntry`). Hubble does not store Wasm bytes, so the tool downloads them separately.

The query in [`examples/hubble-contract-instances.sql`](https://github.com/soroban-advisory-watch/soroban-advisory-watch/blob/main/examples/hubble-contract-instances.sql) keeps the latest instance row per contract:

```sql
SELECT contract_id, contract_data_xdr
FROM (
  SELECT contract_id, contract_data_xdr, deleted,
         ROW_NUMBER() OVER (PARTITION BY contract_id ORDER BY ledger_sequence DESC) AS rn
  FROM `crypto-stellar.crypto_stellar.contract_data`
  WHERE contract_key_type = 'ScValTypeScvLedgerKeyContractInstance'
)
WHERE rn = 1 AND deleted = FALSE;
```

> **Status:** the column names are taken from the Hubble data dictionary and stellar-etl's source code. The maintainers have not run this query against BigQuery yet. Check the table path and the query cost first. Verifying it is an open issue.

Export the result as CSV or newline-delimited JSON. Both work as an inventory without changes.

You can also build an inventory from your own indexer. See [Inventory format](../reference/inventory.md).

## Step 2: run the report

```bash
export ADVISORY_WATCH_RPC_URL=https://your-mainnet-rpc.example
advisory-watch report \
  --inventory contracts.csv \
  --wasm-dir ./wasm-cache \
  --advisory GHSA-96xm-fv9w-pf3f \
  --format json > report.json
```

- Contracts are grouped by Wasm hash, so each unique Wasm is downloaded and checked once.
- `--wasm-dir` caches downloads as `<hash>.wasm`. A second run reads from the cache. Cached files are re-hashed before use.
- `--offline` uses only the cache and reports missing Wasm as errors.
- Leave out `--advisory` to check every bundled advisory.

## Example output

From `examples/inventory.jsonl` with the fixture Wasm in `examples/wasm/`:

```bash
advisory-watch report --offline --inventory examples/inventory.jsonl --wasm-dir examples/wasm
```

```text
5 contracts, 3 unique Wasm, 1 Stellar Asset Contracts
  possible      2 contracts in 1 Wasm
  unknown       1 contracts in 1 Wasm
  not-matched   1 contracts in 1 Wasm

Wasm d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0 (sdk 25.0.1#9414..., 2 contracts)
  GHSA-96xm-fv9w-pf3f: Built with soroban-sdk 25.0.1, which is in an affected range; fixed in 25.0.2.
  ...
```

The JSON form has the full contract list per Wasm. See [Results and JSON output](../reference/output.md).

## Publishing results

A `possible` result is not a vulnerability. If you publish a list of contracts, label them as "built with an affected SDK version" and link the advisory's conditions. Give contract teams a way to tell you a result does not apply.
