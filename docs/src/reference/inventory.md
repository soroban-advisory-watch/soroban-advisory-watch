# Inventory format

`advisory-watch report --inventory FILE` reads a list of contracts. The format is chosen by extension: `.csv` is CSV, anything else is JSON Lines.

Every row needs `contract_id` (a `C...` strkey) and one of:

| Field | Meaning |
|---|---|
| `wasm_hash` | Hex SHA-256 of the contract's Wasm (64 characters, any case). |
| `executable` | `stellar_asset` for a Stellar Asset Contract. |
| `contract_data_xdr` | Base64 `ContractDataEntry` of the contract's instance entry, as in Hubble's `contract_data` table. The tool decodes the executable from it. |

If a row has more than one, `wasm_hash` wins, then `executable`.

## JSON Lines

One object per line. Blank lines and lines starting with `#` are skipped. Unknown fields are ignored.

```text
{"contract_id": "CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526", "wasm_hash": "d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0"}
{"contract_id": "CACQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQLC2U", "executable": "stellar_asset"}
```

## CSV

A header row naming the columns, then one row per contract. Quoted fields are not supported; contract ids, hex and base64 never need quotes. Other columns are ignored.

```text
contract_id,contract_data_xdr
CAAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQCAIBAEAQC526,AAAAAAAAAAE...
```

## Duplicates and errors

- If a contract id appears more than once, the last row wins.
- Any invalid row stops the run with its line number.
- A `contract_data_xdr` value that is not an instance entry is an error.
- Instances with an executable type this version does not handle (for example `ExternalRef`, which appears in stellar-xdr 30) are listed under `errors` in the report.
