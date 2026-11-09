# Results and JSON output

## Statuses

| Status | Meaning | Contract-level when |
|---|---|---|
| `possible` | The recorded version is in an affected range. Other conditions not checked. | Any recorded-version finding is `possible`. |
| `unknown` | The version needed to decide is not recorded. | No `rssdkver`, or it is not semver, or only unrecorded crates are being checked. |
| `not-matched` | The recorded version is outside every affected range. Not a safety guarantee. | All recorded-version findings are `not-matched`. |
| `not-applicable` | Stellar Asset Contract. | The contract runs built-in host code. |

## Confidence

Only `possible` findings have a confidence:

- `high`: the affected crate is `soroban-sdk`, whose exact version is recorded.
- `low`: the affected crate is `soroban-sdk-macros` or `soroban-spec`. Only a lower bound on its version is known.

## `scan --format json`

Top level:

| Field | Type | Meaning |
|---|---|---|
| `tool` | object | `name` and `version` of the tool. |
| `advisories_checked` | string[] | Contract-level advisory ids that were evaluated. |
| `host_advisories_skipped` | string[] | Host-only advisory ids that were skipped. |
| `targets` | object[] | One per `--wasm` or `--contract-id`. |

Each target:

| Field | Type | Meaning |
|---|---|---|
| `source` | object | `{"kind":"file","path":...}` or `{"kind":"contract","contract_id":...,"network":...,"ledger":...}` |
| `executable` | string | `wasm` or `stellar-asset` |
| `wasm_hash` | string? | Hex SHA-256 of the Wasm. |
| `sdk_version` | string? | Raw `rssdkver` value. |
| `rustc_version` | string? | Raw `rsver` value. |
| `protocol` | number? | Interface version from `contractenvmetav0`. |
| `status` | string | Contract-level status. |
| `findings` | object[] | One per advisory, most urgent first. |

Each finding:

| Field | Type | Meaning |
|---|---|---|
| `advisory_id` | string | GHSA id. |
| `aliases` | string[] | CVE ids and other aliases. |
| `summary` | string | Advisory title. |
| `severity` | string? | GitHub severity: `low`, `moderate`, `high`, `critical`. |
| `url` | string | Advisory page. |
| `crates` | string[] | Affected crates. |
| `status` | string | Status for this advisory. |
| `confidence` | string? | `high` or `low`, only for `possible`. |
| `version_recorded` | bool | False for crates the Wasm never records. |
| `reason` | string | Why this status was chosen. |
| `condition` | string? | What else must be true for the contract to be affected. |
| `signals` | object[]? | Related facts from the Wasm: `id`, `description`, `observed`, `evidence`, `limits`. |

Example (fixture built with soroban-sdk 25.0.1, filtered to one advisory):

```json
{
  "tool": {
    "name": "soroban-advisory-watch",
    "version": "0.1.0"
  },
  "advisories_checked": [
    "GHSA-x2hw-px52-wp4m"
  ],
  "host_advisories_skipped": [],
  "targets": [
    {
      "source": {
        "kind": "file",
        "path": "fixtures/wasm/sdk-25-0-1.wasm"
      },
      "executable": "wasm",
      "wasm_hash": "d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0",
      "sdk_version": "25.0.1#941448079eccf95627d2ffea13ba268e305a9077",
      "rustc_version": "1.97.0",
      "protocol": 25,
      "status": "possible",
      "findings": [
        {
          "advisory_id": "GHSA-x2hw-px52-wp4m",
          "aliases": [
            "CVE-2026-32322"
          ],
          "summary": "rs-soroban-sdk: `Fr` scalar field equality comparison bypasses modular reduction",
          "severity": "moderate",
          "url": "https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-x2hw-px52-wp4m",
          "crates": [
            "soroban-sdk"
          ],
          "status": "possible",
          "confidence": "high",
          "version_recorded": true,
          "reason": "Built with soroban-sdk 25.0.1, which is in an affected range; fixed in 25.3.0.",
          "condition": "Only contracts that accept `Fr` values (BN254 or BLS12-381 scalar field) from callers and compare them with `==`, `!=` or `assert_eq!` without first going through host-side arithmetic are affected.",
          "signals": [
            {
              "id": "imports-pairing-curve-host-functions",
              "description": "Wasm imports BLS12-381 or BN254 host functions",
              "observed": true,
              "evidence": [
                "c.h (bls12_381_fr_add)"
              ],
              "limits": "Shows the contract does pairing-curve work on the host. A contract can still build and compare `Fr` values without importing any of these functions, so `observed: false` does not rule the advisory out."
            }
          ]
        }
      ]
    }
  ]
}
```

## `report --format json`

| Field | Type | Meaning |
|---|---|---|
| `tool` | object | As above. |
| `advisory` | string? | The `--advisory` filter, if given. |
| `advisories_checked` | string[] | As above. |
| `summary.contracts` | number | Contracts in the inventory. |
| `summary.unique_wasm` | number | Distinct Wasm hashes. |
| `summary.stellar_asset_contracts` | number | Stellar Asset Contracts. |
| `summary.by_status` | object | For each status: `{"contracts": n, "wasm": n}`. |
| `summary.errors` | object | `{"contracts": n, "wasm": n}` that could not be fetched or parsed. |
| `groups` | object[] | One per Wasm hash: `wasm_hash`, `contract_count`, `contracts`, `sdk_version`, `status`, `findings`. Sorted most urgent first, then by contract count. |
| `errors` | object[] | `wasm_hash`, `contracts`, `error`. |

The JSON field names are stable within a minor version. A change to them is listed in the changelog.
