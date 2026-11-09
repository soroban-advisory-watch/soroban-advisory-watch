# Command line

Generated from `advisory-watch --help`. Run any command with `--help` for the same text.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success, and no result reached the `--fail-on` level. |
| 1 | A result reached the `--fail-on` level. |
| 2 | Error: bad arguments, unreadable file, invalid Wasm, RPC failure, wrong network. |

## Environment

| Variable | Same as |
|---|---|
| `ADVISORY_WATCH_RPC_URL` | `--rpc-url` |

## advisory-watch

```text
Find Soroban contracts that may be affected by soroban-sdk security advisories.

Results are `possible`, `unknown`, `not-matched` or `not-applicable`. A `possible` result is a version match, not a confirmed vulnerability.

Usage: advisory-watch <COMMAND>

Commands:
  scan        Check Wasm files or deployed contracts against advisories
  report      Check every contract in an inventory file (network-wide report)
  meta        Print the Soroban metadata of a Wasm file or deployed contract
  advisories  List or show the advisories this tool knows about
  help        Print this message or the help of the given subcommand(s)

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## advisory-watch scan

```text
Check Wasm files or deployed contracts against advisories

Usage: advisory-watch scan [OPTIONS]

Options:
      --wasm <PATH>
          Local Wasm file. Repeatable

      --contract-id <ID>
          Deployed contract id (C...). Repeatable

      --network <NETWORK>
          Network the contract lives on
          
          [default: mainnet]
          [possible values: mainnet, testnet, futurenet]

      --rpc-url <URL>
          Soroban RPC endpoint. Required for mainnet, which has no default
          
          [env: ADVISORY_WATCH_RPC_URL=]

      --osv <FILE>
          Extra OSV JSON file (one record or an array). Records replace bundled ones with the same id. Repeatable

      --advisory <ID>
          Only check this advisory (GHSA or CVE id)

      --format <FORMAT>
          Output format
          
          [default: text]
          [possible values: text, json]

      --fail-on <FAIL_ON>
          Exit with code 1 if any result is at least this serious

          Possible values:
          - possible: Fail if any result is `possible`
          - unknown:  Fail if any result is `possible` or `unknown`
          - never:    Never fail because of results
          
          [default: never]

  -h, --help
          Print help (see a summary with '-h')
```

## advisory-watch report

```text
Check every contract in an inventory file (network-wide report)

Usage: advisory-watch report [OPTIONS] --inventory <FILE>

Options:
      --inventory <FILE>
          Inventory file (.jsonl or .csv). Format: https://soroban-advisory-watch.github.io/soroban-advisory-watch/reference/inventory.html

      --wasm-dir <DIR>
          Directory of `<wasm-hash>.wasm` files. Read before calling RPC; downloaded Wasm is saved here

      --offline
          Do not call RPC. Wasm missing from --wasm-dir is reported as an error

      --network <NETWORK>
          Network the contract lives on
          
          [default: mainnet]
          [possible values: mainnet, testnet, futurenet]

      --rpc-url <URL>
          Soroban RPC endpoint. Required for mainnet, which has no default
          
          [env: ADVISORY_WATCH_RPC_URL=]

      --osv <FILE>
          Extra OSV JSON file (one record or an array). Records replace bundled ones with the same id. Repeatable

      --advisory <ID>
          Only check this advisory (GHSA or CVE id)

      --format <FORMAT>
          Output format
          
          [default: text]
          [possible values: text, json]

      --fail-on <FAIL_ON>
          Exit with code 1 if any result is at least this serious

          Possible values:
          - possible: Fail if any result is `possible`
          - unknown:  Fail if any result is `possible` or `unknown`
          - never:    Never fail because of results
          
          [default: never]

  -h, --help
          Print help (see a summary with '-h')
```

## advisory-watch meta

```text
Print the Soroban metadata of a Wasm file or deployed contract

Usage: advisory-watch meta [OPTIONS]

Options:
      --wasm <PATH>        Local Wasm file
      --contract-id <ID>   Deployed contract id (C...)
      --network <NETWORK>  Network the contract lives on [default: mainnet] [possible values: mainnet, testnet, futurenet]
      --rpc-url <URL>      Soroban RPC endpoint. Required for mainnet, which has no default [env: ADVISORY_WATCH_RPC_URL=]
      --format <FORMAT>    Output format [default: text] [possible values: text, json]
  -h, --help               Print help
```

## advisory-watch advisories list

```text
List advisories

Usage: advisory-watch advisories list [OPTIONS]

Options:
      --osv <FILE>       
      --format <FORMAT>  [default: text] [possible values: text, json]
  -h, --help             Print help
```

## advisory-watch advisories show

```text
Show one advisory

Usage: advisory-watch advisories show [OPTIONS] <ID>

Arguments:
  <ID>  GHSA or CVE id

Options:
      --osv <FILE>       
      --format <FORMAT>  [default: text] [possible values: text, json]
  -h, --help             Print help
```

