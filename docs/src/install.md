# Install

## From source (any platform with Rust 1.88 or later)

```bash
cargo install --git https://github.com/soroban-advisory-watch/soroban-advisory-watch soroban-advisory-watch --locked
```

This installs the `advisory-watch` binary into `~/.cargo/bin`.

## Prebuilt binaries

Tagged releases attach binaries for Linux (x86_64), macOS (Apple silicon and Intel) and Windows (x86_64), with a `SHA256SUMS` file. Download from the [releases page](https://github.com/soroban-advisory-watch/soroban-advisory-watch/releases), check the checksum, and put `advisory-watch` on your `PATH`.

## Check it works

```bash
advisory-watch advisories list
```

```text
GHSA-4chv-4c6w-w254  CVE-2026-26267   high      contract soroban-sdk-macros
GHSA-96xm-fv9w-pf3f  CVE-2026-24889   moderate  contract soroban-sdk
GHSA-pm4j-7r4q-ccg8  -                low       host     soroban-env-host
GHSA-x2hw-px52-wp4m  CVE-2026-32322   moderate  contract soroban-sdk
GHSA-x5m4-43jf-hh65  CVE-2026-24783   high      contract soroban-fixed-point-math
```

## RPC endpoints

Scanning deployed contracts needs a Soroban RPC endpoint.

| Network | Default |
|---|---|
| testnet | `https://soroban-testnet.stellar.org` |
| futurenet | `https://rpc-futurenet.stellar.org` |
| mainnet | none: SDF does not run a public mainnet endpoint |

For mainnet, pick a provider from the [Stellar RPC providers list](https://developers.stellar.org/docs/data/apis/rpc/providers) and pass `--rpc-url` or set `ADVISORY_WATCH_RPC_URL`.
