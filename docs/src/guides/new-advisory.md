# Respond to a new advisory

The binary bundles the advisories that existed when it was released. When a new one is published, you do not need to wait for a release.

## 1. Get the OSV record

GitHub publishes every reviewed advisory as OSV JSON in [github/advisory-database](https://github.com/github/advisory-database), under `advisories/github-reviewed/<year>/<month>/<GHSA-id>/<GHSA-id>.json`. OSV.dev serves the same records at `https://api.osv.dev/v1/vulns/<id>`.

## 2. Pass it with `--osv`

```bash
advisory-watch scan --osv GHSA-xxxx-xxxx-xxxx.json --advisory GHSA-xxxx-xxxx-xxxx --wasm contract.wasm
advisory-watch report --osv GHSA-xxxx-xxxx-xxxx.json --advisory GHSA-xxxx-xxxx-xxxx --inventory contracts.csv --wasm-dir ./wasm-cache
```

A file can hold one record or a JSON array. A record whose id is already bundled replaces the bundled copy, so you can also use `--osv` to apply a corrected range.

The tool uses the crate name in the record to decide how to match it (see [How it works](../how-it-works.md#3-match-advisories)). A new `soroban-sdk` advisory works immediately. An advisory for a crate the Wasm does not record will show as `unknown`.

## 3. Get it bundled

Open a pull request that adds the file to `advisories/osv/`, registers it in `crates/core/src/advisory.rs`, and adds a condition to `advisories/annotations.toml`. See [Advisory data](../reference/advisories.md).
