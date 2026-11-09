# Rust library

The CLI is a thin layer over the `advisory-watch-core` crate. Use the crate directly to build the same checks into an explorer, indexer or bot.

```toml
[dependencies]
advisory-watch-core = { git = "https://github.com/soroban-advisory-watch/soroban-advisory-watch" }
```

## Scan bytes you already have

```rust
use advisory_watch_core::{advisory::AdvisoryDb, matcher, wasm};

let bytes = std::fs::read("contract.wasm")?;
let info = wasm::analyze(&bytes)?;
let db = AdvisoryDb::bundled()?;
let target = matcher::Target::Wasm(&info);
let findings = matcher::evaluate(target, &db);
println!("overall: {}", matcher::overall_status(target, &findings).as_str());
for f in &findings {
    println!("{} {} {}", f.advisory_id, f.status.as_str(), f.reason);
}
```

## Modules

| Module | Purpose |
|---|---|
| `wasm` | `analyze(&[u8]) -> WasmInfo`: metadata, interface version, imports, hash. |
| `advisory` | `AdvisoryDb`: bundled OSV records, `add_osv_file_contents` for more. `Relation` decides how a crate is matched. |
| `matcher` | `evaluate`, `overall_status`, `Status`, `Confidence`, `Finding`. |
| `signals` | Signal definitions and the BLS12-381/BN254 host function table. |
| `rpc` | `RpcClient<T: Transport>`: `check_network`, `contract_instance`, `wasm_by_hash`. Bring your own HTTP client by implementing `Transport`. |
| `inventory` | Parse JSON Lines or CSV inventories. |
| `report` | `ScanReport`, `NetworkReport` and their text rendering. |

The core crate does no networking and no file I/O, except reading advisory files compiled into it.

API docs: `cargo doc -p advisory-watch-core --open`.
