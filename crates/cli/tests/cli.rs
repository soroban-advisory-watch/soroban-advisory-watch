//! End-to-end tests for the `advisory-watch` binary, using real contract Wasm
//! from `fixtures/wasm` and a local mock Soroban RPC server.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::{json, Value};
use stellar_xdr::{
    ContractCodeEntry, ContractCodeEntryExt, ContractDataDurability, ContractDataEntry,
    ContractExecutable, ContractId, ExtensionPoint, Hash, LedgerEntryData, LedgerKey, Limits,
    ReadXdr, ScAddress, ScContractInstance, ScVal, WriteXdr,
};

const HASH_25_0_1: &str = "d63d1cb832ae111f3e7370d64ec811e7503c7d6fc37167b8af83bcd363d092b0";
const HASH_25_3_0: &str = "a706467a568fc00bdc234a02ca40e6d67ca94999e29422de930fa2750e72382f";
const HASH_NO_META: &str = "08a671c7767ff0803bf8e9d98c17173ad2063dd6aa28480862bc77acf43ce83f";

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/wasm")
        .join(name)
}

fn contract_id(byte: u8) -> String {
    format!("{}", stellar_strkey::Contract([byte; 32]))
}

fn bin() -> Command {
    let mut cmd = Command::cargo_bin("advisory-watch").unwrap();
    for var in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "ADVISORY_WATCH_RPC_URL",
    ] {
        cmd.env_remove(var);
    }
    cmd
}

fn json_output(cmd: &mut Command) -> Value {
    let out = cmd.output().unwrap();
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON ({e}): {}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn finding<'a>(target: &'a Value, id: &str) -> &'a Value {
    target["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["advisory_id"] == id)
        .unwrap_or_else(|| panic!("no finding for {id}"))
}

#[test]
fn fixture_hashes_match() {
    for (name, hash) in [
        ("sdk-25-0-1.wasm", HASH_25_0_1),
        ("sdk-25-3-0.wasm", HASH_25_3_0),
        ("no-meta.wasm", HASH_NO_META),
    ] {
        let bytes = std::fs::read(fixture(name)).unwrap();
        assert_eq!(advisory_watch_core::wasm::wasm_hash(&bytes), hash, "{name}");
    }
}

#[test]
fn scan_affected_wasm() {
    let v = json_output(
        bin()
            .args(["scan", "--format", "json", "--wasm"])
            .arg(fixture("sdk-25-0-1.wasm")),
    );
    let t = &v["targets"][0];
    assert_eq!(t["status"], "possible");
    assert_eq!(t["wasm_hash"], HASH_25_0_1);
    assert_eq!(t["protocol"], 25);
    assert_eq!(
        t["sdk_version"],
        "25.0.1#941448079eccf95627d2ffea13ba268e305a9077"
    );
    let overflow = finding(t, "GHSA-96xm-fv9w-pf3f");
    assert_eq!(overflow["status"], "possible");
    assert_eq!(overflow["confidence"], "high");
    let fr = finding(t, "GHSA-x2hw-px52-wp4m");
    assert_eq!(fr["signals"][0]["observed"], true);
    assert_eq!(finding(t, "GHSA-4chv-4c6w-w254")["confidence"], "low");
    assert_eq!(v["host_advisories_skipped"][0], "GHSA-pm4j-7r4q-ccg8");
}

#[test]
fn scan_fixed_wasm() {
    let v = json_output(
        bin()
            .args(["scan", "--format", "json", "--wasm"])
            .arg(fixture("sdk-25-3-0.wasm")),
    );
    let t = &v["targets"][0];
    assert_eq!(t["status"], "not-matched");
    assert_eq!(finding(t, "GHSA-x5m4-43jf-hh65")["status"], "unknown");
}

#[test]
fn scan_stripped_wasm_is_unknown() {
    let v = json_output(
        bin()
            .args(["scan", "--format", "json", "--wasm"])
            .arg(fixture("no-meta.wasm")),
    );
    assert_eq!(v["targets"][0]["status"], "unknown");
}

#[test]
fn fail_on_exit_codes() {
    bin()
        .args(["scan", "--fail-on", "possible", "--wasm"])
        .arg(fixture("sdk-25-0-1.wasm"))
        .assert()
        .code(1);
    bin()
        .args(["scan", "--fail-on", "possible", "--wasm"])
        .arg(fixture("sdk-25-3-0.wasm"))
        .assert()
        .code(0);
    bin()
        .args(["scan", "--fail-on", "possible", "--wasm"])
        .arg(fixture("no-meta.wasm"))
        .assert()
        .code(0);
    bin()
        .args(["scan", "--fail-on", "unknown", "--wasm"])
        .arg(fixture("no-meta.wasm"))
        .assert()
        .code(1);
}

#[test]
fn advisory_filter_accepts_cve_id() {
    let v = json_output(
        bin()
            .args([
                "scan",
                "--format",
                "json",
                "--advisory",
                "CVE-2026-24889",
                "--wasm",
            ])
            .arg(fixture("sdk-25-0-1.wasm")),
    );
    let findings = v["targets"][0]["findings"].as_array().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["advisory_id"], "GHSA-96xm-fv9w-pf3f");
}

#[test]
fn host_advisory_filter_is_rejected() {
    bin()
        .args(["scan", "--advisory", "GHSA-pm4j-7r4q-ccg8", "--wasm"])
        .arg(fixture("sdk-25-0-1.wasm"))
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Soroban host"));
}

#[test]
fn extra_osv_file_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let osv = dir.path().join("new.json");
    std::fs::write(
        &osv,
        r#"{"id":"GHSA-test-test-test","summary":"test advisory","affected":[
            {"package":{"ecosystem":"crates.io","name":"soroban-sdk"},
             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"25.3.0"},{"fixed":"25.4.0"}]}]}]}"#,
    )
    .unwrap();
    let v = json_output(
        bin()
            .args([
                "scan",
                "--format",
                "json",
                "--advisory",
                "GHSA-test-test-test",
                "--osv",
            ])
            .arg(&osv)
            .arg("--wasm")
            .arg(fixture("sdk-25-3-0.wasm")),
    );
    assert_eq!(v["targets"][0]["status"], "possible");
}

#[test]
fn meta_prints_entries() {
    bin()
        .args(["meta", "--wasm"])
        .arg(fixture("sdk-25-3-0.wasm"))
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "rssdkver = 25.3.0#dcbea44513feb7734af6b6c4aced2c4a7a2715d0",
        ));
}

#[test]
fn advisories_list_and_show() {
    bin()
        .args(["advisories", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("GHSA-x2hw-px52-wp4m"))
        .stdout(predicate::str::contains("host"));
    bin()
        .args(["advisories", "show", "CVE-2026-32322"])
        .assert()
        .success()
        .stdout(predicate::str::contains(">=25.0.0, <25.3.0"));
}

#[test]
fn mainnet_requires_rpc_url() {
    bin()
        .args([
            "scan",
            "--network",
            "mainnet",
            "--contract-id",
            &contract_id(1),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("--rpc-url"));
}

#[test]
fn bad_wasm_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("bad.wasm");
    std::fs::write(&p, b"nope").unwrap();
    bin()
        .args(["scan", "--wasm"])
        .arg(&p)
        .assert()
        .code(2)
        .stderr(predicate::str::contains("not a valid Wasm module"));
}

#[test]
fn offline_report_groups_by_wasm() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm");
    std::fs::create_dir(&cache).unwrap();
    for (name, hash) in [
        ("sdk-25-0-1.wasm", HASH_25_0_1),
        ("sdk-25-3-0.wasm", HASH_25_3_0),
        ("no-meta.wasm", HASH_NO_META),
    ] {
        std::fs::copy(fixture(name), cache.join(format!("{hash}.wasm"))).unwrap();
    }
    let missing = "ff".repeat(32);
    let inventory = dir.path().join("inventory.jsonl");
    let lines = [
        json!({"contract_id": contract_id(1), "wasm_hash": HASH_25_0_1}),
        json!({"contract_id": contract_id(2), "wasm_hash": HASH_25_0_1}),
        json!({"contract_id": contract_id(3), "wasm_hash": HASH_25_3_0}),
        json!({"contract_id": contract_id(4), "wasm_hash": HASH_NO_META}),
        json!({"contract_id": contract_id(5), "executable": "stellar_asset"}),
        json!({"contract_id": contract_id(6), "wasm_hash": missing}),
    ];
    std::fs::write(
        &inventory,
        lines
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();

    let v = json_output(
        bin()
            .args(["report", "--offline", "--format", "json", "--inventory"])
            .arg(&inventory)
            .arg("--wasm-dir")
            .arg(&cache),
    );
    let s = &v["summary"];
    assert_eq!(s["contracts"], 6);
    assert_eq!(s["unique_wasm"], 4);
    assert_eq!(s["stellar_asset_contracts"], 1);
    assert_eq!(s["by_status"]["possible"]["contracts"], 2);
    assert_eq!(s["by_status"]["possible"]["wasm"], 1);
    assert_eq!(s["by_status"]["not-matched"]["contracts"], 1);
    assert_eq!(s["by_status"]["unknown"]["contracts"], 1);
    assert_eq!(s["errors"]["contracts"], 1);
    assert_eq!(v["groups"][0]["wasm_hash"], HASH_25_0_1);
    assert_eq!(v["groups"][0]["contract_count"], 2);
    assert!(v["errors"][0]["error"]
        .as_str()
        .unwrap()
        .contains("--offline"));

    // Filtered to one advisory, with --fail-on.
    bin()
        .args([
            "report",
            "--offline",
            "--advisory",
            "GHSA-96xm-fv9w-pf3f",
            "--fail-on",
            "possible",
            "--inventory",
        ])
        .arg(&inventory)
        .arg("--wasm-dir")
        .arg(&cache)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("GHSA-96xm-fv9w-pf3f"));
}

#[test]
fn csv_inventory_with_hubble_contract_data_xdr() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("wasm");
    std::fs::create_dir(&cache).unwrap();
    std::fs::copy(
        fixture("sdk-25-0-1.wasm"),
        cache.join(format!("{HASH_25_0_1}.wasm")),
    )
    .unwrap();
    let entry = contract_data_entry([1; 32], hash_bytes(HASH_25_0_1));
    let csv = format!(
        "contract_id,contract_data_xdr\n{},{}\n",
        contract_id(1),
        entry.to_xdr_base64(Limits::none()).unwrap()
    );
    let inventory = dir.path().join("hubble.csv");
    std::fs::write(&inventory, csv).unwrap();
    let v = json_output(
        bin()
            .args(["report", "--offline", "--format", "json", "--inventory"])
            .arg(&inventory)
            .arg("--wasm-dir")
            .arg(&cache),
    );
    assert_eq!(v["summary"]["by_status"]["possible"]["contracts"], 1);
}

// ---------------------------------------------------------------------------
// Mock RPC server
// ---------------------------------------------------------------------------

fn hash_bytes(hex_str: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

fn contract_data_entry(contract: [u8; 32], wasm: [u8; 32]) -> ContractDataEntry {
    ContractDataEntry {
        ext: ExtensionPoint::V0,
        contract: ScAddress::Contract(ContractId(Hash(contract))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
        val: ScVal::ContractInstance(ScContractInstance {
            executable: ContractExecutable::Wasm(Hash(wasm)),
            storage: None,
        }),
    }
}

/// Serve `requests` JSON-RPC calls, answering like a testnet RPC node that
/// knows one contract (byte 7) running the 25.0.1 fixture and one Stellar
/// Asset Contract (byte 8).
fn spawn_rpc(requests: usize) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let wasm = std::fs::read(fixture("sdk-25-0-1.wasm")).unwrap();
    thread::spawn(move || {
        for _ in 0..requests {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0u8; len];
            reader.read_exact(&mut body).unwrap();
            let req: Value = serde_json::from_slice(&body).unwrap();
            let result = match req["method"].as_str().unwrap() {
                "getNetwork" => {
                    json!({"passphrase": "Test SDF Network ; September 2015", "protocolVersion": 25})
                }
                "getLedgerEntries" => {
                    let key = LedgerKey::from_xdr_base64(
                        req["params"]["keys"][0].as_str().unwrap(),
                        Limits::none(),
                    )
                    .unwrap();
                    let entry = match key {
                        LedgerKey::ContractData(k) => match k.contract {
                            ScAddress::Contract(ContractId(Hash(id))) if id == [7; 32] => {
                                Some(LedgerEntryData::ContractData(contract_data_entry(
                                    id,
                                    hash_bytes(HASH_25_0_1),
                                )))
                            }
                            ScAddress::Contract(ContractId(Hash(id))) if id == [8; 32] => {
                                let mut e = contract_data_entry(id, [0; 32]);
                                e.val = ScVal::ContractInstance(ScContractInstance {
                                    executable: ContractExecutable::StellarAsset,
                                    storage: None,
                                });
                                Some(LedgerEntryData::ContractData(e))
                            }
                            _ => None,
                        },
                        LedgerKey::ContractCode(k) if k.hash.0 == hash_bytes(HASH_25_0_1) => {
                            Some(LedgerEntryData::ContractCode(ContractCodeEntry {
                                ext: ContractCodeEntryExt::V0,
                                hash: k.hash,
                                code: wasm.clone().try_into().unwrap(),
                            }))
                        }
                        _ => None,
                    };
                    let entries: Vec<Value> = entry
                        .into_iter()
                        .map(|e| json!({"key": "", "xdr": e.to_xdr_base64(Limits::none()).unwrap(), "lastModifiedLedgerSeq": 100}))
                        .collect();
                    json!({"entries": entries, "latestLedger": 123456})
                }
                other => panic!("unexpected method {other}"),
            };
            let body = json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
        }
    });
    format!("http://{addr}")
}

#[test]
fn scan_deployed_contract_over_rpc() {
    // getNetwork + instance + code for contract 7, then instance for SAC 8.
    let url = spawn_rpc(4);
    let v = json_output(bin().args([
        "scan",
        "--format",
        "json",
        "--network",
        "testnet",
        "--rpc-url",
        &url,
        "--contract-id",
        &contract_id(7),
        "--contract-id",
        &contract_id(8),
    ]));
    let wasm_target = &v["targets"][0];
    assert_eq!(wasm_target["source"]["kind"], "contract");
    assert_eq!(wasm_target["source"]["ledger"], 123456);
    assert_eq!(wasm_target["source"]["network"], "testnet");
    assert_eq!(wasm_target["wasm_hash"], HASH_25_0_1);
    assert_eq!(wasm_target["status"], "possible");
    let sac = &v["targets"][1];
    assert_eq!(sac["executable"], "stellar-asset");
    assert_eq!(sac["status"], "not-applicable");
}

#[test]
fn wrong_network_is_rejected() {
    let url = spawn_rpc(1);
    bin()
        .args([
            "scan",
            "--network",
            "mainnet",
            "--rpc-url",
            &url,
            "--contract-id",
            &contract_id(7),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("passphrase"));
}

#[test]
fn report_downloads_and_caches_wasm() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache");
    let inventory = dir.path().join("inv.jsonl");
    std::fs::write(
        &inventory,
        json!({"contract_id": contract_id(7), "wasm_hash": HASH_25_0_1}).to_string(),
    )
    .unwrap();
    // getNetwork + one code download.
    let url = spawn_rpc(2);
    let v = json_output(
        bin()
            .args([
                "report",
                "--format",
                "json",
                "--network",
                "testnet",
                "--rpc-url",
                &url,
                "--inventory",
            ])
            .arg(&inventory)
            .arg("--wasm-dir")
            .arg(&cache),
    );
    assert_eq!(v["summary"]["by_status"]["possible"]["contracts"], 1);
    assert!(cache.join(format!("{HASH_25_0_1}.wasm")).is_file());
}
