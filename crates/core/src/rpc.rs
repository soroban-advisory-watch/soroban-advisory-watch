//! Minimal Soroban RPC client: just enough to resolve a contract id to its
//! Wasm and to download Wasm by hash.
//!
//! The HTTP layer is abstracted behind [`Transport`] so this crate does no
//! networking itself and tests can replay recorded responses.

use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};
use stellar_xdr::{
    ContractDataDurability, ContractExecutable, ContractId, Hash, LedgerEntryData, LedgerKey,
    LedgerKeyContractCode, LedgerKeyContractData, Limits, ReadXdr, ScAddress, ScVal, WriteXdr,
};

pub const PASSPHRASE_MAINNET: &str = "Public Global Stellar Network ; September 2015";
pub const PASSPHRASE_TESTNET: &str = "Test SDF Network ; September 2015";
pub const PASSPHRASE_FUTURENET: &str = "Test SDF Future Network ; October 2022";

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("HTTP request failed: {0}")]
    Transport(String),
    #[error("RPC returned invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("unexpected RPC response: {0}")]
    Unexpected(String),
    #[error("invalid contract id `{0}`: expected a C... strkey")]
    ContractId(String),
    #[error("invalid Wasm hash `{0}`: expected 64 hex characters")]
    WasmHash(String),
    #[error("XDR error: {0}")]
    Xdr(#[from] stellar_xdr::Error),
    #[error("contract instance for {0} not found (wrong network, never deployed, or archived)")]
    InstanceNotFound(String),
    #[error("Wasm {0} not found (archived, or wrong network)")]
    CodeNotFound(String),
    #[error("RPC network passphrase is `{actual}`, expected `{expected}`")]
    WrongNetwork { expected: String, actual: String },
}

/// Sends one JSON-RPC request body and returns the response body.
pub trait Transport {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String>;
}

/// What a contract instance runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Executable {
    Wasm {
        hash: String,
    },
    StellarAsset,
    /// An executable type this tool does not handle yet (for example
    /// `ExternalRef`, added in stellar-xdr 30).
    Unsupported {
        name: String,
    },
}

/// A contract instance read from the ledger.
#[derive(Debug, Clone, Serialize)]
pub struct ContractInstance {
    pub contract_id: String,
    pub executable: Executable,
    /// Latest ledger the RPC server had when it answered.
    pub latest_ledger: u32,
}

pub struct RpcClient<T: Transport> {
    url: String,
    transport: T,
    next_id: std::cell::Cell<u64>,
}

impl<T: Transport> RpcClient<T> {
    pub fn new(url: impl Into<String>, transport: T) -> Self {
        Self {
            url: url.into(),
            transport,
            next_id: std::cell::Cell::new(1),
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        let body = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let text = self
            .transport
            .post_json(&self.url, &body.to_string())
            .map_err(RpcError::Transport)?;
        let mut resp: Value = serde_json::from_str(&text)?;
        if let Some(err) = resp.get("error") {
            return Err(RpcError::Rpc {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            });
        }
        resp.get_mut("result")
            .map(Value::take)
            .ok_or_else(|| RpcError::Unexpected("missing `result`".into()))
    }

    /// The network passphrase reported by the server.
    pub fn network_passphrase(&self) -> Result<String, RpcError> {
        let result = self.call("getNetwork", Value::Null)?;
        result
            .get("passphrase")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| RpcError::Unexpected("getNetwork: missing `passphrase`".into()))
    }

    /// Fail unless the server is on the network with `expected` passphrase.
    pub fn check_network(&self, expected: &str) -> Result<(), RpcError> {
        let actual = self.network_passphrase()?;
        if actual != expected {
            return Err(RpcError::WrongNetwork {
                expected: expected.to_string(),
                actual,
            });
        }
        Ok(())
    }

    fn get_ledger_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<(u32, Vec<LedgerEntryData>), RpcError> {
        let keys_b64 = keys
            .iter()
            .map(|k| k.to_xdr_base64(Limits::none()))
            .collect::<Result<Vec<_>, _>>()?;
        let result = self.call("getLedgerEntries", json!({ "keys": keys_b64 }))?;
        let latest = result
            .get("latestLedger")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                RpcError::Unexpected("getLedgerEntries: missing `latestLedger`".into())
            })? as u32;
        let mut out = Vec::new();
        if let Some(entries) = result.get("entries").and_then(Value::as_array) {
            for entry in entries {
                let xdr = entry
                    .get("xdr")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RpcError::Unexpected("entry without `xdr`".into()))?;
                out.push(LedgerEntryData::from_xdr_base64(xdr, Limits::none())?);
            }
        }
        Ok((latest, out))
    }

    /// Read a contract's instance entry to find what it executes.
    pub fn contract_instance(&self, contract_id: &str) -> Result<ContractInstance, RpcError> {
        let id = parse_contract_id(contract_id)?;
        let key = LedgerKey::ContractData(LedgerKeyContractData {
            contract: ScAddress::Contract(ContractId(Hash(id))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
        });
        let (latest_ledger, entries) = self.get_ledger_entries(&[key])?;
        for entry in entries {
            if let LedgerEntryData::ContractData(data) = entry {
                if let ScVal::ContractInstance(instance) = data.val {
                    return Ok(ContractInstance {
                        contract_id: contract_id.to_string(),
                        executable: executable_from_xdr(&instance.executable),
                        latest_ledger,
                    });
                }
            }
        }
        Err(RpcError::InstanceNotFound(contract_id.to_string()))
    }

    /// Download the Wasm stored under `hash` (hex).
    pub fn wasm_by_hash(&self, hash_hex: &str) -> Result<Vec<u8>, RpcError> {
        let hash = parse_wasm_hash(hash_hex)?;
        let key = LedgerKey::ContractCode(LedgerKeyContractCode { hash: Hash(hash) });
        let (_, entries) = self.get_ledger_entries(&[key])?;
        for entry in entries {
            if let LedgerEntryData::ContractCode(code) = entry {
                return Ok(code.code.to_vec());
            }
        }
        Err(RpcError::CodeNotFound(hash_hex.to_string()))
    }
}

pub fn executable_from_xdr(exec: &ContractExecutable) -> Executable {
    match exec {
        ContractExecutable::Wasm(h) => Executable::Wasm {
            hash: hex::encode(h.0),
        },
        ContractExecutable::StellarAsset => Executable::StellarAsset,
        ContractExecutable::ExternalRef(_) => Executable::Unsupported {
            name: "external-ref".into(),
        },
    }
}

pub fn parse_contract_id(s: &str) -> Result<[u8; 32], RpcError> {
    stellar_strkey::Contract::from_string(s.trim())
        .map(|c| c.0)
        .map_err(|_| RpcError::ContractId(s.to_string()))
}

pub fn parse_wasm_hash(s: &str) -> Result<[u8; 32], RpcError> {
    let bytes = hex::decode(s.trim()).map_err(|_| RpcError::WasmHash(s.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| RpcError::WasmHash(s.to_string()))
}

/// Decode a base64 `ContractDataEntry` (the `contract_data_xdr` column in
/// Stellar's Hubble dataset) and return the executable if the entry is a
/// contract instance.
pub fn executable_from_contract_data_xdr(b64: &str) -> Result<Option<Executable>, RpcError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| RpcError::Unexpected(format!("invalid base64: {e}")))?;
    let entry = stellar_xdr::ContractDataEntry::from_xdr(bytes, Limits::none())?;
    Ok(match entry.val {
        ScVal::ContractInstance(instance) => Some(executable_from_xdr(&instance.executable)),
        _ => None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use stellar_xdr::{
        ContractCodeEntry, ContractCodeEntryExt, ContractDataEntry, ExtensionPoint,
        ScContractInstance,
    };

    /// Replays canned responses and records requests.
    pub struct Replay {
        pub responses: RefCell<VecDeque<String>>,
        pub requests: RefCell<Vec<String>>,
    }

    impl Replay {
        pub fn new(responses: Vec<String>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                requests: RefCell::new(Vec::new()),
            }
        }
    }

    impl Transport for &Replay {
        fn post_json(&self, _url: &str, body: &str) -> Result<String, String> {
            self.requests.borrow_mut().push(body.to_string());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| "no more canned responses".to_string())
        }
    }

    pub fn contract() -> String {
        format!("{}", stellar_strkey::Contract([5; 32]))
    }

    pub fn instance_entry(contract: [u8; 32], exec: ContractExecutable) -> LedgerEntryData {
        LedgerEntryData::ContractData(ContractDataEntry {
            ext: ExtensionPoint::V0,
            contract: ScAddress::Contract(ContractId(Hash(contract))),
            key: ScVal::LedgerKeyContractInstance,
            durability: ContractDataDurability::Persistent,
            val: ScVal::ContractInstance(ScContractInstance {
                executable: exec,
                storage: None,
            }),
        })
    }

    pub fn entries_response(entries: &[LedgerEntryData], latest: u32) -> String {
        let entries: Vec<Value> = entries
            .iter()
            .map(|e| json!({"key": "", "xdr": e.to_xdr_base64(Limits::none()).unwrap(), "lastModifiedLedgerSeq": 1}))
            .collect();
        json!({"jsonrpc":"2.0","id":1,"result":{"entries":entries,"latestLedger":latest}})
            .to_string()
    }

    #[test]
    fn resolves_wasm_instance() {
        let id = parse_contract_id(&contract()).unwrap();
        let replay = Replay::new(vec![entries_response(
            &[instance_entry(id, ContractExecutable::Wasm(Hash([7; 32])))],
            1234,
        )]);
        let client = RpcClient::new("http://rpc", &replay);
        let inst = client.contract_instance(&contract()).unwrap();
        assert_eq!(inst.latest_ledger, 1234);
        assert_eq!(
            inst.executable,
            Executable::Wasm {
                hash: hex::encode([7; 32])
            }
        );
        let req: Value = serde_json::from_str(&replay.requests.borrow()[0]).unwrap();
        assert_eq!(req["method"], "getLedgerEntries");
        let key =
            LedgerKey::from_xdr_base64(req["params"]["keys"][0].as_str().unwrap(), Limits::none())
                .unwrap();
        assert!(matches!(key, LedgerKey::ContractData(_)));
    }

    #[test]
    fn resolves_stellar_asset_instance() {
        let id = parse_contract_id(&contract()).unwrap();
        let replay = Replay::new(vec![entries_response(
            &[instance_entry(id, ContractExecutable::StellarAsset)],
            9,
        )]);
        let client = RpcClient::new("http://rpc", &replay);
        assert_eq!(
            client.contract_instance(&contract()).unwrap().executable,
            Executable::StellarAsset
        );
    }

    #[test]
    fn missing_instance_is_an_error() {
        let replay = Replay::new(vec![entries_response(&[], 9)]);
        let client = RpcClient::new("http://rpc", &replay);
        assert!(matches!(
            client.contract_instance(&contract()),
            Err(RpcError::InstanceNotFound(_))
        ));
    }

    #[test]
    fn downloads_wasm() {
        let code = LedgerEntryData::ContractCode(ContractCodeEntry {
            ext: ContractCodeEntryExt::V0,
            hash: Hash([1; 32]),
            code: vec![0, 97, 115, 109].try_into().unwrap(),
        });
        let replay = Replay::new(vec![entries_response(&[code], 5)]);
        let client = RpcClient::new("http://rpc", &replay);
        assert_eq!(
            client.wasm_by_hash(&hex::encode([1; 32])).unwrap(),
            vec![0, 97, 115, 109]
        );
    }

    #[test]
    fn rpc_error_is_reported() {
        let replay = Replay::new(vec![
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"bad key"}}"#.into(),
        ]);
        let client = RpcClient::new("http://rpc", &replay);
        match client.contract_instance(&contract()) {
            Err(RpcError::Rpc { code, message }) => {
                assert_eq!(code, -32602);
                assert_eq!(message, "bad key");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn checks_network_passphrase() {
        let replay = Replay::new(vec![
            json!({"jsonrpc":"2.0","id":1,"result":{"passphrase":PASSPHRASE_TESTNET,"protocolVersion":25}}).to_string(),
        ]);
        let client = RpcClient::new("http://rpc", &replay);
        assert!(matches!(
            client.check_network(PASSPHRASE_MAINNET),
            Err(RpcError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn rejects_bad_ids() {
        assert!(parse_contract_id("GABC").is_err());
        assert!(parse_wasm_hash("abcd").is_err());
        assert!(parse_wasm_hash(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn decodes_hubble_contract_data_xdr() {
        let id = parse_contract_id(&contract()).unwrap();
        let LedgerEntryData::ContractData(entry) =
            instance_entry(id, ContractExecutable::Wasm(Hash([3; 32])))
        else {
            unreachable!()
        };
        let b64 = entry.to_xdr_base64(Limits::none()).unwrap();
        assert_eq!(
            executable_from_contract_data_xdr(&b64).unwrap(),
            Some(Executable::Wasm {
                hash: hex::encode([3; 32])
            })
        );
    }
}
