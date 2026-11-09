//! Inventory files: the list of contracts a network-wide report covers.
//!
//! Soroban RPC cannot list every contract, so the list comes from outside:
//! an export from Stellar's Hubble dataset, or any other indexer. Two formats
//! are accepted, chosen by file extension:
//!
//! * JSON Lines (`.jsonl`, `.ndjson`, `.json`): one object per line.
//! * CSV (`.csv`): a header row, then one contract per row. Fields must not
//!   contain commas or quotes (contract ids, hex and base64 never do).
//!
//! Each row needs `contract_id` and one of:
//!
//! * `wasm_hash`: hex SHA-256 of the Wasm.
//! * `executable`: `stellar_asset` for a Stellar Asset Contract.
//! * `contract_data_xdr`: base64 `ContractDataEntry` for the instance, as in
//!   Hubble's `contract_data` table.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::rpc::{executable_from_contract_data_xdr, parse_wasm_hash, Executable};

#[derive(Debug, thiserror::Error)]
#[error("inventory line {line}: {message}")]
pub struct InventoryError {
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Default, Deserialize)]
struct Row {
    contract_id: Option<String>,
    wasm_hash: Option<String>,
    executable: Option<String>,
    contract_data_xdr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InventoryEntry {
    pub contract_id: String,
    pub executable: Executable,
}

/// Parse an inventory. `csv` selects the CSV reader; otherwise JSON Lines.
/// Duplicate contract ids keep the last row, so a newer export appended to an
/// older one wins.
pub fn parse(text: &str, csv: bool) -> Result<Vec<InventoryEntry>, InventoryError> {
    let rows = if csv {
        parse_csv(text)?
    } else {
        parse_jsonl(text)?
    };
    let mut by_id: BTreeMap<String, InventoryEntry> = BTreeMap::new();
    for (line, row) in rows {
        let err = |message: String| InventoryError { line, message };
        let contract_id = row
            .contract_id
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| err("missing `contract_id`".into()))?
            .trim()
            .to_string();
        crate::rpc::parse_contract_id(&contract_id).map_err(|e| err(e.to_string()))?;

        let executable = if let Some(hash) = row.wasm_hash.filter(|s| !s.trim().is_empty()) {
            parse_wasm_hash(&hash).map_err(|e| err(e.to_string()))?;
            Executable::Wasm {
                hash: hash.trim().to_ascii_lowercase(),
            }
        } else if let Some(exec) = row.executable.filter(|s| !s.trim().is_empty()) {
            match exec.trim().to_ascii_lowercase().as_str() {
                "stellar_asset" | "stellar-asset" | "sac" => Executable::StellarAsset,
                other => {
                    return Err(err(format!(
                        "unknown executable `{other}` (use `wasm_hash` for Wasm contracts)"
                    )))
                }
            }
        } else if let Some(xdr) = row.contract_data_xdr.filter(|s| !s.trim().is_empty()) {
            executable_from_contract_data_xdr(&xdr)
                .map_err(|e| err(e.to_string()))?
                .ok_or_else(|| err("`contract_data_xdr` is not a contract instance entry".into()))?
        } else {
            return Err(err(
                "need one of `wasm_hash`, `executable` or `contract_data_xdr`".into(),
            ));
        };
        by_id.insert(
            contract_id.clone(),
            InventoryEntry {
                contract_id,
                executable,
            },
        );
    }
    Ok(by_id.into_values().collect())
}

fn parse_jsonl(text: &str) -> Result<Vec<(usize, Row)>, InventoryError> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line_no = i + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let row: Row = serde_json::from_str(trimmed).map_err(|e| InventoryError {
            line: line_no,
            message: format!("invalid JSON: {e}"),
        })?;
        out.push((line_no, row));
    }
    Ok(out)
}

fn parse_csv(text: &str) -> Result<Vec<(usize, Row)>, InventoryError> {
    let mut lines = text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty());
    let Some((_, header)) = lines.next() else {
        return Ok(Vec::new());
    };
    let columns: Vec<String> = header
        .split(',')
        .map(|c| c.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
        .collect();
    if !columns.iter().any(|c| c == "contract_id") {
        return Err(InventoryError {
            line: 1,
            message: "CSV header has no `contract_id` column".into(),
        });
    }
    let mut out = Vec::new();
    for (i, line) in lines {
        let line_no = i + 1;
        if line.contains('"') {
            return Err(InventoryError {
                line: line_no,
                message: "quoted CSV fields are not supported".into(),
            });
        }
        let mut row = Row::default();
        for (col, value) in columns.iter().zip(line.split(',')) {
            let value = Some(value.trim().to_string());
            match col.as_str() {
                "contract_id" => row.contract_id = value,
                "wasm_hash" => row.wasm_hash = value,
                "executable" => row.executable = value,
                "contract_data_xdr" => row.contract_data_xdr = value,
                _ => {}
            }
        }
        out.push((line_no, row));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::tests::{contract, instance_entry};
    use stellar_xdr::{ContractExecutable, Hash, LedgerEntryData, Limits, WriteXdr};

    fn other_contract() -> String {
        format!("{}", stellar_strkey::Contract([9; 32]))
    }

    #[test]
    fn parses_jsonl_with_all_row_kinds() {
        let id = crate::rpc::parse_contract_id(&contract()).unwrap();
        let LedgerEntryData::ContractData(entry) =
            instance_entry(id, ContractExecutable::Wasm(Hash([4; 32])))
        else {
            unreachable!()
        };
        let xdr = entry.to_xdr_base64(Limits::none()).unwrap();
        let text = format!(
            "# comment\n{{\"contract_id\":\"{c}\",\"contract_data_xdr\":\"{xdr}\"}}\n\n{{\"contract_id\":\"{o}\",\"executable\":\"stellar_asset\"}}\n",
            c = contract(),
            o = other_contract()
        );
        let entries = parse(&text, false).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.executable
            == Executable::Wasm {
                hash: hex::encode([4; 32])
            }));
        assert!(entries
            .iter()
            .any(|e| e.executable == Executable::StellarAsset));
    }

    #[test]
    fn parses_csv() {
        let text = format!(
            "contract_id,wasm_hash\n{},{}\n",
            contract(),
            "AB".repeat(32)
        );
        let entries = parse(&text, true).unwrap();
        assert_eq!(
            entries[0].executable,
            Executable::Wasm {
                hash: "ab".repeat(32)
            }
        );
    }

    #[test]
    fn last_duplicate_wins() {
        let text = format!(
            "{{\"contract_id\":\"{c}\",\"wasm_hash\":\"{a}\"}}\n{{\"contract_id\":\"{c}\",\"wasm_hash\":\"{b}\"}}\n",
            c = contract(),
            a = "aa".repeat(32),
            b = "bb".repeat(32)
        );
        let entries = parse(&text, false).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].executable,
            Executable::Wasm {
                hash: "bb".repeat(32)
            }
        );
    }

    #[test]
    fn reports_line_numbers() {
        let text = format!("{{\"contract_id\":\"{}\"}}\n", contract());
        let err = parse(&text, false).unwrap_err();
        assert_eq!(err.line, 1);
        let err = parse("\n{\"contract_id\":\"GBAD\",\"wasm_hash\":\"00\"}", false).unwrap_err();
        assert_eq!(err.line, 2);
    }

    #[test]
    fn csv_requires_contract_id_column() {
        assert!(parse("id,wasm_hash\nx,y\n", true).is_err());
    }
}
