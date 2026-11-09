//! Report types shared by the CLI's `scan` and `report` commands, with JSON
//! (via serde) and plain-text output.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::advisory::AdvisoryDb;
use crate::matcher::{self, Finding, Status, Target};
use crate::wasm::WasmInfo;

pub const TOOL_NAME: &str = "soroban-advisory-watch";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: TOOL_NAME,
            version: TOOL_VERSION,
        }
    }
}

/// Where a scanned contract came from.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Source {
    File {
        path: String,
    },
    Contract {
        contract_id: String,
        network: String,
        ledger: u32,
    },
}

/// Result for one contract or Wasm file.
#[derive(Debug, Clone, Serialize)]
pub struct TargetReport {
    pub source: Source,
    pub executable: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wasm_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rustc_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u32>,
    pub status: Status,
    pub findings: Vec<Finding>,
}

impl TargetReport {
    pub fn for_wasm(source: Source, info: &WasmInfo, db: &AdvisoryDb) -> Self {
        let target = Target::Wasm(info);
        let findings = matcher::evaluate(target, db);
        Self {
            source,
            executable: "wasm",
            wasm_hash: Some(info.hash.clone()),
            sdk_version: info.sdk_version_raw.clone(),
            rustc_version: info.rustc_version.clone(),
            protocol: info.interface_version.map(|v| v.protocol),
            status: matcher::overall_status(target, &findings),
            findings,
        }
    }

    pub fn for_stellar_asset(source: Source, db: &AdvisoryDb) -> Self {
        let findings = matcher::evaluate(Target::StellarAsset, db);
        Self {
            source,
            executable: "stellar-asset",
            wasm_hash: None,
            sdk_version: None,
            rustc_version: None,
            protocol: None,
            status: Status::NotApplicable,
            findings,
        }
    }
}

/// Output of `scan`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub tool: ToolInfo,
    pub advisories_checked: Vec<String>,
    pub host_advisories_skipped: Vec<String>,
    pub targets: Vec<TargetReport>,
}

impl ScanReport {
    pub fn new(db: &AdvisoryDb, targets: Vec<TargetReport>) -> Self {
        let (host, contract): (Vec<_>, Vec<_>) =
            db.advisories.iter().partition(|a| a.is_host_only());
        Self {
            tool: ToolInfo::default(),
            advisories_checked: contract.iter().map(|a| a.id.clone()).collect(),
            host_advisories_skipped: host.iter().map(|a| a.id.clone()).collect(),
            targets,
        }
    }

    /// The most urgent status across all targets.
    pub fn worst_status(&self) -> Option<Status> {
        self.targets.iter().map(|t| t.status).min()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        for (i, t) in self.targets.iter().enumerate() {
            if i > 0 {
                out.push('\n');
            }
            write_target(&mut out, t);
        }
        if !self.host_advisories_skipped.is_empty() {
            let _ = writeln!(
                out,
                "\nSkipped host-only advisories (not part of contract Wasm): {}",
                self.host_advisories_skipped.join(", ")
            );
        }
        out
    }
}

fn write_target(out: &mut String, t: &TargetReport) {
    match &t.source {
        Source::File { path } => {
            let _ = writeln!(out, "{path}");
        }
        Source::Contract {
            contract_id,
            network,
            ledger,
        } => {
            let _ = writeln!(out, "{contract_id} ({network}, ledger {ledger})");
        }
    }
    if let Some(h) = &t.wasm_hash {
        let _ = writeln!(out, "  wasm hash:   {h}");
    }
    let _ = writeln!(
        out,
        "  sdk version: {}",
        t.sdk_version
            .as_deref()
            .unwrap_or(if t.executable == "wasm" {
                "(not recorded)"
            } else {
                "(stellar asset contract)"
            })
    );
    if let Some(p) = t.protocol {
        let _ = writeln!(out, "  protocol:    {p}");
    }
    let _ = writeln!(out, "  status:      {}", t.status.as_str());
    for f in &t.findings {
        write_finding(out, f);
    }
}

fn write_finding(out: &mut String, f: &Finding) {
    let conf = f
        .confidence
        .map(|c| match c {
            matcher::Confidence::High => " (high confidence)",
            matcher::Confidence::Low => " (low confidence)",
        })
        .unwrap_or("");
    let aliases = if f.aliases.is_empty() {
        String::new()
    } else {
        format!(" / {}", f.aliases.join(", "))
    };
    let _ = writeln!(
        out,
        "\n  [{}{}] {}{}",
        f.status.as_str(),
        conf,
        f.advisory_id,
        aliases
    );
    let _ = writeln!(out, "    {}", f.summary);
    let _ = writeln!(out, "    {}", f.reason);
    if f.status == Status::Possible {
        if let Some(c) = &f.condition {
            let _ = writeln!(out, "    Condition: {}", c.trim());
        }
        for s in &f.signals {
            let ev = if s.evidence.is_empty() {
                String::new()
            } else {
                format!(": {}", s.evidence.join(", "))
            };
            let _ = writeln!(
                out,
                "    Signal: {} = {}{}",
                s.description,
                if s.observed { "yes" } else { "no" },
                ev
            );
        }
        let _ = writeln!(out, "    {}", f.url);
    }
}

// ---------------------------------------------------------------------------
// Network-wide report
// ---------------------------------------------------------------------------

/// Contracts that share one Wasm.
#[derive(Debug, Clone, Serialize)]
pub struct WasmGroup {
    pub wasm_hash: String,
    pub contract_count: usize,
    pub contracts: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    pub status: Status,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WasmGroupError {
    pub wasm_hash: String,
    pub contracts: Vec<String>,
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusCount {
    pub contracts: usize,
    pub wasm: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub contracts: usize,
    pub unique_wasm: usize,
    pub stellar_asset_contracts: usize,
    pub by_status: BTreeMap<&'static str, StatusCount>,
    pub errors: StatusCount,
}

/// Output of `report`.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkReport {
    pub tool: ToolInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory: Option<String>,
    pub advisories_checked: Vec<String>,
    pub summary: Summary,
    pub groups: Vec<WasmGroup>,
    pub errors: Vec<WasmGroupError>,
}

impl NetworkReport {
    pub fn new(
        db: &AdvisoryDb,
        advisory: Option<String>,
        mut groups: Vec<WasmGroup>,
        errors: Vec<WasmGroupError>,
        stellar_asset_contracts: usize,
    ) -> Self {
        groups.sort_by(|a, b| {
            a.status
                .cmp(&b.status)
                .then(b.contract_count.cmp(&a.contract_count))
                .then(a.wasm_hash.cmp(&b.wasm_hash))
        });
        let mut summary = Summary {
            stellar_asset_contracts,
            ..Default::default()
        };
        for g in &groups {
            let c = summary.by_status.entry(g.status.as_str()).or_default();
            c.contracts += g.contract_count;
            c.wasm += 1;
        }
        for e in &errors {
            summary.errors.contracts += e.contracts.len();
            summary.errors.wasm += 1;
        }
        summary.unique_wasm = groups.len() + errors.len();
        summary.contracts = groups.iter().map(|g| g.contract_count).sum::<usize>()
            + summary.errors.contracts
            + stellar_asset_contracts;
        Self {
            tool: ToolInfo::default(),
            advisory,
            advisories_checked: db
                .advisories
                .iter()
                .filter(|a| !a.is_host_only())
                .map(|a| a.id.clone())
                .collect(),
            summary,
            groups,
            errors,
        }
    }

    pub fn worst_status(&self) -> Option<Status> {
        self.groups.iter().map(|g| g.status).min()
    }

    pub fn to_text(&self) -> String {
        let mut out = String::new();
        let s = &self.summary;
        let _ = writeln!(
            out,
            "{} contracts, {} unique Wasm, {} Stellar Asset Contracts",
            s.contracts, s.unique_wasm, s.stellar_asset_contracts
        );
        if let Some(a) = &self.advisory {
            let _ = writeln!(out, "Advisory: {a}");
        }
        for status in [Status::Possible, Status::Unknown, Status::NotMatched] {
            let c = s
                .by_status
                .get(status.as_str())
                .cloned()
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  {:<13} {} contracts in {} Wasm",
                status.as_str(),
                c.contracts,
                c.wasm
            );
        }
        if s.errors.wasm > 0 {
            let _ = writeln!(
                out,
                "  {:<13} {} contracts in {} Wasm (could not fetch or parse)",
                "error", s.errors.contracts, s.errors.wasm
            );
        }
        for g in self.groups.iter().filter(|g| g.status == Status::Possible) {
            let _ = writeln!(
                out,
                "\nWasm {} (sdk {}, {} contracts)",
                g.wasm_hash,
                g.sdk_version.as_deref().unwrap_or("?"),
                g.contract_count
            );
            for f in g.findings.iter().filter(|f| f.status == Status::Possible) {
                let _ = writeln!(out, "  {}: {}", f.advisory_id, f.reason);
            }
            for c in g.contracts.iter().take(10) {
                let _ = writeln!(out, "    {c}");
            }
            if g.contracts.len() > 10 {
                let _ = writeln!(out, "    ... and {} more", g.contracts.len() - 10);
            }
        }
        for e in &self.errors {
            let _ = writeln!(
                out,
                "\nError for Wasm {} ({} contracts): {}",
                e.wasm_hash,
                e.contracts.len(),
                e.error
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{meta_bytes, module};
    use crate::wasm::analyze;

    #[test]
    fn scan_text_mentions_status_and_skipped_host_advisory() {
        let db = AdvisoryDb::bundled().unwrap();
        let info = analyze(&module(Some(&meta_bytes(&[("rssdkver", "25.0.1")])), &[])).unwrap();
        let report = ScanReport::new(
            &db,
            vec![TargetReport::for_wasm(
                Source::File {
                    path: "x.wasm".into(),
                },
                &info,
                &db,
            )],
        );
        let text = report.to_text();
        assert!(text.contains("status:      possible"));
        assert!(text.contains("GHSA-96xm-fv9w-pf3f"));
        assert!(text.contains("Skipped host-only advisories"));
        assert_eq!(report.worst_status(), Some(Status::Possible));
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["targets"][0]["status"], "possible");
        assert_eq!(json["host_advisories_skipped"][0], "GHSA-pm4j-7r4q-ccg8");
    }

    #[test]
    fn network_summary_counts() {
        let db = AdvisoryDb::bundled().unwrap();
        let group = |hash: &str, n: usize, status| WasmGroup {
            wasm_hash: hash.into(),
            contract_count: n,
            contracts: (0..n).map(|i| format!("C{i}")).collect(),
            sdk_version: None,
            status,
            findings: vec![],
        };
        let r = NetworkReport::new(
            &db,
            None,
            vec![
                group("b", 3, Status::NotMatched),
                group("a", 2, Status::Possible),
            ],
            vec![WasmGroupError {
                wasm_hash: "c".into(),
                contracts: vec!["C9".into()],
                error: "archived".into(),
            }],
            4,
        );
        assert_eq!(r.summary.contracts, 10);
        assert_eq!(r.summary.unique_wasm, 3);
        assert_eq!(r.summary.by_status["possible"].contracts, 2);
        assert_eq!(r.groups[0].wasm_hash, "a");
        assert!(r.to_text().contains("could not fetch or parse"));
    }
}
