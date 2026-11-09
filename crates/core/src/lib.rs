//! Core library for `soroban-advisory-watch`.
//!
//! Reads the `contractmetav0` custom section that `soroban-sdk` writes into
//! every contract it builds, and matches the recorded SDK version against
//! security advisories. A match means a contract *may* be affected; it is
//! never proof of a vulnerability.
//!
//! ```no_run
//! use advisory_watch_core::{advisory::AdvisoryDb, matcher, wasm};
//!
//! let bytes = std::fs::read("contract.wasm").unwrap();
//! let info = wasm::analyze(&bytes).unwrap();
//! let db = AdvisoryDb::bundled().unwrap();
//! for finding in matcher::evaluate(matcher::Target::Wasm(&info), &db) {
//!     println!("{} {}", finding.advisory_id, finding.status.as_str());
//! }
//! ```

#![forbid(unsafe_code)]

pub mod advisory;
pub mod inventory;
pub mod matcher;
pub mod report;
pub mod rpc;
pub mod signals;
pub mod wasm;

#[cfg(test)]
pub(crate) mod test_support {
    use stellar_xdr::{Limits, ScMetaEntry, ScMetaV0, WriteXdr};
    use wasm_encoder::{
        CustomSection, EntityType, FunctionSection, ImportSection, Module, TypeSection,
    };

    /// XDR stream of `ScMetaEntry` values, as found in `contractmetav0`.
    pub fn meta_bytes(entries: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in entries {
            let e = ScMetaEntry::ScMetaV0(ScMetaV0 {
                key: (*k).try_into().unwrap(),
                val: (*v).try_into().unwrap(),
            });
            out.extend(e.to_xdr(Limits::none()).unwrap());
        }
        out
    }

    /// A minimal Wasm module with optional `contractmetav0` data and the
    /// given function imports.
    pub fn module(meta: Option<&[u8]>, imports: &[(&str, &str)]) -> Vec<u8> {
        let mut m = Module::new();
        let mut types = TypeSection::new();
        types.ty().function([], []);
        m.section(&types);
        if !imports.is_empty() {
            let mut imp = ImportSection::new();
            for (module, name) in imports {
                imp.import(module, name, EntityType::Function(0));
            }
            m.section(&imp);
        }
        m.section(&FunctionSection::new());
        if let Some(data) = meta {
            m.section(&CustomSection {
                name: "contractmetav0".into(),
                data: data.into(),
            });
        }
        m.finish()
    }
}
