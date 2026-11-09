//! Signals: facts read from a Wasm module that relate to an advisory's
//! conditions. A signal is context for a human reviewer. It never changes a
//! result's status, because none of these checks can prove or rule out a
//! vulnerability on its own.

use serde::Serialize;

use crate::wasm::WasmInfo;

/// Result of checking one signal against one module.
#[derive(Debug, Clone, Serialize)]
pub struct SignalResult {
    pub id: String,
    pub description: String,
    pub observed: bool,
    /// What was found, for example the matching imports.
    pub evidence: Vec<String>,
    /// What the signal can and cannot tell you.
    pub limits: String,
}

/// Soroban host functions for BLS12-381 and BN254 operations, as
/// `(module, export, name)`. Taken from
/// `soroban-env-common/env.json` in `stellar/rs-soroban-env` (main branch,
/// November 2026). Every entry in module `c` whose name starts with
/// `bls12_381_` or `bn254_`.
pub const PAIRING_CURVE_HOST_FUNCTIONS: &[(&str, &str, &str)] = &[
    ("c", "4", "bls12_381_check_g1_is_in_subgroup"),
    ("c", "5", "bls12_381_g1_add"),
    ("c", "6", "bls12_381_g1_mul"),
    ("c", "7", "bls12_381_g1_msm"),
    ("c", "8", "bls12_381_map_fp_to_g1"),
    ("c", "9", "bls12_381_hash_to_g1"),
    ("c", "a", "bls12_381_check_g2_is_in_subgroup"),
    ("c", "b", "bls12_381_g2_add"),
    ("c", "c", "bls12_381_g2_mul"),
    ("c", "d", "bls12_381_g2_msm"),
    ("c", "e", "bls12_381_map_fp2_to_g2"),
    ("c", "f", "bls12_381_hash_to_g2"),
    ("c", "g", "bls12_381_multi_pairing_check"),
    ("c", "h", "bls12_381_fr_add"),
    ("c", "i", "bls12_381_fr_sub"),
    ("c", "j", "bls12_381_fr_mul"),
    ("c", "k", "bls12_381_fr_pow"),
    ("c", "l", "bls12_381_fr_inv"),
    ("c", "m", "bn254_g1_add"),
    ("c", "n", "bn254_g1_mul"),
    ("c", "o", "bn254_multi_pairing_check"),
    ("c", "r", "bn254_g1_msm"),
    ("c", "s", "bn254_fr_add"),
    ("c", "t", "bn254_fr_sub"),
    ("c", "u", "bn254_fr_mul"),
    ("c", "v", "bn254_fr_pow"),
    ("c", "w", "bn254_fr_inv"),
    ("c", "x", "bls12_381_g1_is_on_curve"),
    ("c", "y", "bls12_381_g2_is_on_curve"),
    ("c", "z", "bn254_g1_is_on_curve"),
];

/// Every signal this tool knows, as `(id, description)`.
pub const KNOWN_SIGNALS: &[(&str, &str)] = &[(
    "imports-pairing-curve-host-functions",
    "Wasm imports BLS12-381 or BN254 host functions",
)];

/// Evaluate signal `id` against `info`. Returns `None` for an unknown id.
pub fn evaluate(id: &str, info: &WasmInfo) -> Option<SignalResult> {
    match id {
        "imports-pairing-curve-host-functions" => Some(pairing_curve_imports(info)),
        _ => None,
    }
}

fn pairing_curve_imports(info: &WasmInfo) -> SignalResult {
    let evidence: Vec<String> = info
        .imports
        .iter()
        .filter_map(|imp| {
            PAIRING_CURVE_HOST_FUNCTIONS
                .iter()
                .find(|(m, e, _)| *m == imp.module && *e == imp.name)
                .map(|(m, e, name)| format!("{m}.{e} ({name})"))
        })
        .collect();
    SignalResult {
        id: "imports-pairing-curve-host-functions".into(),
        description: "Wasm imports BLS12-381 or BN254 host functions".into(),
        observed: !evidence.is_empty(),
        evidence,
        limits: "Shows the contract does pairing-curve work on the host. A contract can still \
                 build and compare `Fr` values without importing any of these functions, so \
                 `observed: false` does not rule the advisory out."
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::module;
    use crate::wasm::analyze;

    #[test]
    fn detects_fr_add_import() {
        let info = analyze(&module(None, &[("c", "h"), ("x", "_")])).unwrap();
        let r = evaluate("imports-pairing-curve-host-functions", &info).unwrap();
        assert!(r.observed);
        assert_eq!(r.evidence, vec!["c.h (bls12_381_fr_add)".to_string()]);
    }

    #[test]
    fn no_pairing_imports() {
        let info = analyze(&module(None, &[("c", "p"), ("b", "j")])).unwrap();
        let r = evaluate("imports-pairing-curve-host-functions", &info).unwrap();
        assert!(!r.observed);
    }

    #[test]
    fn unknown_signal() {
        let info = analyze(&module(None, &[])).unwrap();
        assert!(evaluate("nope", &info).is_none());
    }

    #[test]
    fn known_signals_all_evaluate() {
        let info = analyze(&module(None, &[])).unwrap();
        for (id, _) in KNOWN_SIGNALS {
            assert!(evaluate(id, &info).is_some(), "{id}");
        }
    }
}
