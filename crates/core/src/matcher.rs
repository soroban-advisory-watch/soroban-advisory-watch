//! Match one contract against a set of advisories.

use semver::Version;
use serde::Serialize;

use crate::advisory::{Advisory, AdvisoryDb, AffectedPackage, Relation};
use crate::signals::{self, SignalResult};
use crate::wasm::WasmInfo;

/// Result for one advisory, or the overall result for one contract.
///
/// Ordering is by how much attention the result needs: `Possible` first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// The recorded version is in an affected range. Other conditions in the
    /// advisory have not been ruled out.
    Possible,
    /// The version needed to decide is not recorded in the Wasm.
    Unknown,
    /// The recorded version is outside every affected range. Not a safety
    /// guarantee.
    NotMatched,
    /// The contract is not Wasm (Stellar Asset Contract).
    NotApplicable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Possible => "possible",
            Status::Unknown => "unknown",
            Status::NotMatched => "not-matched",
            Status::NotApplicable => "not-applicable",
        }
    }
}

/// How directly the version evidence supports a `possible` result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    /// The affected crate's exact version is recorded.
    High,
    /// Only a lower bound on the affected crate's version is known.
    Low,
}

/// What the matcher is looking at.
#[derive(Debug, Clone, Copy)]
pub enum Target<'a> {
    Wasm(&'a WasmInfo),
    StellarAsset,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    pub severity: Option<String>,
    pub url: String,
    pub crates: Vec<String>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// False when Wasm metadata cannot say anything about the affected
    /// crate's version (third-party crates). Such findings are always
    /// `unknown` and do not decide the contract's overall status.
    pub version_recorded: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<SignalResult>,
}

/// Evaluate `target` against every contract-level advisory in `db`.
/// Host-only advisories are skipped; see [`AdvisoryDb::advisories`] to list them.
pub fn evaluate(target: Target<'_>, db: &AdvisoryDb) -> Vec<Finding> {
    let mut findings: Vec<Finding> = db
        .advisories
        .iter()
        .filter(|a| !a.is_host_only())
        .map(|a| evaluate_one(target, a))
        .collect();
    findings.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then(a.confidence.cmp(&b.confidence))
            .then(a.advisory_id.cmp(&b.advisory_id))
    });
    findings
}

/// The overall status of a contract: the most urgent of the findings whose
/// crate version the metadata records. Findings for crates the metadata never
/// records are always `unknown`; if they decided the overall status, every
/// contract would be `unknown`. They only decide it when no other advisory is
/// being checked.
pub fn overall_status(target: Target<'_>, findings: &[Finding]) -> Status {
    if let Target::StellarAsset = target {
        return Status::NotApplicable;
    }
    let recorded = findings
        .iter()
        .filter(|f| f.version_recorded)
        .map(|f| f.status)
        .min();
    recorded
        .or_else(|| findings.iter().map(|f| f.status).min())
        .unwrap_or(Status::NotMatched)
}

struct PackageVerdict {
    status: Status,
    confidence: Option<Confidence>,
    recorded: bool,
    reason: String,
}

fn evaluate_one(target: Target<'_>, advisory: &Advisory) -> Finding {
    let info = match target {
        Target::StellarAsset => {
            return finding(
                advisory,
                PackageVerdict {
                    status: Status::NotApplicable,
                    confidence: None,
                    recorded: true,
                    reason: "Stellar Asset Contract: runs built-in host code, not Wasm.".into(),
                },
                Vec::new(),
            );
        }
        Target::Wasm(info) => info,
    };

    let verdict = advisory
        .packages
        .iter()
        .filter(|p| p.relation != Relation::Host)
        .map(|p| evaluate_package(info, p))
        .min_by(|a, b| {
            a.status
                .cmp(&b.status)
                .then(a.confidence.cmp(&b.confidence))
        })
        .unwrap_or(PackageVerdict {
            status: Status::NotMatched,
            confidence: None,
            recorded: true,
            reason: "No contract-level packages in this advisory.".into(),
        });

    let signal_results = advisory
        .signals
        .iter()
        .filter_map(|id| signals::evaluate(id, info))
        .collect();
    finding(advisory, verdict, signal_results)
}

fn finding(advisory: &Advisory, v: PackageVerdict, signals: Vec<SignalResult>) -> Finding {
    Finding {
        advisory_id: advisory.id.clone(),
        aliases: advisory.aliases.clone(),
        summary: advisory.summary.clone(),
        severity: advisory.severity.clone(),
        url: advisory.url.clone(),
        crates: advisory
            .crate_names()
            .into_iter()
            .map(str::to_string)
            .collect(),
        status: v.status,
        confidence: v.confidence,
        version_recorded: v.recorded,
        reason: v.reason,
        condition: advisory.condition.clone(),
        signals,
    }
}

fn evaluate_package(info: &WasmInfo, pkg: &AffectedPackage) -> PackageVerdict {
    let recorded = pkg.relation != Relation::NotRecorded;
    let sdk = match (&info.sdk_version, &info.sdk_version_raw) {
        (Some(sdk), _) => &sdk.version,
        (None, Some(raw)) if pkg.relation != Relation::NotRecorded => {
            return PackageVerdict {
                status: Status::Unknown,
                confidence: None,
                recorded,
                reason: format!("`rssdkver` is `{raw}`, which is not a semver version."),
            };
        }
        (None, None) if pkg.relation != Relation::NotRecorded => {
            return PackageVerdict {
                status: Status::Unknown,
                confidence: None,
                recorded,
                reason: if info.has_meta_section {
                    "No `rssdkver` in contract metadata (built without the Rust SDK, or the key \
                     was removed)."
                        .into()
                } else {
                    "No `contractmetav0` section (metadata stripped, or built without the Rust \
                     SDK)."
                        .into()
                },
            };
        }
        _ => &Version::new(0, 0, 0),
    };

    match pkg.relation {
        Relation::Direct => {
            if pkg.contains(sdk) {
                PackageVerdict {
                    status: Status::Possible,
                    confidence: Some(Confidence::High),
                    recorded,
                    reason: format!(
                        "Built with {} {sdk}, which is in an affected range{}.",
                        pkg.name,
                        fixed_hint(pkg, sdk)
                    ),
                }
            } else {
                PackageVerdict {
                    status: Status::NotMatched,
                    confidence: None,
                    recorded,
                    reason: format!(
                        "Built with {} {sdk}, which is outside every affected range.",
                        pkg.name
                    ),
                }
            }
        }
        Relation::SdkCaret => {
            let upper = next_breaking(sdk);
            if pkg.ranges.iter().any(|r| r.intersects(sdk, &upper))
                || pkg.versions.iter().any(|v| v >= sdk && v < &upper)
            {
                PackageVerdict {
                    status: Status::Possible,
                    confidence: Some(Confidence::Low),
                    recorded,
                    reason: format!(
                        "Built with soroban-sdk {sdk}. That release accepts any {name} from {sdk} \
                         up to (not including) {upper}, and part of that span is affected. The \
                         exact {name} version is not recorded; check the contract's Cargo.lock.",
                        name = pkg.name
                    ),
                }
            } else {
                PackageVerdict {
                    status: Status::NotMatched,
                    confidence: None,
                    recorded,
                    reason: format!(
                        "Built with soroban-sdk {sdk}, which requires {name} {sdk} or later \
                         within the same major version. None of those versions are affected.",
                        name = pkg.name
                    ),
                }
            }
        }
        Relation::NotRecorded => PackageVerdict {
            status: Status::Unknown,
            confidence: None,
            recorded,
            reason: format!(
                "Wasm metadata does not record the {} version. Check the contract's Cargo.lock.",
                pkg.name
            ),
        },
        Relation::Host => unreachable!("host packages are filtered out before this point"),
    }
}

/// The first version that a caret requirement `^v` does not accept.
fn next_breaking(v: &Version) -> Version {
    if v.major > 0 {
        Version::new(v.major + 1, 0, 0)
    } else if v.minor > 0 {
        Version::new(0, v.minor + 1, 0)
    } else {
        Version::new(0, 0, v.patch + 1)
    }
}

fn fixed_hint(pkg: &AffectedPackage, v: &Version) -> String {
    pkg.ranges
        .iter()
        .find(|r| r.contains(v))
        .and_then(|r| r.fixed.as_ref())
        .map(|f| format!("; fixed in {f}"))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{meta_bytes, module};
    use crate::wasm::analyze;

    fn info_with_sdk(ver: Option<&str>) -> WasmInfo {
        let meta = ver.map(|v| meta_bytes(&[("rssdkver", v)]));
        analyze(&module(meta.as_deref(), &[])).unwrap()
    }

    fn find<'a>(fs: &'a [Finding], id: &str) -> &'a Finding {
        fs.iter().find(|f| f.advisory_id == id).unwrap()
    }

    #[test]
    fn sdk_25_0_1_matches_overflow_and_fr() {
        let db = AdvisoryDb::bundled().unwrap();
        let info = info_with_sdk(Some("25.0.1#abc"));
        let fs = evaluate(Target::Wasm(&info), &db);
        let overflow = find(&fs, "GHSA-96xm-fv9w-pf3f");
        assert_eq!(overflow.status, Status::Possible);
        assert_eq!(overflow.confidence, Some(Confidence::High));
        assert!(overflow.reason.contains("fixed in 25.0.2"));
        assert_eq!(find(&fs, "GHSA-x2hw-px52-wp4m").status, Status::Possible);
        let macros = find(&fs, "GHSA-4chv-4c6w-w254");
        assert_eq!(macros.status, Status::Possible);
        assert_eq!(macros.confidence, Some(Confidence::Low));
        assert_eq!(find(&fs, "GHSA-x5m4-43jf-hh65").status, Status::Unknown);
        assert!(!fs.iter().any(|f| f.advisory_id == "GHSA-pm4j-7r4q-ccg8"));
        assert_eq!(overall_status(Target::Wasm(&info), &fs), Status::Possible);
    }

    #[test]
    fn sdk_25_3_0_matches_nothing_by_version() {
        let db = AdvisoryDb::bundled().unwrap();
        let info = info_with_sdk(Some("25.3.0"));
        let fs = evaluate(Target::Wasm(&info), &db);
        for id in [
            "GHSA-96xm-fv9w-pf3f",
            "GHSA-x2hw-px52-wp4m",
            "GHSA-4chv-4c6w-w254",
        ] {
            assert_eq!(find(&fs, id).status, Status::NotMatched, "{id}");
        }
        // The third-party crate stays unknown but does not decide the overall
        // status.
        let fpm = find(&fs, "GHSA-x5m4-43jf-hh65");
        assert_eq!(fpm.status, Status::Unknown);
        assert!(!fpm.version_recorded);
        assert_eq!(overall_status(Target::Wasm(&info), &fs), Status::NotMatched);
    }

    #[test]
    fn caret_relation_boundaries() {
        let db = AdvisoryDb::bundled().unwrap();
        // macros fixed in 25.1.1: sdk 25.1.0 may resolve to 25.1.0 (affected).
        let fs = evaluate(Target::Wasm(&info_with_sdk(Some("25.1.0"))), &db);
        assert_eq!(find(&fs, "GHSA-4chv-4c6w-w254").status, Status::Possible);
        // sdk 25.1.1 requires macros >= 25.1.1: not affected.
        let fs = evaluate(Target::Wasm(&info_with_sdk(Some("25.1.1"))), &db);
        assert_eq!(find(&fs, "GHSA-4chv-4c6w-w254").status, Status::NotMatched);
        // sdk 23.5.2 requires macros >= 23.5.2 (fix) in 23.x.
        let fs = evaluate(Target::Wasm(&info_with_sdk(Some("23.5.2"))), &db);
        assert_eq!(find(&fs, "GHSA-4chv-4c6w-w254").status, Status::NotMatched);
        // sdk 26.0.0: no 26.x range.
        let fs = evaluate(Target::Wasm(&info_with_sdk(Some("26.0.0"))), &db);
        assert_eq!(find(&fs, "GHSA-4chv-4c6w-w254").status, Status::NotMatched);
    }

    #[test]
    fn missing_metadata_is_unknown_not_safe() {
        let db = AdvisoryDb::bundled().unwrap();
        let info = info_with_sdk(None);
        let fs = evaluate(Target::Wasm(&info), &db);
        assert!(fs.iter().all(|f| f.status == Status::Unknown));
        assert!(find(&fs, "GHSA-96xm-fv9w-pf3f")
            .reason
            .contains("No `contractmetav0`"));
        assert_eq!(overall_status(Target::Wasm(&info), &fs), Status::Unknown);
    }

    #[test]
    fn only_unrecorded_advisory_gives_unknown_overall() {
        let db = AdvisoryDb::bundled()
            .unwrap()
            .filtered("GHSA-x5m4-43jf-hh65")
            .unwrap();
        let info = info_with_sdk(Some("25.3.0"));
        let fs = evaluate(Target::Wasm(&info), &db);
        assert_eq!(overall_status(Target::Wasm(&info), &fs), Status::Unknown);
    }

    #[test]
    fn invalid_version_is_unknown() {
        let db = AdvisoryDb::bundled().unwrap();
        let info = info_with_sdk(Some("my-fork"));
        let fs = evaluate(Target::Wasm(&info), &db);
        assert_eq!(find(&fs, "GHSA-96xm-fv9w-pf3f").status, Status::Unknown);
    }

    #[test]
    fn stellar_asset_is_not_applicable() {
        let db = AdvisoryDb::bundled().unwrap();
        let fs = evaluate(Target::StellarAsset, &db);
        assert!(fs.iter().all(|f| f.status == Status::NotApplicable));
        assert_eq!(
            overall_status(Target::StellarAsset, &fs),
            Status::NotApplicable
        );
    }

    #[test]
    fn fr_finding_carries_signal() {
        let db = AdvisoryDb::bundled().unwrap();
        let meta = meta_bytes(&[("rssdkver", "25.0.1")]);
        let info = analyze(&module(Some(&meta), &[("c", "h")])).unwrap();
        let fs = evaluate(Target::Wasm(&info), &db);
        let fr = find(&fs, "GHSA-x2hw-px52-wp4m");
        assert_eq!(fr.signals.len(), 1);
        assert!(fr.signals[0].observed);
    }

    #[test]
    fn annotation_signals_are_known() {
        let db = AdvisoryDb::bundled().unwrap();
        for a in &db.advisories {
            for s in &a.signals {
                assert!(
                    signals::KNOWN_SIGNALS.iter().any(|(id, _)| id == s),
                    "{} references unknown signal {s}",
                    a.id
                );
            }
        }
    }

    #[test]
    fn next_breaking_versions() {
        assert_eq!(
            next_breaking(&Version::new(25, 1, 0)),
            Version::new(26, 0, 0)
        );
        assert_eq!(
            next_breaking(&Version::new(0, 9, 3)),
            Version::new(0, 10, 0)
        );
        assert_eq!(next_breaking(&Version::new(0, 0, 3)), Version::new(0, 0, 4));
    }
}
