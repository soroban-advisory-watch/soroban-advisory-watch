//! Advisory data: OSV records plus this project's annotations.
//!
//! Records are stored in the [OSV schema](https://ossf.github.io/osv-schema/)
//! exactly as published by the GitHub Advisory Database. Our own notes about
//! each advisory (conditions, Wasm signals) live in a separate annotations
//! file so the upstream data is never edited by hand.

use std::collections::BTreeMap;

use semver::Version;
use serde::{Deserialize, Serialize};

/// OSV files bundled into the binary at build time.
const BUNDLED_OSV: &[(&str, &str)] = &[
    (
        "GHSA-96xm-fv9w-pf3f",
        include_str!("../../../advisories/osv/GHSA-96xm-fv9w-pf3f.json"),
    ),
    (
        "GHSA-x2hw-px52-wp4m",
        include_str!("../../../advisories/osv/GHSA-x2hw-px52-wp4m.json"),
    ),
    (
        "GHSA-4chv-4c6w-w254",
        include_str!("../../../advisories/osv/GHSA-4chv-4c6w-w254.json"),
    ),
    (
        "GHSA-pm4j-7r4q-ccg8",
        include_str!("../../../advisories/osv/GHSA-pm4j-7r4q-ccg8.json"),
    ),
    (
        "GHSA-x5m4-43jf-hh65",
        include_str!("../../../advisories/osv/GHSA-x5m4-43jf-hh65.json"),
    ),
];

const BUNDLED_ANNOTATIONS: &str = include_str!("../../../advisories/annotations.toml");

#[derive(Debug, thiserror::Error)]
pub enum AdvisoryError {
    #[error("invalid OSV JSON in {source_name}: {err}")]
    Json {
        source_name: String,
        err: serde_json::Error,
    },
    #[error("invalid annotations TOML: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("advisory {id}: invalid version `{version}` in affected range")]
    Version { id: String, version: String },
}

// ---------------------------------------------------------------------------
// OSV schema (the subset we read)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
struct OsvRecord {
    id: String,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    withdrawn: Option<String>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
    #[serde(default)]
    references: Vec<OsvReference>,
    #[serde(default)]
    severity: Vec<OsvSeverity>,
    #[serde(default)]
    database_specific: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvAffected {
    package: OsvPackage,
    #[serde(default)]
    ranges: Vec<OsvRange>,
    #[serde(default)]
    versions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvPackage {
    ecosystem: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvRange {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    events: Vec<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvReference {
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OsvSeverity {
    #[serde(rename = "type")]
    kind: String,
    score: String,
}

// ---------------------------------------------------------------------------
// Annotations
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Deserialize)]
struct AnnotationsFile {
    #[serde(default)]
    advisory: Vec<Annotation>,
}

/// Our notes about one advisory.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Annotation {
    pub id: String,
    /// Plain-language description of what else must be true for a contract
    /// to be affected, beyond the version.
    #[serde(default)]
    pub condition: Option<String>,
    /// Ids of signals from [`crate::signals`] that add context.
    #[serde(default)]
    pub signals: Vec<String>,
}

// ---------------------------------------------------------------------------
// Normalised model
// ---------------------------------------------------------------------------

/// One half-open (or closed) version interval from an OSV range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VersionRange {
    pub introduced: Version,
    /// First version that is not affected.
    pub fixed: Option<Version>,
    /// Last version that is affected (used when no fix exists).
    pub last_affected: Option<Version>,
}

impl VersionRange {
    pub fn contains(&self, v: &Version) -> bool {
        if v < &self.introduced {
            return false;
        }
        if let Some(fixed) = &self.fixed {
            return v < fixed;
        }
        if let Some(last) = &self.last_affected {
            return v <= last;
        }
        true
    }

    /// True if any version `m` with `lower <= m < upper` is in this range.
    pub fn intersects(&self, lower: &Version, upper: &Version) -> bool {
        let start = if lower > &self.introduced {
            lower
        } else {
            &self.introduced
        };
        if start >= upper {
            return false;
        }
        match (&self.fixed, &self.last_affected) {
            (Some(fixed), _) => start < fixed,
            (None, Some(last)) => start <= last,
            (None, None) => true,
        }
    }
}

/// How a crate's version relates to what Wasm metadata records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Relation {
    /// The crate is `soroban-sdk`; `rssdkver` records its exact version.
    Direct,
    /// `soroban-sdk` depends on the crate with a caret requirement on its own
    /// version (`^X.Y.Z`). The compiled-in version is at least the SDK version
    /// and has the same major, but the exact version is not recorded.
    /// Checked against crates.io for soroban-sdk 22.0.0 through 29.0.1.
    SdkCaret,
    /// Runs in validators, not in contract Wasm. Fixed by a network upgrade.
    Host,
    /// Wasm metadata does not record this crate's version.
    NotRecorded,
}

impl Relation {
    pub fn for_crate(name: &str) -> Self {
        match name {
            "soroban-sdk" => Relation::Direct,
            "soroban-sdk-macros" | "soroban-spec" => Relation::SdkCaret,
            "soroban-env-host" => Relation::Host,
            _ => Relation::NotRecorded,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AffectedPackage {
    pub name: String,
    pub relation: Relation,
    pub ranges: Vec<VersionRange>,
    /// Explicit version list from OSV, used when no ranges are given.
    pub versions: Vec<Version>,
}

impl AffectedPackage {
    pub fn contains(&self, v: &Version) -> bool {
        self.ranges.iter().any(|r| r.contains(v)) || self.versions.iter().any(|x| x == v)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Advisory {
    pub id: String,
    pub aliases: Vec<String>,
    pub summary: String,
    /// `low`, `moderate`, `high` or `critical`, from GitHub's
    /// `database_specific.severity`, when present.
    pub severity: Option<String>,
    pub cvss: Option<String>,
    pub published: Option<String>,
    pub url: String,
    pub packages: Vec<AffectedPackage>,
    pub condition: Option<String>,
    pub signals: Vec<String>,
}

impl Advisory {
    /// True if every affected package runs only in the host.
    pub fn is_host_only(&self) -> bool {
        !self.packages.is_empty() && self.packages.iter().all(|p| p.relation == Relation::Host)
    }

    pub fn matches_id(&self, id: &str) -> bool {
        self.id.eq_ignore_ascii_case(id) || self.aliases.iter().any(|a| a.eq_ignore_ascii_case(id))
    }

    pub fn crate_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.packages.iter().map(|p| p.name.as_str()).collect();
        names.dedup();
        names
    }
}

/// A set of advisories.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdvisoryDb {
    pub advisories: Vec<Advisory>,
}

impl AdvisoryDb {
    /// The advisories bundled with this release.
    pub fn bundled() -> Result<Self, AdvisoryError> {
        let annotations = parse_annotations(BUNDLED_ANNOTATIONS)?;
        let mut db = AdvisoryDb::default();
        for (name, json) in BUNDLED_OSV {
            db.add_osv_json(name, json, &annotations)?;
        }
        Ok(db)
    }

    /// Add one OSV record (or a JSON array of records). Records for other
    /// ecosystems, and packages outside crates.io, are ignored. A record with
    /// an id already present replaces the existing one, so a newer file from
    /// the user wins over the bundled copy.
    pub fn add_osv_json(
        &mut self,
        source_name: &str,
        json: &str,
        annotations: &BTreeMap<String, Annotation>,
    ) -> Result<usize, AdvisoryError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|err| AdvisoryError::Json {
                source_name: source_name.to_string(),
                err,
            })?;
        let records: Vec<OsvRecord> = if value.is_array() {
            serde_json::from_value(value)
        } else {
            serde_json::from_value(value).map(|r| vec![r])
        }
        .map_err(|err| AdvisoryError::Json {
            source_name: source_name.to_string(),
            err,
        })?;

        let mut added = 0;
        for record in records {
            if record.withdrawn.is_some() {
                continue;
            }
            if let Some(adv) = normalise(record, annotations)? {
                self.advisories.retain(|a| a.id != adv.id);
                self.advisories.push(adv);
                added += 1;
            }
        }
        self.advisories.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(added)
    }

    /// Add an OSV file using the bundled annotations.
    pub fn add_osv_file_contents(
        &mut self,
        source_name: &str,
        json: &str,
    ) -> Result<usize, AdvisoryError> {
        let annotations = parse_annotations(BUNDLED_ANNOTATIONS)?;
        self.add_osv_json(source_name, json, &annotations)
    }

    pub fn get(&self, id: &str) -> Option<&Advisory> {
        self.advisories.iter().find(|a| a.matches_id(id))
    }

    /// Keep only the advisory matching `id` (GHSA id or alias).
    pub fn filtered(&self, id: &str) -> Option<AdvisoryDb> {
        self.get(id).map(|a| AdvisoryDb {
            advisories: vec![a.clone()],
        })
    }
}

fn parse_annotations(src: &str) -> Result<BTreeMap<String, Annotation>, AdvisoryError> {
    let file: AnnotationsFile = toml::from_str(src)?;
    Ok(file
        .advisory
        .into_iter()
        .map(|a| (a.id.clone(), a))
        .collect())
}

fn parse_version(id: &str, s: &str) -> Result<Version, AdvisoryError> {
    if s == "0" {
        return Ok(Version::new(0, 0, 0));
    }
    Version::parse(s).map_err(|_| AdvisoryError::Version {
        id: id.to_string(),
        version: s.to_string(),
    })
}

fn normalise(
    record: OsvRecord,
    annotations: &BTreeMap<String, Annotation>,
) -> Result<Option<Advisory>, AdvisoryError> {
    let mut packages: Vec<AffectedPackage> = Vec::new();
    for affected in &record.affected {
        if !affected.package.ecosystem.eq_ignore_ascii_case("crates.io") {
            continue;
        }
        let mut ranges = Vec::new();
        for range in &affected.ranges {
            if range.kind != "SEMVER" && range.kind != "ECOSYSTEM" {
                continue;
            }
            ranges.extend(events_to_ranges(&record.id, &range.events)?);
        }
        let versions = affected
            .versions
            .iter()
            .map(|v| parse_version(&record.id, v))
            .collect::<Result<Vec<_>, _>>()?;
        let name = affected.package.name.clone();
        if let Some(existing) = packages.iter_mut().find(|p| p.name == name) {
            existing.ranges.extend(ranges);
            existing.versions.extend(versions);
        } else {
            packages.push(AffectedPackage {
                relation: Relation::for_crate(&name),
                name,
                ranges,
                versions,
            });
        }
    }
    if packages.is_empty() {
        return Ok(None);
    }
    for p in &mut packages {
        p.ranges.sort_by(|a, b| a.introduced.cmp(&b.introduced));
    }

    let severity = record
        .database_specific
        .as_ref()
        .and_then(|d| d.get("severity"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_ascii_lowercase());
    let cvss = record
        .severity
        .iter()
        .find(|s| s.kind.starts_with("CVSS"))
        .map(|s| s.score.clone());
    // Prefer the maintainer's own advisory page (it has the full write-up),
    // then any advisory reference, then GitHub's global advisory page.
    let url = record
        .references
        .iter()
        .find(|r| r.url.contains("/security/advisories/") && r.url.contains(&record.id))
        .or_else(|| record.references.iter().find(|r| r.kind == "ADVISORY"))
        .map(|r| r.url.clone())
        .unwrap_or_else(|| format!("https://github.com/advisories/{}", record.id));
    let annotation = annotations.get(&record.id).cloned().unwrap_or_default();

    Ok(Some(Advisory {
        summary: record.summary.clone().unwrap_or_default(),
        aliases: record.aliases.clone(),
        severity,
        cvss,
        published: record.published.clone(),
        url,
        packages,
        condition: annotation.condition,
        signals: annotation.signals,
        id: record.id,
    }))
}

/// Turn an OSV event list into intervals. Events are read in order:
/// `introduced` opens an interval, `fixed` or `last_affected` closes it.
fn events_to_ranges(
    id: &str,
    events: &[BTreeMap<String, String>],
) -> Result<Vec<VersionRange>, AdvisoryError> {
    let mut out = Vec::new();
    let mut open: Option<Version> = None;
    for event in events {
        if let Some(v) = event.get("introduced") {
            if let Some(start) = open.take() {
                out.push(VersionRange {
                    introduced: start,
                    fixed: None,
                    last_affected: None,
                });
            }
            open = Some(parse_version(id, v)?);
        } else if let Some(v) = event.get("fixed") {
            let start = open.take().unwrap_or(Version::new(0, 0, 0));
            out.push(VersionRange {
                introduced: start,
                fixed: Some(parse_version(id, v)?),
                last_affected: None,
            });
        } else if let Some(v) = event.get("last_affected") {
            let start = open.take().unwrap_or(Version::new(0, 0, 0));
            out.push(VersionRange {
                introduced: start,
                fixed: None,
                last_affected: Some(parse_version(id, v)?),
            });
        }
    }
    if let Some(start) = open {
        out.push(VersionRange {
            introduced: start,
            fixed: None,
            last_affected: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn bundled_db_loads() {
        let db = AdvisoryDb::bundled().unwrap();
        assert_eq!(db.advisories.len(), 5);
        let a = db.get("CVE-2026-24889").unwrap();
        assert_eq!(a.id, "GHSA-96xm-fv9w-pf3f");
        assert_eq!(a.severity.as_deref(), Some("moderate"));
        assert!(a.condition.is_some());
        assert_eq!(
            a.url,
            "https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-96xm-fv9w-pf3f"
        );
        let sdk = &a.packages[0];
        assert_eq!(sdk.name, "soroban-sdk");
        assert_eq!(sdk.relation, Relation::Direct);
        assert!(sdk.contains(&v("25.0.1")));
        assert!(!sdk.contains(&v("25.0.2")));
        assert!(sdk.contains(&v("23.5.0")));
        assert!(!sdk.contains(&v("23.5.1")));
        assert!(sdk.contains(&v("22.0.8")));
        assert!(!sdk.contains(&v("22.0.9")));
        assert!(!sdk.contains(&v("26.0.0")));
    }

    #[test]
    fn host_advisory_is_flagged() {
        let db = AdvisoryDb::bundled().unwrap();
        assert!(db.get("GHSA-pm4j-7r4q-ccg8").unwrap().is_host_only());
        assert!(!db.get("GHSA-96xm-fv9w-pf3f").unwrap().is_host_only());
    }

    #[test]
    fn macros_advisory_uses_caret_relation() {
        let db = AdvisoryDb::bundled().unwrap();
        let a = db.get("CVE-2026-26267").unwrap();
        assert_eq!(a.packages[0].relation, Relation::SdkCaret);
    }

    #[test]
    fn range_intersection() {
        let r = VersionRange {
            introduced: v("25.0.0"),
            fixed: Some(v("25.1.1")),
            last_affected: None,
        };
        assert!(r.intersects(&v("25.0.0"), &v("26.0.0")));
        assert!(r.intersects(&v("25.1.0"), &v("26.0.0")));
        assert!(!r.intersects(&v("25.1.1"), &v("26.0.0")));
        assert!(!r.intersects(&v("24.0.0"), &v("25.0.0")));
    }

    #[test]
    fn last_affected_is_inclusive() {
        let r = VersionRange {
            introduced: v("1.0.0"),
            fixed: None,
            last_affected: Some(v("1.2.0")),
        };
        assert!(r.contains(&v("1.2.0")));
        assert!(!r.contains(&v("1.2.1")));
    }

    #[test]
    fn user_file_replaces_bundled_record() {
        let mut db = AdvisoryDb::bundled().unwrap();
        let json = r#"{"id":"GHSA-96xm-fv9w-pf3f","summary":"updated","affected":[
            {"package":{"ecosystem":"crates.io","name":"soroban-sdk"},
             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"30.0.0"}]}]}]}"#;
        db.add_osv_file_contents("test", json).unwrap();
        assert_eq!(db.advisories.len(), 5);
        let a = db.get("GHSA-96xm-fv9w-pf3f").unwrap();
        assert_eq!(a.summary, "updated");
        assert!(a.packages[0].contains(&v("29.0.0")));
    }

    #[test]
    fn ignores_other_ecosystems_and_withdrawn() {
        let mut db = AdvisoryDb::default();
        let json = r#"[
          {"id":"GHSA-npm","affected":[{"package":{"ecosystem":"npm","name":"x"},"ranges":[]}]},
          {"id":"GHSA-gone","withdrawn":"2026-01-01T00:00:00Z","affected":[{"package":{"ecosystem":"crates.io","name":"soroban-sdk"},"ranges":[]}]}
        ]"#;
        assert_eq!(db.add_osv_file_contents("t", json).unwrap(), 0);
    }

    #[test]
    fn rejects_bad_version() {
        let mut db = AdvisoryDb::default();
        let json = r#"{"id":"GHSA-bad","affected":[{"package":{"ecosystem":"crates.io","name":"soroban-sdk"},
           "ranges":[{"type":"SEMVER","events":[{"introduced":"abc"}]}]}]}"#;
        assert!(db.add_osv_file_contents("t", json).is_err());
    }
}
