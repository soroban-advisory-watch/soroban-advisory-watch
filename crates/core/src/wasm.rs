//! Read the parts of a Soroban contract Wasm module that this tool uses:
//! the `contractmetav0` and `contractenvmetav0` custom sections, the import
//! list, and the SHA-256 hash that identifies the code on chain.

use serde::Serialize;
use sha2::{Digest, Sha256};
use stellar_xdr::{Limited, Limits, ReadXdr, ScEnvMetaEntry, ScMetaEntry};
use wasmparser::{Parser, Payload, TypeRef};

/// Name of the custom section that holds `ScMetaEntry` key/value pairs.
pub const CONTRACT_META_SECTION: &str = "contractmetav0";
/// Name of the custom section that holds the environment interface version.
pub const CONTRACT_ENV_META_SECTION: &str = "contractenvmetav0";

/// Meta key written by `soroban-sdk` with its crate version and git revision.
pub const META_KEY_SDK_VERSION: &str = "rssdkver";
/// Meta key written by `soroban-sdk` with the rustc version used for the build.
pub const META_KEY_RUSTC_VERSION: &str = "rsver";

/// Upper bound on custom section size we are willing to decode.
/// Real contracts are far below this. It stops a crafted file from making us
/// allocate a large amount of memory.
const MAX_SECTION_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum WasmError {
    #[error("not a valid Wasm module: {0}")]
    Parse(#[from] wasmparser::BinaryReaderError),
    #[error("custom section `{section}` could not be decoded as XDR: {source}")]
    Xdr {
        section: &'static str,
        source: stellar_xdr::Error,
    },
    #[error("custom section `{0}` is larger than 1 MiB")]
    SectionTooLarge(String),
}

/// One key/value pair from `contractmetav0`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MetaEntry {
    pub key: String,
    pub val: String,
}

/// The `soroban-sdk` version recorded in `rssdkver`, for example
/// `25.0.1#941448079eccf95627d2ffea13ba268e305a9077`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SdkVersion {
    /// The exact string found in the metadata.
    pub raw: String,
    /// The crate version, parsed as semver.
    pub version: semver::Version,
    /// The git revision after `#`, if present.
    pub git_revision: Option<String>,
}

impl SdkVersion {
    /// Parse an `rssdkver` value. Returns `None` if the part before `#` is not
    /// valid semver.
    pub fn parse(raw: &str) -> Option<Self> {
        let (ver, rev) = match raw.split_once('#') {
            Some((v, r)) => (v, Some(r.trim().to_string()).filter(|r| !r.is_empty())),
            None => (raw, None),
        };
        let version = semver::Version::parse(ver.trim()).ok()?;
        Some(Self {
            raw: raw.to_string(),
            version,
            git_revision: rev,
        })
    }
}

/// A function the module imports from the Soroban host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Import {
    pub module: String,
    pub name: String,
}

/// The environment interface version from `contractenvmetav0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct InterfaceVersion {
    pub protocol: u32,
    pub pre_release: u32,
}

/// Everything this tool reads from one Wasm module.
#[derive(Debug, Clone, Serialize)]
pub struct WasmInfo {
    /// Hex-encoded SHA-256 of the module bytes. This is the hash Soroban uses
    /// for the contract code ledger entry.
    pub hash: String,
    pub size: usize,
    /// True if at least one `contractmetav0` section was present.
    pub has_meta_section: bool,
    pub meta: Vec<MetaEntry>,
    /// Raw `rssdkver` value, if present.
    pub sdk_version_raw: Option<String>,
    /// Parsed `rssdkver`, if present and valid semver.
    pub sdk_version: Option<SdkVersion>,
    pub rustc_version: Option<String>,
    pub interface_version: Option<InterfaceVersion>,
    pub imports: Vec<Import>,
}

impl WasmInfo {
    /// Look up the last value written for `key`. Later entries win, which
    /// matches how a reader would see a key repeated by a build tool.
    pub fn meta_value(&self, key: &str) -> Option<&str> {
        self.meta
            .iter()
            .rev()
            .find(|e| e.key == key)
            .map(|e| e.val.as_str())
    }
}

/// Hex SHA-256 of `bytes`.
pub fn wasm_hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Parse a Wasm module and extract its Soroban metadata and imports.
pub fn analyze(bytes: &[u8]) -> Result<WasmInfo, WasmError> {
    let mut meta = Vec::new();
    let mut has_meta_section = false;
    let mut interface_version = None;
    let mut imports = Vec::new();

    for payload in Parser::new(0).parse_all(bytes) {
        match payload? {
            Payload::CustomSection(reader) => {
                let name = reader.name();
                if name == CONTRACT_META_SECTION {
                    has_meta_section = true;
                    check_size(name, reader.data())?;
                    meta.extend(decode_meta(reader.data())?);
                } else if name == CONTRACT_ENV_META_SECTION {
                    check_size(name, reader.data())?;
                    if let Some(v) = decode_env_meta(reader.data())? {
                        interface_version = Some(v);
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import?;
                    if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        imports.push(Import {
                            module: import.module.to_string(),
                            name: import.name.to_string(),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    let mut info = WasmInfo {
        hash: wasm_hash(bytes),
        size: bytes.len(),
        has_meta_section,
        meta,
        sdk_version_raw: None,
        sdk_version: None,
        rustc_version: None,
        interface_version,
        imports,
    };
    info.sdk_version_raw = info.meta_value(META_KEY_SDK_VERSION).map(str::to_string);
    info.sdk_version = info.sdk_version_raw.as_deref().and_then(SdkVersion::parse);
    info.rustc_version = info.meta_value(META_KEY_RUSTC_VERSION).map(str::to_string);
    Ok(info)
}

fn check_size(name: &str, data: &[u8]) -> Result<(), WasmError> {
    if data.len() > MAX_SECTION_BYTES {
        return Err(WasmError::SectionTooLarge(name.to_string()));
    }
    Ok(())
}

fn limits(data: &[u8]) -> Limits {
    Limits {
        depth: 64,
        len: data.len(),
    }
}

fn decode_meta(data: &[u8]) -> Result<Vec<MetaEntry>, WasmError> {
    let mut reader = Limited::new(data, limits(data));
    let mut out = Vec::new();
    for entry in ScMetaEntry::read_xdr_iter(&mut reader) {
        let entry = entry.map_err(|source| WasmError::Xdr {
            section: CONTRACT_META_SECTION,
            source,
        })?;
        match entry {
            ScMetaEntry::ScMetaV0(v0) => out.push(MetaEntry {
                key: v0.key.to_utf8_string_lossy(),
                val: v0.val.to_utf8_string_lossy(),
            }),
        }
    }
    Ok(out)
}

fn decode_env_meta(data: &[u8]) -> Result<Option<InterfaceVersion>, WasmError> {
    let mut reader = Limited::new(data, limits(data));
    let mut found = None;
    for entry in ScEnvMetaEntry::read_xdr_iter(&mut reader) {
        let entry = entry.map_err(|source| WasmError::Xdr {
            section: CONTRACT_ENV_META_SECTION,
            source,
        })?;
        match entry {
            ScEnvMetaEntry::ScEnvMetaKindInterfaceVersion(v) => {
                found = Some(InterfaceVersion {
                    protocol: v.protocol,
                    pre_release: v.pre_release,
                });
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{meta_bytes, module};

    #[test]
    fn parses_sdk_version_with_revision() {
        let v = SdkVersion::parse("25.0.1#941448079eccf95627d2ffea13ba268e305a9077").unwrap();
        assert_eq!(v.version, semver::Version::new(25, 0, 1));
        assert_eq!(
            v.git_revision.as_deref(),
            Some("941448079eccf95627d2ffea13ba268e305a9077")
        );
    }

    #[test]
    fn parses_sdk_version_without_revision() {
        let v = SdkVersion::parse("22.0.0-rc.1").unwrap();
        assert_eq!(v.version, semver::Version::parse("22.0.0-rc.1").unwrap());
        assert_eq!(v.git_revision, None);
    }

    #[test]
    fn rejects_non_semver() {
        assert!(SdkVersion::parse("latest").is_none());
        assert!(SdkVersion::parse("").is_none());
    }

    #[test]
    fn reads_meta_and_imports_from_synthetic_module() {
        let wasm = module(
            Some(&meta_bytes(&[
                ("rsver", "1.90.0"),
                ("rssdkver", "23.4.0#abc"),
            ])),
            &[("c", "h"), ("x", "_")],
        );
        let info = analyze(&wasm).unwrap();
        assert!(info.has_meta_section);
        assert_eq!(info.rustc_version.as_deref(), Some("1.90.0"));
        assert_eq!(
            info.sdk_version.unwrap().version,
            semver::Version::new(23, 4, 0)
        );
        assert_eq!(info.imports.len(), 2);
        assert_eq!(info.hash, wasm_hash(&wasm));
    }

    #[test]
    fn module_without_meta_has_no_version() {
        let wasm = module(None, &[]);
        let info = analyze(&wasm).unwrap();
        assert!(!info.has_meta_section);
        assert!(info.sdk_version.is_none());
        assert!(info.sdk_version_raw.is_none());
    }

    #[test]
    fn keeps_raw_value_when_version_is_not_semver() {
        let wasm = module(Some(&meta_bytes(&[("rssdkver", "custom-build")])), &[]);
        let info = analyze(&wasm).unwrap();
        assert_eq!(info.sdk_version_raw.as_deref(), Some("custom-build"));
        assert!(info.sdk_version.is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(analyze(b"not wasm").is_err());
    }

    #[test]
    fn rejects_truncated_meta_section() {
        let mut bytes = meta_bytes(&[("rssdkver", "25.0.1")]);
        bytes.truncate(bytes.len() - 3);
        let wasm = module(Some(&bytes), &[]);
        assert!(matches!(analyze(&wasm), Err(WasmError::Xdr { .. })));
    }
}
