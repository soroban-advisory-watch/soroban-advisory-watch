# Advisory data

## Bundled advisories

| Id | Aliases | Crate | Scope | Affected | Signals |
|---|---|---|---|---|---|
| GHSA-96xm-fv9w-pf3f | CVE-2026-24889 | soroban-sdk | contract | `<22.0.9`, `>=23.0.0 <23.5.1`, `>=25.0.0 <25.0.2` | none |
| GHSA-x2hw-px52-wp4m | CVE-2026-32322 | soroban-sdk | contract | `<22.0.11`, `>=23.0.0 <23.5.3`, `>=25.0.0 <25.3.0` | `imports-pairing-curve-host-functions` |
| GHSA-4chv-4c6w-w254 | CVE-2026-26267 | soroban-sdk-macros | contract (lower bound) | `<22.0.10`, `>=23.0.0 <23.5.2`, `>=25.0.0 <25.1.1` | none |
| GHSA-x5m4-43jf-hh65 | CVE-2026-24783 | soroban-fixed-point-math | contract (not recorded) | `>=1.3.0 <1.3.1`, `>=1.4.0 <1.4.1` | none |
| GHSA-pm4j-7r4q-ccg8 | none | soroban-env-host | host (skipped) | `<26.0.0` | none |

## Where the data lives

```text
advisories/
  osv/                 OSV JSON, copied unchanged from github/advisory-database
  annotations.toml     this project's notes: condition text and signal ids
```

The OSV files come from the [GitHub Advisory Database](https://github.com/github/advisory-database), which is licensed under [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/). They are not edited. Anything this project adds goes in `annotations.toml`, so the upstream data can be refreshed by copying files.

## Annotation fields

```toml
[[advisory]]
id = "GHSA-x2hw-px52-wp4m"
condition = """Only contracts that accept `Fr` values ..."""
signals = ["imports-pairing-curve-host-functions"]
```

| Field | Rule |
|---|---|
| `id` | GHSA id of a bundled advisory. |
| `condition` | Quote or paraphrase the advisory. Do not add conditions the advisory does not state. |
| `signals` | Ids from `crates/core/src/signals.rs`. A test fails if an id is unknown. |

## Adding an advisory

1. Copy the OSV JSON from `github/advisory-database` into `advisories/osv/`.
2. Add it to `BUNDLED_OSV` in `crates/core/src/advisory.rs`.
3. Add an `[[advisory]]` entry in `annotations.toml`.
4. Add a test in `crates/core/src/matcher.rs` for a version just inside and just outside each range.
5. Update the table above and `CHANGELOG.md`.
