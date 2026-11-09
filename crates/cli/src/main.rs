//! `advisory-watch`: find Soroban contracts that may be affected by
//! soroban-sdk security advisories.

use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use advisory_watch_core::advisory::AdvisoryDb;
use advisory_watch_core::inventory;
use advisory_watch_core::matcher::{self, Status, Target};
use advisory_watch_core::report::{
    NetworkReport, ScanReport, Source, TargetReport, WasmGroup, WasmGroupError,
};
use advisory_watch_core::rpc::{self, Executable, RpcClient, Transport};
use advisory_watch_core::wasm::{self, WasmInfo};
use anyhow::{anyhow, bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};

const EXIT_OK: u8 = 0;
const EXIT_FAIL_ON: u8 = 1;
const EXIT_ERROR: u8 = 2;

/// Find Soroban contracts that may be affected by soroban-sdk security
/// advisories.
///
/// Results are `possible`, `unknown`, `not-matched` or `not-applicable`.
/// A `possible` result is a version match, not a confirmed vulnerability.
#[derive(Parser)]
#[command(name = "advisory-watch", version, about, long_about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Check Wasm files or deployed contracts against advisories.
    Scan(ScanArgs),
    /// Check every contract in an inventory file (network-wide report).
    Report(ReportArgs),
    /// Print the Soroban metadata of a Wasm file or deployed contract.
    Meta(MetaArgs),
    /// List or show the advisories this tool knows about.
    Advisories {
        #[command(subcommand)]
        cmd: AdvisoriesCmd,
    },
}

#[derive(Args)]
struct AdvisoryArgs {
    /// Extra OSV JSON file (one record or an array). Records replace bundled
    /// ones with the same id. Repeatable.
    #[arg(long = "osv", value_name = "FILE")]
    osv: Vec<PathBuf>,
    /// Only check this advisory (GHSA or CVE id).
    #[arg(long, value_name = "ID")]
    advisory: Option<String>,
}

#[derive(Args)]
struct NetworkArgs {
    /// Network the contract lives on.
    #[arg(long, value_enum, default_value_t = Network::Mainnet)]
    network: Network,
    /// Soroban RPC endpoint. Required for mainnet, which has no default.
    #[arg(long, env = "ADVISORY_WATCH_RPC_URL", value_name = "URL")]
    rpc_url: Option<String>,
}

#[derive(Args)]
struct OutputArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Exit with code 1 if any result is at least this serious.
    #[arg(long, value_enum, default_value_t = FailOn::Never)]
    fail_on: FailOn,
}

#[derive(Args)]
struct ScanArgs {
    /// Local Wasm file. Repeatable.
    #[arg(long, value_name = "PATH", required_unless_present = "contract_id")]
    wasm: Vec<PathBuf>,
    /// Deployed contract id (C...). Repeatable.
    #[arg(long, value_name = "ID", conflicts_with = "wasm")]
    contract_id: Vec<String>,
    #[command(flatten)]
    network: NetworkArgs,
    #[command(flatten)]
    advisories: AdvisoryArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct ReportArgs {
    /// Inventory file (.jsonl or .csv). See `docs/` for the format.
    #[arg(long, value_name = "FILE")]
    inventory: PathBuf,
    /// Directory of `<wasm-hash>.wasm` files. Read before calling RPC;
    /// downloaded Wasm is saved here.
    #[arg(long, value_name = "DIR")]
    wasm_dir: Option<PathBuf>,
    /// Do not call RPC. Wasm missing from --wasm-dir is reported as an error.
    #[arg(long, requires = "wasm_dir")]
    offline: bool,
    #[command(flatten)]
    network: NetworkArgs,
    #[command(flatten)]
    advisories: AdvisoryArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Args)]
struct MetaArgs {
    /// Local Wasm file.
    #[arg(long, value_name = "PATH", required_unless_present = "contract_id")]
    wasm: Option<PathBuf>,
    /// Deployed contract id (C...).
    #[arg(long, value_name = "ID", conflicts_with = "wasm")]
    contract_id: Option<String>,
    #[command(flatten)]
    network: NetworkArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Subcommand)]
enum AdvisoriesCmd {
    /// List advisories.
    List {
        #[arg(long = "osv", value_name = "FILE")]
        osv: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Show one advisory.
    Show {
        /// GHSA or CVE id.
        id: String,
        #[arg(long = "osv", value_name = "FILE")]
        osv: Vec<PathBuf>,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Network {
    Mainnet,
    Testnet,
    Futurenet,
}

impl Network {
    fn name(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Futurenet => "futurenet",
        }
    }

    fn passphrase(self) -> &'static str {
        match self {
            Network::Mainnet => rpc::PASSPHRASE_MAINNET,
            Network::Testnet => rpc::PASSPHRASE_TESTNET,
            Network::Futurenet => rpc::PASSPHRASE_FUTURENET,
        }
    }

    /// SDF's public endpoints, from the Stellar docs list of RPC providers.
    /// SDF does not run a public mainnet endpoint.
    fn default_rpc(self) -> Option<&'static str> {
        match self {
            Network::Mainnet => None,
            Network::Testnet => Some("https://soroban-testnet.stellar.org"),
            Network::Futurenet => Some("https://rpc-futurenet.stellar.org"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FailOn {
    /// Fail if any result is `possible`.
    Possible,
    /// Fail if any result is `possible` or `unknown`.
    Unknown,
    /// Never fail because of results.
    Never,
}

impl FailOn {
    fn triggered(self, worst: Option<Status>) -> bool {
        match (self, worst) {
            (FailOn::Never, _) | (_, None) => false,
            (FailOn::Possible, Some(s)) => s == Status::Possible,
            (FailOn::Unknown, Some(s)) => s <= Status::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP transport
// ---------------------------------------------------------------------------

struct Http {
    agent: ureq::Agent,
}

impl Http {
    fn new() -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(concat!(
                "soroban-advisory-watch/",
                env!("CARGO_PKG_VERSION")
            ))
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Transport for Http {
    fn post_json(&self, url: &str, body: &str) -> Result<String, String> {
        let mut resp = self
            .agent
            .post(url)
            .header("content-type", "application/json")
            .send(body)
            .map_err(|e| e.to_string())?;
        resp.body_mut()
            .with_config()
            .limit(32 * 1024 * 1024)
            .read_to_string()
            .map_err(|e| e.to_string())
    }
}

fn rpc_client(net: &NetworkArgs) -> Result<RpcClient<Http>> {
    let url = match (&net.rpc_url, net.network.default_rpc()) {
        (Some(u), _) => u.clone(),
        (None, Some(d)) => d.to_string(),
        (None, None) => bail!(
            "{} has no default RPC endpoint. Pass --rpc-url or set ADVISORY_WATCH_RPC_URL. \
             Providers are listed at https://developers.stellar.org/docs/data/apis/rpc/providers",
            net.network.name()
        ),
    };
    let client = RpcClient::new(url, Http::new());
    client
        .check_network(net.network.passphrase())
        .with_context(|| format!("checking network at {}", client.url()))?;
    Ok(client)
}

/// Download a contract's Wasm and confirm it hashes to the expected value.
fn fetch_wasm<T: Transport>(client: &RpcClient<T>, hash: &str) -> Result<Vec<u8>> {
    let code = client.wasm_by_hash(hash)?;
    let actual = wasm::wasm_hash(&code);
    if actual != hash {
        bail!("RPC returned Wasm with hash {actual}, expected {hash}");
    }
    Ok(code)
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn load_db(osv: &[PathBuf], only: Option<&str>) -> Result<AdvisoryDb> {
    let mut db = AdvisoryDb::bundled()?;
    for path in osv {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        db.add_osv_file_contents(&path.display().to_string(), &text)?;
    }
    if let Some(id) = only {
        let a = db.get(id).ok_or_else(|| {
            anyhow!("unknown advisory `{id}`; see `advisory-watch advisories list`")
        })?;
        if a.is_host_only() {
            bail!(
                "{} affects the Soroban host, not contract Wasm, so there is nothing to scan",
                a.id
            );
        }
        db = db.filtered(id).expect("checked above");
    }
    Ok(db)
}

fn read_wasm(path: &Path) -> Result<(Vec<u8>, WasmInfo)> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let info = wasm::analyze(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok((bytes, info))
}

fn print_json<T: serde::Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn scan(args: ScanArgs) -> Result<u8> {
    let db = load_db(&args.advisories.osv, args.advisories.advisory.as_deref())?;
    let mut targets = Vec::new();
    for path in &args.wasm {
        let (_, info) = read_wasm(path)?;
        targets.push(TargetReport::for_wasm(
            Source::File {
                path: path.display().to_string(),
            },
            &info,
            &db,
        ));
    }
    if !args.contract_id.is_empty() {
        let client = rpc_client(&args.network)?;
        for id in &args.contract_id {
            let inst = client.contract_instance(id)?;
            let source = Source::Contract {
                contract_id: id.clone(),
                network: args.network.network.name().into(),
                ledger: inst.latest_ledger,
            };
            match &inst.executable {
                Executable::StellarAsset => {
                    targets.push(TargetReport::for_stellar_asset(source, &db))
                }
                Executable::Wasm { hash } => {
                    let code = fetch_wasm(&client, hash)?;
                    let info = wasm::analyze(&code)?;
                    targets.push(TargetReport::for_wasm(source, &info, &db));
                }
                Executable::Unsupported { name } => {
                    bail!("{id} uses executable type `{name}`, which is not supported yet")
                }
            }
        }
    }
    let report = ScanReport::new(&db, targets);
    match args.output.format {
        Format::Json => print_json(&report)?,
        Format::Text => print!("{}", report.to_text()),
    }
    Ok(if args.output.fail_on.triggered(report.worst_status()) {
        EXIT_FAIL_ON
    } else {
        EXIT_OK
    })
}

fn report(args: ReportArgs) -> Result<u8> {
    let db = load_db(&args.advisories.osv, args.advisories.advisory.as_deref())?;
    let text = std::fs::read_to_string(&args.inventory)
        .with_context(|| format!("reading {}", args.inventory.display()))?;
    let is_csv = args
        .inventory
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
    let entries = inventory::parse(&text, is_csv)?;

    let mut by_hash: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut unsupported: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut sac = 0usize;
    for e in entries {
        match e.executable {
            Executable::StellarAsset => sac += 1,
            Executable::Wasm { hash } => by_hash.entry(hash).or_default().push(e.contract_id),
            Executable::Unsupported { name } => {
                unsupported.entry(name).or_default().push(e.contract_id)
            }
        }
    }

    if let Some(dir) = &args.wasm_dir {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let client = if args.offline || by_hash.is_empty() {
        None
    } else {
        let all_cached = args.wasm_dir.as_ref().is_some_and(|dir| {
            by_hash
                .keys()
                .all(|h| dir.join(format!("{h}.wasm")).is_file())
        });
        if all_cached {
            None
        } else {
            Some(rpc_client(&args.network)?)
        }
    };

    let progress = std::io::stderr().is_terminal();
    let total = by_hash.len();
    let mut groups = Vec::new();
    let mut errors = Vec::new();
    for (i, (hash, contracts)) in by_hash.into_iter().enumerate() {
        if progress {
            eprint!("\r[{}/{}] {}", i + 1, total, &hash[..12]);
        }
        let result = (|| -> Result<WasmInfo> {
            let cached = args
                .wasm_dir
                .as_ref()
                .map(|d| d.join(format!("{hash}.wasm")));
            let bytes = match &cached {
                Some(p) if p.is_file() => {
                    let b = std::fs::read(p)?;
                    if wasm::wasm_hash(&b) != hash {
                        bail!("cached file {} does not match its hash", p.display());
                    }
                    b
                }
                _ => {
                    let client = client
                        .as_ref()
                        .ok_or_else(|| anyhow!("not in --wasm-dir and --offline is set"))?;
                    let b = fetch_wasm(client, &hash)?;
                    if let Some(p) = &cached {
                        std::fs::write(p, &b)
                            .with_context(|| format!("writing {}", p.display()))?;
                    }
                    b
                }
            };
            Ok(wasm::analyze(&bytes)?)
        })();
        match result {
            Ok(info) => {
                let target = Target::Wasm(&info);
                let findings = matcher::evaluate(target, &db);
                groups.push(WasmGroup {
                    wasm_hash: hash,
                    contract_count: contracts.len(),
                    contracts,
                    sdk_version: info.sdk_version_raw.clone(),
                    status: matcher::overall_status(target, &findings),
                    findings,
                });
            }
            Err(e) => errors.push(WasmGroupError {
                wasm_hash: hash,
                contracts,
                error: format!("{e:#}"),
            }),
        }
    }
    if progress && total > 0 {
        eprintln!();
    }
    for (name, contracts) in unsupported {
        errors.push(WasmGroupError {
            wasm_hash: String::new(),
            contracts,
            error: format!("executable type `{name}` is not supported yet"),
        });
    }

    let report = NetworkReport::new(&db, args.advisories.advisory.clone(), groups, errors, sac);
    match args.output.format {
        Format::Json => print_json(&report)?,
        Format::Text => print!("{}", report.to_text()),
    }
    Ok(if args.output.fail_on.triggered(report.worst_status()) {
        EXIT_FAIL_ON
    } else {
        EXIT_OK
    })
}

fn meta(args: MetaArgs) -> Result<u8> {
    let info = if let Some(path) = &args.wasm {
        read_wasm(path)?.1
    } else {
        let id = args.contract_id.as_deref().expect("clap requires one");
        let client = rpc_client(&args.network)?;
        match client.contract_instance(id)?.executable {
            Executable::StellarAsset => {
                bail!("{id} is a Stellar Asset Contract; it has no Wasm or metadata")
            }
            Executable::Wasm { hash } => wasm::analyze(&fetch_wasm(&client, &hash)?)?,
            Executable::Unsupported { name } => {
                bail!("{id} uses executable type `{name}`, which is not supported yet")
            }
        }
    };
    match args.format {
        Format::Json => print_json(&info)?,
        Format::Text => {
            println!("wasm hash: {}", info.hash);
            println!("size:      {} bytes", info.size);
            if let Some(v) = info.interface_version {
                println!("protocol:  {}", v.protocol);
            }
            if info.meta.is_empty() {
                println!("contractmetav0: (none)");
            } else {
                println!("contractmetav0:");
                for e in &info.meta {
                    println!("  {} = {}", e.key, e.val);
                }
            }
            println!("host imports: {}", info.imports.len());
        }
    }
    Ok(EXIT_OK)
}

fn advisories(cmd: AdvisoriesCmd) -> Result<u8> {
    match cmd {
        AdvisoriesCmd::List { osv, format } => {
            let db = load_db(&osv, None)?;
            match format {
                Format::Json => print_json(&db.advisories)?,
                Format::Text => {
                    for a in &db.advisories {
                        let scope = if a.is_host_only() { "host" } else { "contract" };
                        println!(
                            "{:<20} {:<16} {:<9} {:<8} {}",
                            a.id,
                            a.aliases.first().map(String::as_str).unwrap_or("-"),
                            a.severity.as_deref().unwrap_or("-"),
                            scope,
                            a.crate_names().join(",")
                        );
                    }
                }
            }
        }
        AdvisoriesCmd::Show { id, osv, format } => {
            let db = load_db(&osv, None)?;
            let a = db
                .get(&id)
                .ok_or_else(|| anyhow!("unknown advisory `{id}`"))?;
            match format {
                Format::Json => print_json(a)?,
                Format::Text => {
                    println!("{} {}", a.id, a.aliases.join(" "));
                    println!("{}", a.summary);
                    println!("severity: {}", a.severity.as_deref().unwrap_or("-"));
                    println!(
                        "scope:    {}",
                        if a.is_host_only() { "host" } else { "contract" }
                    );
                    for p in &a.packages {
                        let ranges: Vec<String> = p
                            .ranges
                            .iter()
                            .map(|r| match (&r.fixed, &r.last_affected) {
                                (Some(f), _) => format!(">={}, <{}", r.introduced, f),
                                (None, Some(l)) => format!(">={}, <={}", r.introduced, l),
                                (None, None) => format!(">={}", r.introduced),
                            })
                            .collect();
                        println!("affected: {} {}", p.name, ranges.join(" | "));
                    }
                    if let Some(c) = &a.condition {
                        println!("condition: {}", c.trim());
                    }
                    println!("{}", a.url);
                }
            }
        }
    }
    Ok(EXIT_OK)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.cmd {
        Cmd::Scan(a) => scan(a),
        Cmd::Report(a) => report(a),
        Cmd::Meta(a) => meta(a),
        Cmd::Advisories { cmd } => advisories(cmd),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(EXIT_ERROR)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn fail_on_thresholds() {
        assert!(FailOn::Possible.triggered(Some(Status::Possible)));
        assert!(!FailOn::Possible.triggered(Some(Status::Unknown)));
        assert!(FailOn::Unknown.triggered(Some(Status::Unknown)));
        assert!(FailOn::Unknown.triggered(Some(Status::Possible)));
        assert!(!FailOn::Unknown.triggered(Some(Status::NotMatched)));
        assert!(!FailOn::Never.triggered(Some(Status::Possible)));
        assert!(!FailOn::Possible.triggered(None));
    }
}
