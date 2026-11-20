//! signafaide-verify <pack.json> --keys <file|url> --agent-keys <file|url> [--head head.json]
//!   [--content <dir|file>] [--timestamp-check <explorer API>] [--offline] [--json]
//!
//! signafaide-verify --version | --help
//!
//! Exit code 0 = PASS, 1 = FAIL, 2 = the inputs could not be read.

use signafaide_verify::{heights_in, is_loopback_url, verify_text, Inputs};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: signafaide-verify <pack.json> --keys <file|url> --agent-keys <file|url> [--head head.json] [--content <dir|file>] [--timestamp-check <explorer API URL>] [--offline] [--trust-embedded-keys] [--trust-embedded-agent-keys] [--json]\n       signafaide-verify --version | --help";
/// The SDK release this binary was built from (the release check compares it with the packages).
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Esplora-style API (`GET /block-height/{h}`, `GET /block/{hash}/header`); blockstream.info/api works too.
const DEFAULT_BITCOIN: &str = "https://mempool.space/api";

struct Args {
    pack: String,
    keys: Option<String>,
    agent_keys: Option<String>,
    head: Option<String>,
    trust_embedded: bool,
    trust_embedded_agent_keys: bool,
    content: Option<String>,
    bitcoin: String,
    offline: bool,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut it = std::env::args().skip(1);
    let mut a = Args {
        pack: String::new(),
        keys: None,
        agent_keys: None,
        head: None,
        trust_embedded: false,
        trust_embedded_agent_keys: false,
        content: None,
        bitcoin: DEFAULT_BITCOIN.into(),
        offline: false,
        json: false,
    };
    let mut pack = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--keys" => a.keys = Some(it.next().ok_or("--keys needs a file or URL")?),
            "--agent-keys" => {
                a.agent_keys = Some(
                    it.next()
                        .ok_or("--agent-keys needs a file or URL (from `signafaide keys export`)")?,
                )
            }
            "--head" => a.head = Some(it.next().ok_or("--head needs the client's .signafaide/head.json")?),
            "--content" => a.content = Some(it.next().ok_or("--content needs a directory or file")?),
            "--timestamp-check" | "--bitcoin" => {
                a.bitcoin = it
                    .next()
                    .ok_or("--timestamp-check needs an explorer API URL such as https://mempool.space/api")?
            }
            "--offline" => a.offline = true,
            "--trust-embedded-keys" => a.trust_embedded = true,
            "--trust-embedded-agent-keys" => a.trust_embedded_agent_keys = true,
            "--json" => a.json = true,
            "-h" | "--help" => {
                println!("signafaide-verify {VERSION}\n{USAGE}");
                std::process::exit(0);
            }
            "-V" | "--version" => {
                println!("signafaide-verify {VERSION}");
                std::process::exit(0);
            }
            s if s.starts_with('-') => return Err(format!("unknown option {s}\n{USAGE}")),
            s if pack.is_none() => pack = Some(s.to_string()),
            s => return Err(format!("unexpected argument {s}\n{USAGE}")),
        }
    }
    a.pack = pack.ok_or(USAGE)?;
    Ok(a)
}

fn read(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(15)))
        .max_redirects(0)
        .build()
        .into()
}

/// A file, or an http(s) URL, and whether it came over plain http. Plain http can be altered
/// in transit: it is accepted only from a loopback address, with a warning, and the keys then
/// do not count as independent.
fn fetch(flag: &str, src: &str) -> Result<(String, bool), String> {
    if src.starts_with("https://") || src.starts_with("http://") {
        let plain = src.starts_with("http://");
        if plain && !is_loopback_url(src) {
            return Err(format!("{flag} {src} uses plain http://, which anyone on the network path can alter; use https:// (plain http is accepted only from this machine, e.g. http://127.0.0.1)"));
        }
        if plain {
            eprintln!("WARNING: {flag} {src} uses plain http:// on this machine; the keys do not count as independent");
        }
        let mut resp = agent().get(src).call().map_err(|e| format!("{src}: {e}"))?;
        Ok((
            resp.body_mut().read_to_string().map_err(|e| format!("{src}: {e}"))?,
            plain,
        ))
    } else {
        Ok((read(src)?, false))
    }
}

/// Content from one file, or from every *.jsonl file under a directory
/// (for example `.signafaide/chain`). Files without records are skipped.
fn read_content(src: &str) -> Result<String, String> {
    let path = Path::new(src);
    if path.is_file() {
        return read(src);
    }
    let mut out = String::new();
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if matches!(p.extension().and_then(|e| e.to_str()), Some("jsonl")) {
                out += &read(&p.to_string_lossy())?;
                out.push('\n');
            }
        }
    }
    Ok(out)
}

/// Why a plain-http explorer is not asked (§7 check 11).
const PLAIN_HTTP_EXPLORER: &str =
    "the explorer URL uses plain http, which anyone on the network path can alter; use https";

/// The block hash at `height` and its raw 80-byte header (hex) from an Esplora-style API; the
/// core checks the header against the hash and its proof of work.
fn block_header(base: &str, height: u64) -> Result<(String, String), String> {
    let base = base.trim_end_matches('/');
    let get = |url: String| -> Result<String, String> {
        let mut r = agent().get(&url).call().map_err(|e| format!("{url}: {e}"))?;
        r.body_mut()
            .with_config()
            .limit(1 << 16)
            .read_to_string()
            .map_err(|e| format!("{url}: {e}"))
    };
    let hash = get(format!("{base}/block-height/{height}"))?.trim().to_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("{base}: no block at height {height}"));
    }
    let header = get(format!("{base}/block/{hash}/header"))?.trim().to_lowercase();
    Ok((hash, header))
}

fn run() -> Result<bool, String> {
    let args = parse_args()?;
    let pack = read(&args.pack)?;
    let (keys, keys_plain_http) = match args.keys.as_deref().map(|k| fetch("--keys", k)).transpose()? {
        Some((k, plain)) => (Some(k), plain),
        None => (None, false),
    };
    let (agent_keys, agent_keys_plain_http) = match args
        .agent_keys
        .as_deref()
        .map(|k| fetch("--agent-keys", k))
        .transpose()?
    {
        Some((k, plain)) => (Some(k), plain),
        None => (None, false),
    };
    if agent_keys.is_none() && !args.trust_embedded_agent_keys {
        eprintln!("signafaide-verify: no --agent-keys: check 3 fails as NOT INDEPENDENT. Ask the customer for `signafaide keys export -o agent-keys.json` and pass --agent-keys agent-keys.json");
    }
    let head = args.head.as_deref().map(read).transpose()?;
    let content = args.content.as_deref().map(read_content).transpose()?;
    let plain = args.bitcoin.starts_with("http://");
    if plain && !args.offline {
        eprintln!("WARNING: --timestamp-check {} uses plain http://, which anyone on the network path can alter: public timestamps are not checked; use https://", args.bitcoin);
    }
    let bitcoin = (!args.offline).then(|| {
        heights_in(&pack)
            .into_iter()
            .map(|h| {
                (
                    h,
                    if plain {
                        Err(PLAIN_HTTP_EXPLORER.to_string())
                    } else {
                        block_header(&args.bitcoin, h)
                    },
                )
            })
            .collect::<BTreeMap<_, _>>()
    });
    let inputs = Inputs {
        keys: keys.as_deref(),
        trust_embedded_keys: args.trust_embedded,
        agent_keys: agent_keys.as_deref(),
        trust_embedded_agent_keys: args.trust_embedded_agent_keys,
        head: head.as_deref(),
        contents: content.as_deref(),
        bitcoin,
        keys_plain_http,
        agent_keys_plain_http,
    };
    let report = verify_text(&pack, &inputs).map_err(|e| e.0)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report).expect("report serializes"));
    } else {
        print!("{}", report.to_text());
    }
    Ok(report.passed())
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("signafaide-verify: {e}");
            ExitCode::from(2)
        }
    }
}
