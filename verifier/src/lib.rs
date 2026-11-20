//! signafAIde pack verification for the CLI and, behind the `wasm` feature, for browsers.

pub use signafaide_core::verify::{
    agent_keys_from_text, bitcoin_heights, block_header_from_hex, clean_line, contents_from_text, heads_from_text,
    verify_pack, Bitcoin, Check, Options, Report, Status,
};
use signafaide_core::{from_value, Error, KeyEntry, KeysDocument, Result};
use std::collections::BTreeMap;

/// Bitcoin block headers by height: (block hash, raw header hex), or why they could not be fetched.
pub type BitcoinHeaders = BTreeMap<u64, std::result::Result<(String, String), String>>;

/// Parse a keys document: `{"keys":[...], "revoked"?: [{"key_id", ...}]}` as served at
/// `/.well-known/signafaide-keys.json` (§5). Each key is checked; a revoked entry needs only its
/// `key_id` (other fields are ignored).
pub fn parse_keys_document(text: &str) -> Result<KeysDocument> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| Error::new(format!("keys: {e}")))?;
    let doc = from_value::<KeysDocument>(&v).map_err(|e| Error::new(format!("keys: {e}")))?;
    for k in &doc.keys {
        k.validate().map_err(|e| Error::new(format!("keys: {e}")))?;
    }
    Ok(doc)
}

/// The one service-key loader: the whole key list (every key, revoked ones too, as the anchors'
/// `keys_hash` covers them) and the ids of the revoked keys (no signature by one of them verifies).
pub fn load_service_keys(text: &str) -> Result<(Vec<KeyEntry>, Vec<String>)> {
    signafaide_core::keyset::load(text)
}

/// The whole key list of a keys document (revoked keys included).
pub fn parse_keys(text: &str) -> Result<Vec<KeyEntry>> {
    Ok(parse_keys_document(text)?.keys)
}

/// Text inputs besides the pack.
#[derive(Default)]
pub struct Inputs<'a> {
    pub keys: Option<&'a str>,
    pub trust_embedded_keys: bool,
    /// Revoked service key ids applied besides the ones `keys` lists: the release's pinned
    /// revocations when the keys come from the pack (`--trust-embedded-keys`, spec §7).
    pub revoked: Vec<String>,
    pub agent_keys: Option<&'a str>,
    pub trust_embedded_agent_keys: bool,
    pub head: Option<&'a str>,
    /// Local content files (§7 check 12), each JSON lines or one JSON array; a later file wins.
    pub contents: Vec<&'a str>,
    /// `None`: offline. `Some`: height -> (block hash, raw header hex) as an explorer served
    /// them, or why they could not be fetched.
    pub bitcoin: Option<BitcoinHeaders>,
    /// `keys` came over plain http from a local address (not independent).
    pub keys_plain_http: bool,
    /// `agent_keys` came over plain http from a local address (not independent).
    pub agent_keys_plain_http: bool,
}

/// True for `localhost` and loopback addresses: the only hosts plain http is accepted from.
pub fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.contains('@') {
        return false;
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Verify pack text with the inputs as text.
pub fn verify_text(pack: &str, inputs: &Inputs) -> Result<Report> {
    let pack: serde_json::Value =
        serde_json::from_str(pack).map_err(|e| Error::new(format!("pack is not JSON: {e}")))?;
    let bitcoin = match &inputs.bitcoin {
        None => Bitcoin::Offline,
        Some(m) => Bitcoin::Checked(
            m.iter()
                .map(|(h, r)| {
                    (
                        *h,
                        r.clone()
                            .and_then(|(hash, header)| block_header_from_hex(&hash, &header)),
                    )
                })
                .collect(),
        ),
    };
    let (service_keys, mut revoked_service_keys) = match inputs.keys.map(load_service_keys).transpose()? {
        Some((keys, revoked)) => (Some(keys), revoked),
        None => (None, Vec::new()),
    };
    for id in &inputs.revoked {
        if !revoked_service_keys.contains(id) {
            revoked_service_keys.push(id.clone());
        }
    }
    let opts = Options {
        service_keys,
        revoked_service_keys,
        trust_embedded_keys: inputs.trust_embedded_keys,
        agent_keys: inputs.agent_keys.map(agent_keys_from_text).transpose()?,
        trust_embedded_agent_keys: inputs.trust_embedded_agent_keys,
        heads: inputs.head.map(heads_from_text).transpose()?,
        bitcoin,
        contents: {
            let mut all = std::collections::HashMap::new();
            for text in &inputs.contents {
                all.extend(contents_from_text(text)?);
            }
            all
        },
        service_keys_plain_http: inputs.keys_plain_http,
        agent_keys_plain_http: inputs.agent_keys_plain_http,
        by_service: false,
    };
    verify_pack(&pack, &opts)
}

/// Browser entry point: returns the report as JSON, or throws with the reason. `bitcoin` is a
/// JSON object of height -> `{hash, header}` (hex) the page fetched over https, or absent for offline.
/// `revoked` is a JSON list of revoked service key ids applied besides the keys document's: the
/// page's pinned ones (spec §5, §7), whatever the keys' source.
#[cfg(feature = "wasm")]
#[wasm_bindgen::prelude::wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn verify(
    pack: &str,
    keys: Option<String>,
    trust_embedded_keys: bool,
    agent_keys: Option<String>,
    trust_embedded_agent_keys: bool,
    head: Option<String>,
    contents: Option<String>,
    bitcoin: Option<String>,
    revoked: Option<String>,
) -> Result<String, wasm_bindgen::JsValue> {
    let run = || -> Result<Report> {
        let bitcoin = match bitcoin.as_deref() {
            None => None,
            Some(b) => {
                let m: BTreeMap<String, BTreeMap<String, String>> = serde_json::from_str(b)
                    .map_err(|e| Error::new(format!("bitcoin: {e} (height -> {{hash, header}})")))?;
                Some(
                    m.into_iter()
                        .map(|(h, r)| {
                            let height = h
                                .parse::<u64>()
                                .map_err(|_| Error::new("bitcoin: heights are integers"))?;
                            let got = match (r.get("hash"), r.get("header")) {
                                (Some(hash), Some(header)) => Ok((hash.clone(), header.clone())),
                                _ => Err(r.get("error").cloned().unwrap_or_else(|| "no block header".into())),
                            };
                            Ok((height, got))
                        })
                        .collect::<Result<_>>()?,
                )
            }
        };
        let revoked: Vec<String> = match revoked.as_deref() {
            None => Vec::new(),
            Some(r) => serde_json::from_str(r).map_err(|e| Error::new(format!("revoked: {e} (a list of key ids)")))?,
        };
        let inputs = Inputs {
            keys: keys.as_deref(),
            trust_embedded_keys,
            revoked,
            agent_keys: agent_keys.as_deref(),
            trust_embedded_agent_keys,
            head: head.as_deref(),
            contents: contents.as_deref().into_iter().collect(),
            bitcoin,
            ..Default::default()
        };
        verify_text(pack, &inputs)
    };
    run()
        .map(|r| serde_json::to_string(&r).expect("report serializes"))
        .map_err(|e| wasm_bindgen::JsValue::from_str(&e.0))
}

/// The Bitcoin heights claimed by the anchors in pack text (empty when it is not JSON).
pub fn heights_in(pack: &str) -> Vec<u64> {
    serde_json::from_str(pack)
        .map(|v| bitcoin_heights(&v))
        .unwrap_or_default()
}
