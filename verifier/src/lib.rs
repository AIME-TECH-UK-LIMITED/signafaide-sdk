//! signafAIde pack verification for the CLI and, behind the `wasm` feature, for browsers.

pub use signafaide_core::verify::{
    agent_keys_from_text, bitcoin_heights, block_header_from_hex, contents_from_text, heads_from_text, verify_pack, Bitcoin, Check, Options, Report, Status,
};
use signafaide_core::{from_value, Error, KeyEntry, KeysDocument, Result};
use std::collections::BTreeMap;

/// Parse a keys document: `{"keys":[...]}` as served at `/.well-known/signafaide-keys.json`.
pub fn parse_keys(text: &str) -> Result<Vec<KeyEntry>> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| Error::new(format!("keys: {e}")))?;
    let keys = from_value::<KeysDocument>(&v).map_err(|e| Error::new(format!("keys: {e}")))?.keys;
    for k in &keys {
        k.validate().map_err(|e| Error::new(format!("keys: {e}")))?;
    }
    Ok(keys)
}

/// Text inputs besides the pack.
#[derive(Default)]
pub struct Inputs<'a> {
    pub keys: Option<&'a str>,
    pub trust_embedded_keys: bool,
    pub agent_keys: Option<&'a str>,
    pub trust_embedded_agent_keys: bool,
    pub head: Option<&'a str>,
    pub contents: Option<&'a str>,
    /// `None`: offline. `Some`: height -> (block hash, raw header hex) as an explorer served
    /// them, or why they could not be fetched.
    pub bitcoin: Option<BTreeMap<u64, std::result::Result<(String, String), String>>>,
    /// `keys` came over plain http from a local address (not independent).
    pub keys_plain_http: bool,
    /// `agent_keys` came over plain http from a local address (not independent).
    pub agent_keys_plain_http: bool,
}

/// True for `localhost` and loopback addresses: the only hosts plain http is accepted from.
pub fn is_loopback_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
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
    let pack: serde_json::Value = serde_json::from_str(pack).map_err(|e| Error::new(format!("pack is not JSON: {e}")))?;
    let bitcoin = match &inputs.bitcoin {
        None => Bitcoin::Offline,
        Some(m) => Bitcoin::Checked(m.iter().map(|(h, r)| (*h, r.clone().and_then(|(hash, header)| block_header_from_hex(&hash, &header)))).collect()),
    };
    let opts = Options {
        service_keys: inputs.keys.map(parse_keys).transpose()?,
        trust_embedded_keys: inputs.trust_embedded_keys,
        agent_keys: inputs.agent_keys.map(agent_keys_from_text).transpose()?,
        trust_embedded_agent_keys: inputs.trust_embedded_agent_keys,
        heads: inputs.head.map(heads_from_text).transpose()?,
        bitcoin,
        contents: inputs.contents.map(contents_from_text).transpose()?.unwrap_or_default(),
        service_keys_plain_http: inputs.keys_plain_http,
        agent_keys_plain_http: inputs.agent_keys_plain_http,
        by_service: false,
    };
    verify_pack(&pack, &opts)
}

/// Browser entry point: returns the report as JSON, or throws with the reason. `bitcoin` is a
/// JSON object of height -> `{hash, header}` (hex) the page fetched over https, or absent for offline.
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
) -> Result<String, wasm_bindgen::JsValue> {
    let run = || -> Result<Report> {
        let bitcoin = match bitcoin.as_deref() {
            None => None,
            Some(b) => {
                let m: BTreeMap<String, BTreeMap<String, String>> =
                    serde_json::from_str(b).map_err(|e| Error::new(format!("bitcoin: {e} (height -> {{hash, header}})")))?;
                Some(
                    m.into_iter()
                        .map(|(h, r)| {
                            let height = h.parse::<u64>().map_err(|_| Error::new("bitcoin: heights are integers"))?;
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
        let inputs = Inputs {
            keys: keys.as_deref(),
            trust_embedded_keys,
            agent_keys: agent_keys.as_deref(),
            trust_embedded_agent_keys,
            head: head.as_deref(),
            contents: contents.as_deref(),
            bitcoin,
            ..Default::default()
        };
        verify_text(pack, &inputs)
    };
    run().map(|r| serde_json::to_string(&r).expect("report serializes")).map_err(|e| wasm_bindgen::JsValue::from_str(&e.0))
}

/// The Bitcoin heights claimed by the anchors in pack text (empty when it is not JSON).
pub fn heights_in(pack: &str) -> Vec<u64> {
    serde_json::from_str(pack).map(|v| bitcoin_heights(&v)).unwrap_or_default()
}
