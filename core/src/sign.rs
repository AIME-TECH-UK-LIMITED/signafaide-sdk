//! Ed25519 with domain separation (§1): the signed message is `signafaide/v1/<domain>\n`
//! followed by the 32 raw bytes of the hash being signed.

use crate::{bail, sha256, Error, Hash, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Record,
    Batch,
    Head,
    Anchor,
    /// Proof of possession: the new agent key signs its own registration (§2.4).
    Register,
    /// Rotation: an active agent key signs a new key's registration (§2.4).
    Rotate,
    /// Self-signature of an entry in an exported agent-key manifest (§2.5).
    AgentKey,
    /// The service's export statement over a verification pack (§7).
    Export,
    /// A client's local draft, before its project is known (§8); never sent to the service.
    Draft,
    /// The witness's ruling on a strict decision (§3.5).
    Ruling,
    /// A published rule set version (§10.2).
    Rules,
    /// An update or snapshot of the shared fingerprint list (§11.2).
    Fingerprints,
}

impl Domain {
    pub fn as_str(self) -> &'static str {
        match self {
            Domain::Record => "record",
            Domain::Batch => "batch",
            Domain::Head => "head",
            Domain::Anchor => "anchor",
            Domain::Register => "register",
            Domain::Rotate => "rotate",
            Domain::AgentKey => "agent_key",
            Domain::Export => "export",
            Domain::Draft => "draft",
            Domain::Ruling => "ruling",
            Domain::Rules => "rules",
            Domain::Fingerprints => "fingerprints",
        }
    }
}

/// The exact bytes that are signed for `hash` under `domain`.
pub fn message(domain: Domain, hash: &Hash) -> Vec<u8> {
    let mut m = format!("signafaide/v1/{}\n", domain.as_str()).into_bytes();
    m.extend_from_slice(&hash.0);
    m
}

pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|_| Error::new("not base64url without padding"))
}

/// Key id: the first 16 hex characters of SHA-256(raw public key).
pub fn key_id(public_key: &[u8; 32]) -> String {
    sha256(public_key).hex()[..16].to_string()
}

/// A signing key built from a 32-byte seed.
#[derive(Clone)]
pub struct Keypair(SigningKey);

impl Keypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Keypair(SigningKey::from_bytes(seed))
    }

    /// From a base64url (no padding) 32-byte seed, the `SIGNAFAIDE_SERVICE_KEY` format.
    pub fn from_seed_b64(s: &str) -> Result<Self> {
        let bytes = b64url_decode(s.trim())?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| Error::new("seed must be 32 bytes"))?;
        Ok(Self::from_seed(&seed))
    }

    pub fn seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    pub fn public_key_b64(&self) -> String {
        b64url(&self.public_key())
    }

    pub fn key_id(&self) -> String {
        key_id(&self.public_key())
    }

    /// base64url signature over `domain` and `hash`.
    pub fn sign(&self, domain: Domain, hash: &Hash) -> String {
        b64url(&self.0.sign(&message(domain, hash)).to_bytes())
    }
}

/// Decode a base64url public key, rejecting anything that is not a valid 32-byte point.
pub fn parse_public_key(public_key_b64: &str) -> Result<[u8; 32]> {
    let raw: [u8; 32] = b64url_decode(public_key_b64)?
        .try_into()
        .map_err(|_| Error::new("public key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&raw).map_err(|_| Error::new("public key is not a valid Ed25519 point"))?;
    if vk.is_weak() {
        bail!("public key is a weak (small-order) Ed25519 point");
    }
    Ok(raw)
}

/// Verify a base64url signature (strict RFC 8032 verification).
pub fn verify(public_key_b64: &str, domain: Domain, hash: &Hash, sig_b64: &str) -> Result<()> {
    let raw = parse_public_key(public_key_b64)?;
    let vk = VerifyingKey::from_bytes(&raw).expect("checked");
    let sig_bytes: [u8; 64] = b64url_decode(sig_b64)?
        .try_into()
        .map_err(|_| Error::new("signature must be 64 bytes"))?;
    vk.verify_strict(&message(domain, hash), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| Error::new(format!("signature does not verify for domain '{}'", domain.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domains_are_separated() {
        let k = Keypair::from_seed(&[7; 32]);
        let h = sha256(b"x");
        let sig = k.sign(Domain::Record, &h);
        verify(&k.public_key_b64(), Domain::Record, &h, &sig).unwrap();
        for d in [
            Domain::Batch,
            Domain::Head,
            Domain::Anchor,
            Domain::Register,
            Domain::Rotate,
            Domain::AgentKey,
            Domain::Export,
            Domain::Draft,
            Domain::Ruling,
            Domain::Rules,
            Domain::Fingerprints,
        ] {
            assert!(verify(&k.public_key_b64(), d, &h, &sig).is_err());
        }
        assert_eq!(k.key_id().len(), 16);
    }
}
