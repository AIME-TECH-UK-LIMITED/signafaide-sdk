//! SHA-256 and the 32-byte hash type, written as 64 lowercase hex characters.

use crate::{bail, jcs, Error, Result};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash(pub [u8; 32]);

pub fn sha256(data: &[u8]) -> Hash {
    Hash(Sha256::digest(data).into())
}

/// `sha256(JCS(value))`, the hash used for content, envelopes, batches, heads and anchors.
pub fn hash_json<T: Serialize + ?Sized>(value: &T) -> Result<Hash> {
    let v = serde_json::to_value(value).map_err(|e| Error::new(e.to_string()))?;
    Ok(sha256(jcs::canonicalize(&v)?.as_bytes()))
}

impl Hash {
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Strict parse: exactly 64 lowercase hex characters.
    pub fn from_hex(s: &str) -> Result<Hash> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            bail!("expected 64 lowercase hex characters");
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|e| Error::new(e.to_string()))?;
        Ok(Hash(out))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", self.hex())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Hash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}
