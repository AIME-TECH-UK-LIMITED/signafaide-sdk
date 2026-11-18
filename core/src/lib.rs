//! signafAIde protocol v1 (see `spec/SPEC.md`).
//!
//! Everything a verifier needs, with no I/O: canonical JSON (RFC 8785), SHA-256,
//! domain-separated Ed25519, the RFC 6962 Merkle tree, the typed protocol objects,
//! an OpenTimestamps proof codec, drand quicknet verification and the §7 pack verifier.

pub mod bitcoin;
pub mod checks;
pub mod confusables_letters;
pub mod coverage;
pub mod drand;
pub mod hash;
pub mod jcs;
pub mod merkle;
pub mod model;
pub mod ots;
pub mod sign;
pub mod time;
pub mod verify;
pub mod vectors;

pub use hash::{sha256, Hash};
pub use model::*;

/// `1 record`, `2 records`: a count with its noun in the right number. The one plural helper
/// for the verifier and the service.
pub fn plural(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// One error type for the whole crate: a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl Error {
    pub fn new(msg: impl Into<String>) -> Self {
        Error(msg.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

macro_rules! bail {
    ($($arg:tt)*) => { return Err($crate::Error(format!($($arg)*))) };
}
pub(crate) use bail;
