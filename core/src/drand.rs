//! drand quicknet (`bls-unchained-g1-rfc9380`, 3-second rounds).

use crate::Drand;
#[cfg(feature = "drand")]
use sha2::Digest;

pub const QUICKNET_CHAIN: &str = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
pub const QUICKNET_PUBLIC_KEY: &str = "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a";
pub const QUICKNET_GENESIS: i64 = 1_692_803_367;
pub const QUICKNET_PERIOD: i64 = 3;

/// A batch's drand round may be at most this old at its `server_time` (§3.1).
pub const MAX_ROUND_AGE_MS: i64 = 120_000;

/// The highest round whose publication time is a protocol time (at most 9999-12-31T23:59:59Z).
pub const MAX_ROUND: u64 = ((253_402_300_799 - QUICKNET_GENESIS) / QUICKNET_PERIOD + 1) as u64;

/// Unix time (seconds) at which `round` was published; `None` outside 1..=MAX_ROUND.
pub fn round_time(round: u64) -> Option<i64> {
    (1..=MAX_ROUND)
        .contains(&round)
        .then(|| QUICKNET_GENESIS + (round as i64 - 1) * QUICKNET_PERIOD)
}

/// §3.1: a batch is written no earlier than its round's publication and at most
/// `MAX_ROUND_AGE_MS` after it. `Err` says which bound is broken.
pub fn check_round_time(server_time_ms: i64, round: u64) -> Result<(), String> {
    let Some(published) = round_time(round).map(|s| s * 1000) else {
        return Err(format!("drand round {round} is out of range (1 to {MAX_ROUND})"));
    };
    if server_time_ms < published {
        return Err(format!(
            "server_time {} is before drand round {round} was published at {}",
            crate::time::format(server_time_ms),
            crate::time::format(published)
        ));
    }
    if server_time_ms - published > MAX_ROUND_AGE_MS {
        return Err(format!(
            "drand round {round} is {} s older than server_time; at most {} s is allowed",
            (server_time_ms - published) / 1000,
            MAX_ROUND_AGE_MS / 1000
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconCheck {
    Valid,
    Invalid(String),
    /// Built without BLS support: never reported as a pass.
    NotChecked,
}

/// Verify a quicknet beacon: the chain, the BLS signature over the round, and
/// `randomness = sha256(signature)`.
pub fn verify_beacon(d: &Drand) -> BeaconCheck {
    if d.chain != QUICKNET_CHAIN {
        return BeaconCheck::Invalid(format!("unknown drand chain {}", d.chain));
    }
    verify_bls(d)
}

#[cfg(feature = "drand")]
fn verify_bls(d: &Drand) -> BeaconCheck {
    use drand_verify::{G2PubkeyRfc, Pubkey};
    let Ok(sig) = hex::decode(&d.signature) else {
        return BeaconCheck::Invalid("signature is not hex".into());
    };
    let pk: [u8; 96] = hex::decode(QUICKNET_PUBLIC_KEY).unwrap().try_into().unwrap();
    let pk = G2PubkeyRfc::from_fixed_unchecked(pk).expect("quicknet public key");
    match pk.verify(d.round, b"", &sig) {
        Ok(true) => {}
        Ok(false) => return BeaconCheck::Invalid(format!("BLS signature does not verify for round {}", d.round)),
        Err(e) => return BeaconCheck::Invalid(e.to_string()),
    }
    if hex::encode(sha2::Sha256::digest(&sig)) != d.randomness {
        return BeaconCheck::Invalid("randomness is not sha256(signature)".into());
    }
    BeaconCheck::Valid
}

#[cfg(not(feature = "drand"))]
fn verify_bls(_: &Drand) -> BeaconCheck {
    BeaconCheck::NotChecked
}

#[cfg(all(test, feature = "drand"))]
mod tests {
    use super::*;

    pub fn round_123() -> Drand {
        let signature =
            "b75c69d0b72a5d906e854e808ba7e2accb1542ac355ae486d591aa9d43765482e26cd02df835d3546d23c4b13e0dfc92";
        Drand {
            chain: QUICKNET_CHAIN.into(),
            round: 123,
            randomness: hex::encode(sha2::Sha256::digest(hex::decode(signature).unwrap())),
            signature: signature.into(),
        }
    }

    #[test]
    fn quicknet_round_123() {
        assert_eq!(verify_beacon(&round_123()), BeaconCheck::Valid);
        let mut bad = round_123();
        bad.round = 124;
        assert!(matches!(verify_beacon(&bad), BeaconCheck::Invalid(_)));
    }
}
