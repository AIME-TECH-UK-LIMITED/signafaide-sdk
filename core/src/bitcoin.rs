//! Bitcoin block headers for §7 check 11: an explorer's 80-byte header is trusted only when it
//! hashes to the block hash the explorer gave for that height and meets its own proof of work.

use crate::sha256;

/// What an explorer returned for one height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// The block hash as explorers show it (display byte order, hex).
    pub hash: String,
    /// The raw 80-byte header.
    pub header: Vec<u8>,
}

fn sha256d(b: &[u8]) -> [u8; 32] {
    sha256(&sha256(b).0).0
}

/// The 256-bit target (big-endian) of a compact `nBits`; `None` when it is negative, zero or overflows.
pub fn target(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as i32;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 {
        return None;
    }
    let mut t = [0u8; 32];
    for i in 0..3i32 {
        let byte = ((mantissa >> (8 * i)) & 0xff) as u8;
        let pos = i + exponent - 3; // byte position from the least significant end
        if pos < 0 {
            continue;
        }
        if pos >= 32 {
            if byte != 0 {
                return None;
            }
            continue;
        }
        t[31 - pos as usize] = byte;
    }
    t.iter().any(|&b| b != 0).then_some(t)
}

/// Check a header against the block hash it was served for and its own proof of work.
/// Returns its Merkle root in header (internal) byte order, or why the header is not trusted.
pub fn check_header(h: &BlockHeader) -> Result<[u8; 32], String> {
    if h.header.len() != 80 {
        return Err(format!("the block header is {} bytes, not 80", h.header.len()));
    }
    let mut id = sha256d(&h.header);
    id.reverse(); // display order = the hash as a big-endian number
    if hex::encode(id) != h.hash.to_ascii_lowercase() {
        return Err(format!("the block header does not hash to block {}", h.hash));
    }
    let bits = u32::from_le_bytes(h.header[72..76].try_into().unwrap());
    let Some(t) = target(bits) else {
        return Err(format!("the block header's nBits {bits:#010x} is not a valid target"));
    };
    if id > t {
        return Err(format!("block {} does not meet the proof of work its header claims", h.hash));
    }
    Ok(h.header[36..68].try_into().unwrap())
}

/// Mine a header (for test vectors only): the given Merkle root, the easiest target (regtest
/// nBits 0x207fffff), and the first nonce that meets it.
pub fn mine_header(merkle_root: &[u8; 32], time: u32) -> BlockHeader {
    let mut header = vec![0u8; 80];
    header[0..4].copy_from_slice(&0x2000_0000u32.to_le_bytes());
    header[4..36].copy_from_slice(&sha256(b"previous block").0);
    header[36..68].copy_from_slice(merkle_root);
    header[68..72].copy_from_slice(&time.to_le_bytes());
    header[72..76].copy_from_slice(&0x207f_ffffu32.to_le_bytes());
    let t = target(0x207f_ffff).unwrap();
    for nonce in 0u32.. {
        header[76..80].copy_from_slice(&nonce.to_le_bytes());
        let mut id = sha256d(&header);
        id.reverse();
        if id <= t {
            return BlockHeader { hash: hex::encode(id), header };
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_block() {
        // Bitcoin's genesis block header.
        let header = hex::decode("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c").unwrap();
        let h = BlockHeader { hash: "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".into(), header };
        let root = check_header(&h).unwrap();
        let mut display = root;
        display.reverse();
        assert_eq!(hex::encode(display), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        let mut bad = h.clone();
        bad.header[79] ^= 1;
        assert!(check_header(&bad).is_err());
        assert_eq!(target(0x1d00ffff).unwrap()[4..6], [0xff, 0xff]);
        assert!(target(0x04800000).is_none() && target(0x23000001).is_none());
    }

    #[test]
    fn mined_header_checks() {
        let h = mine_header(&[7; 32], 1_700_000_000);
        assert_eq!(check_header(&h).unwrap(), [7; 32]);
    }
}
