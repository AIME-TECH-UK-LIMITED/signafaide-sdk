//! OpenTimestamps proof codec (the `.ots` detached-timestamp format).
//!
//! Parses and serializes proofs, replays their operations, merges upgrades fetched from a
//! calendar, and reports what the proof itself attests. It does not contact Bitcoin: a
//! Bitcoin attestation names a block height whose header the caller may check separately.

use crate::{bail, Error, Result};
use sha2::Digest;

pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
const TAG_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const TAG_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
const MAX_MSG: usize = 4096;
const MAX_DEPTH: usize = 256;
/// Limits over the whole proof (§4), so a hostile proof cannot exhaust memory: real proofs
/// are a few kilobytes with a few hundred operations.
pub const MAX_PROOF_BYTES: usize = 65_536;
pub const MAX_NODES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha1 => 0x02,
            Op::Ripemd160 => 0x03,
            Op::Sha256 => 0x08,
            Op::Keccak256 => 0x67,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1,
            Op::Reverse => 0xf2,
            Op::Hexlify => 0xf3,
        }
    }

    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let out = match self {
            Op::Sha1 => sha1::Sha1::digest(msg).to_vec(),
            Op::Ripemd160 => ripemd::Ripemd160::digest(msg).to_vec(),
            Op::Sha256 => sha2::Sha256::digest(msg).to_vec(),
            Op::Keccak256 => sha3::Keccak256::digest(msg).to_vec(),
            Op::Append(arg) => [msg, arg].concat(),
            Op::Prepend(arg) => [arg, msg].concat(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => hex::encode(msg).into_bytes(),
        };
        if out.len() > MAX_MSG {
            bail!("ots: operation result longer than {MAX_MSG} bytes");
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attestation {
    Bitcoin { height: u64 },
    Pending { uri: String },
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

/// A timestamp tree: the message at this node, its attestations and the operations leading on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timestamp {
    pub msg: Vec<u8>,
    pub attestations: Vec<Attestation>,
    pub ops: Vec<(Op, Timestamp)>,
}

/// What a proof attests, without contacting Bitcoin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OtsStatus {
    /// Lowest Bitcoin block height attested anywhere in the proof.
    Confirmed(u64),
    /// Only calendar promises so far.
    Pending,
    /// No attestation at all.
    Empty,
}

/// A detached `.ots` file for a SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetachedFile {
    pub digest: [u8; 32],
    pub timestamp: Timestamp,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    /// Operations and attestations read so far (capped at MAX_NODES).
    nodes: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Result<Reader<'a>> {
        if data.len() > MAX_PROOF_BYTES {
            bail!("ots: proof is longer than {MAX_PROOF_BYTES} bytes");
        }
        Ok(Reader { data, pos: 0, nodes: 0 })
    }

    fn node(&mut self) -> Result<()> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            bail!("ots: proof has more than {MAX_NODES} operations and attestations");
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(|| Error::new("ots: unexpected end of proof"))?;
        self.pos += 1;
        Ok(b)
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.data.len() - self.pos < n {
            bail!("ots: unexpected end of proof");
        }
        self.pos += n;
        Ok(&self.data[self.pos - n..self.pos])
    }

    fn varuint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        bail!("ots: varuint too long")
    }

    fn varbytes(&mut self, max: usize) -> Result<&'a [u8]> {
        let n = self.varuint()? as usize;
        if n > max {
            bail!("ots: field longer than {max} bytes");
        }
        self.bytes(n)
    }
}

fn write_varuint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

fn write_varbytes(out: &mut Vec<u8>, b: &[u8]) {
    write_varuint(out, b.len() as u64);
    out.extend_from_slice(b);
}

impl Attestation {
    fn read(r: &mut Reader) -> Result<Attestation> {
        let tag: [u8; 8] = r.bytes(8)?.try_into().unwrap();
        let payload = r.varbytes(8192)?;
        let mut p = Reader { data: payload, pos: 0, nodes: 0 };
        Ok(match tag {
            TAG_BITCOIN => Attestation::Bitcoin { height: p.varuint()? },
            TAG_PENDING => {
                let uri = std::str::from_utf8(p.varbytes(1000)?).map_err(|_| Error::new("ots: calendar URI is not UTF-8"))?;
                if !uri.bytes().all(|c| c.is_ascii_alphanumeric() || b"-.:/_".contains(&c)) {
                    bail!("ots: calendar URI has invalid characters");
                }
                Attestation::Pending { uri: uri.to_string() }
            }
            _ => Attestation::Unknown { tag, payload: payload.to_vec() },
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        let mut payload = Vec::new();
        let tag = match self {
            Attestation::Bitcoin { height } => {
                write_varuint(&mut payload, *height);
                TAG_BITCOIN
            }
            Attestation::Pending { uri } => {
                write_varbytes(&mut payload, uri.as_bytes());
                TAG_PENDING
            }
            Attestation::Unknown { tag, payload: p } => {
                payload.extend_from_slice(p);
                *tag
            }
        };
        out.extend_from_slice(&tag);
        write_varbytes(out, &payload);
    }
}

impl Timestamp {
    pub fn new(msg: Vec<u8>) -> Timestamp {
        Timestamp { msg, attestations: Vec::new(), ops: Vec::new() }
    }

    /// Parse a serialized timestamp that starts from `msg` (also the body a calendar returns).
    pub fn parse(data: &[u8], msg: &[u8]) -> Result<Timestamp> {
        let mut r = Reader::new(data)?;
        let t = Self::read(&mut r, msg.to_vec(), 0)?;
        if r.pos != data.len() {
            bail!("ots: trailing bytes after timestamp");
        }
        Ok(t)
    }

    fn read(r: &mut Reader, msg: Vec<u8>, depth: usize) -> Result<Timestamp> {
        if depth > MAX_DEPTH {
            bail!("ots: proof nested too deeply");
        }
        let mut t = Timestamp::new(msg);
        loop {
            let mut tag = r.byte()?;
            let fork = tag == 0xff;
            if fork {
                tag = r.byte()?;
            }
            r.node()?;
            if tag == 0x00 {
                t.attestations.push(Attestation::read(r)?);
            } else {
                let op = match tag {
                    0x02 => Op::Sha1,
                    0x03 => Op::Ripemd160,
                    0x08 => Op::Sha256,
                    0x67 => Op::Keccak256,
                    0xf0 => Op::Append(r.varbytes(MAX_MSG)?.to_vec()),
                    0xf1 => Op::Prepend(r.varbytes(MAX_MSG)?.to_vec()),
                    0xf2 => Op::Reverse,
                    0xf3 => Op::Hexlify,
                    _ => bail!("ots: unknown operation tag 0x{tag:02x}"),
                };
                let next = op.apply(&t.msg)?;
                let child = Self::read(r, next, depth + 1)?;
                t.ops.push((op, child));
            }
            if !fork {
                return Ok(t);
            }
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut Vec<u8>) {
        let total = self.attestations.len() + self.ops.len();
        let mut i = 0;
        for a in &self.attestations {
            i += 1;
            if i < total {
                out.push(0xff);
            }
            out.push(0x00);
            a.write(out);
        }
        for (op, child) in &self.ops {
            i += 1;
            if i < total {
                out.push(0xff);
            }
            out.push(op.tag());
            if let Op::Append(arg) | Op::Prepend(arg) = op {
                write_varbytes(out, arg);
            }
            child.write(out);
        }
    }

    /// Every attestation in the tree, with the message it commits to.
    pub fn all_attestations(&self) -> Vec<(&[u8], &Attestation)> {
        let mut out: Vec<(&[u8], &Attestation)> = self.attestations.iter().map(|a| (self.msg.as_slice(), a)).collect();
        for (_, child) in &self.ops {
            out.extend(child.all_attestations());
        }
        out
    }

    pub fn status(&self) -> OtsStatus {
        let all = self.all_attestations();
        let min_height = all.iter().filter_map(|(_, a)| match a {
            Attestation::Bitcoin { height } => Some(*height),
            _ => None,
        });
        match min_height.min() {
            Some(h) => OtsStatus::Confirmed(h),
            None if all.iter().any(|(_, a)| matches!(a, Attestation::Pending { .. })) => OtsStatus::Pending,
            None => OtsStatus::Empty,
        }
    }

    /// Bitcoin attestations as (height, the 32-byte message the operations lead to). OTS
    /// commits that message as the block's Merkle root in header (internal) byte order.
    pub fn bitcoin_attestations(&self) -> Result<Vec<(u64, [u8; 32])>> {
        self.all_attestations()
            .into_iter()
            .filter_map(|(msg, a)| match a {
                Attestation::Bitcoin { height } => Some((*height, msg)),
                _ => None,
            })
            .map(|(h, msg)| {
                let m: [u8; 32] = msg.try_into().map_err(|_| Error::new(format!("ots: the timestamp attestation for block {h} is not over a 32-byte Merkle root")))?;
                Ok((h, m))
            })
            .collect()
    }

    /// Pending calendar attestations as (calendar URI, commitment message) pairs.
    pub fn pending(&self) -> Vec<(String, Vec<u8>)> {
        self.all_attestations()
            .into_iter()
            .filter_map(|(msg, a)| match a {
                Attestation::Pending { uri } => Some((uri.clone(), msg.to_vec())),
                _ => None,
            })
            .collect()
    }

    /// Merge `other` (a timestamp for `commitment`) into the node holding that message.
    /// Returns true when a node was found.
    pub fn merge_at(&mut self, commitment: &[u8], other: &Timestamp) -> bool {
        if self.msg == commitment {
            self.merge(other);
            return true;
        }
        self.ops.iter_mut().any(|(_, child)| child.merge_at(commitment, other))
    }

    fn merge(&mut self, other: &Timestamp) {
        for a in &other.attestations {
            if !self.attestations.contains(a) {
                self.attestations.push(a.clone());
            }
        }
        for (op, theirs) in &other.ops {
            match self.ops.iter_mut().find(|(o, _)| o == op) {
                Some((_, ours)) => ours.merge(theirs),
                None => self.ops.push((op.clone(), theirs.clone())),
            }
        }
    }
}

impl DetachedFile {
    pub fn parse(data: &[u8]) -> Result<DetachedFile> {
        let mut r = Reader::new(data)?;
        if r.bytes(MAGIC.len())? != MAGIC {
            bail!("ots: not an OpenTimestamps proof (bad magic)");
        }
        if r.varuint()? != 1 {
            bail!("ots: unsupported proof version");
        }
        if r.byte()? != 0x08 {
            bail!("ots: only SHA-256 file digests are supported");
        }
        let digest: [u8; 32] = r.bytes(32)?.try_into().unwrap();
        let timestamp = Timestamp::read(&mut r, digest.to_vec(), 0)?;
        if r.pos != data.len() {
            bail!("ots: trailing bytes after timestamp");
        }
        Ok(DetachedFile { digest, timestamp })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        write_varuint(&mut out, 1);
        out.push(0x08);
        out.extend_from_slice(&self.digest);
        self.timestamp.write(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DetachedFile {
        let digest = [7u8; 32];
        let mut t = Timestamp::new(digest.to_vec());
        for (i, uri) in ["https://a.example", "https://b.example"].iter().enumerate() {
            let op = Op::Append(vec![i as u8; 4]);
            let m1 = op.apply(&digest).unwrap();
            let mut c1 = Timestamp::new(m1.clone());
            let m2 = Op::Sha256.apply(&m1).unwrap();
            let mut c2 = Timestamp::new(m2);
            c2.attestations.push(Attestation::Pending { uri: uri.to_string() });
            c1.ops.push((Op::Sha256, c2));
            t.ops.push((op, c1));
        }
        DetachedFile { digest, timestamp: t }
    }

    #[test]
    fn round_trip_and_upgrade() {
        let f = sample();
        let bytes = f.serialize();
        let parsed = DetachedFile::parse(&bytes).unwrap();
        assert_eq!(parsed, f);
        assert_eq!(parsed.timestamp.status(), OtsStatus::Pending);
        let pending = parsed.timestamp.pending();
        assert_eq!(pending.len(), 2);

        // A calendar answers for the first commitment with a Bitcoin attestation.
        let (_, commitment) = &pending[0];
        let mut upgrade = Timestamp::new(commitment.clone());
        let m = Op::Prepend(vec![1, 2]).apply(commitment).unwrap();
        let mut leaf = Timestamp::new(m);
        leaf.attestations.push(Attestation::Bitcoin { height: 812_345 });
        upgrade.ops.push((Op::Prepend(vec![1, 2]), leaf));
        let upgrade = Timestamp::parse(&upgrade.serialize(), commitment).unwrap();

        let mut merged = parsed.clone();
        assert!(merged.timestamp.merge_at(commitment, &upgrade));
        assert_eq!(merged.timestamp.status(), OtsStatus::Confirmed(812_345));
        assert_eq!(DetachedFile::parse(&merged.serialize()).unwrap(), merged);
    }

    #[test]
    fn limits_hold_across_the_whole_proof() {
        // 1100 pending attestations forked from the root: a valid shape, over the node cap.
        let proof = |n: usize| {
            let mut b = MAGIC.to_vec();
            write_varuint(&mut b, 1);
            b.push(0x08);
            b.extend_from_slice(&[0u8; 32]);
            for i in 0..n {
                if i + 1 < n {
                    b.push(0xff);
                }
                b.push(0x00);
                b.extend_from_slice(&TAG_PENDING);
                write_varbytes(&mut b, &[1, b'x']);
            }
            b
        };
        assert!(DetachedFile::parse(&proof(MAX_NODES)).is_ok());
        assert!(DetachedFile::parse(&proof(MAX_NODES + 1)).unwrap_err().0.contains("more than"));
        assert!(DetachedFile::parse(&vec![0u8; MAX_PROOF_BYTES + 1]).unwrap_err().0.contains("longer than"));
    }

    /// Reverse of a displayed block hash or Merkle root: OTS works in header byte order.
    #[test]
    fn bitcoin_attestation_message() {
        let f = sample();
        assert!(f.timestamp.bitcoin_attestations().unwrap().is_empty());
    }

    #[test]
    fn rejects_garbage() {
        assert!(DetachedFile::parse(b"nope").is_err());
        let mut b = sample().serialize();
        b.push(0);
        assert!(DetachedFile::parse(&b).is_err());
    }
}
