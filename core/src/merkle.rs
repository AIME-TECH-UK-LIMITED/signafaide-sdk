//! RFC 6962 Merkle tree over 32-byte item hashes (record hashes or batch hashes).
//!
//! Leaf = sha256(0x00 || item), node = sha256(0x01 || left || right). The tree is built level
//! by level; a lone last node is promoted unchanged, which yields exactly the RFC 6962 split
//! (largest power of two below n on the left).

use crate::{Hash, Result};
use sha2::{Digest, Sha256};

pub fn leaf_hash(item: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(item.0);
    Hash(h.finalize().into())
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left.0);
    h.update(right.0);
    Hash(h.finalize().into())
}

/// A complete tree; computing every audit path costs O(n log n) in total.
pub struct Tree {
    levels: Vec<Vec<Hash>>,
}

impl Tree {
    /// Build from at least one item.
    pub fn new(items: &[Hash]) -> Result<Tree> {
        if items.is_empty() {
            crate::bail!("a Merkle tree needs at least one item");
        }
        let mut levels = vec![items.iter().map(leaf_hash).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .map(|p| if p.len() == 2 { node_hash(&p[0], &p[1]) } else { p[0] })
                .collect();
            levels.push(next);
        }
        Ok(Tree { levels })
    }

    pub fn size(&self) -> usize {
        self.levels[0].len()
    }

    pub fn root(&self) -> Hash {
        self.levels.last().unwrap()[0]
    }

    /// Audit path for `index`, from the leaf upward.
    pub fn path(&self, mut index: usize) -> Vec<Hash> {
        let mut path = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = index ^ 1;
            if sibling < level.len() {
                path.push(level[sibling]);
            }
            index /= 2;
        }
        path
    }
}

/// RFC 9162 §2.1.3.2 inclusion proof verification.
pub fn verify_path(item: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = leaf_hash(item);
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    /// The recursive RFC 6962 definition, as an independent reference.
    fn mth(items: &[Hash]) -> Hash {
        if items.len() == 1 {
            return leaf_hash(&items[0]);
        }
        let mut k = 1;
        while k * 2 < items.len() {
            k *= 2;
        }
        node_hash(&mth(&items[..k]), &mth(&items[k..]))
    }

    #[test]
    fn matches_rfc6962_and_paths_verify() {
        for n in 1..=33usize {
            let items: Vec<Hash> = (0..n).map(|i| sha256(format!("item-{i}").as_bytes())).collect();
            let tree = Tree::new(&items).unwrap();
            assert_eq!(tree.root(), mth(&items), "n={n}");
            for (i, item) in items.iter().enumerate() {
                let path = tree.path(i);
                assert!(verify_path(item, i as u64, n as u64, &path, &tree.root()), "n={n} i={i}");
                if n > 1 {
                    assert!(!verify_path(item, ((i + 1) % n) as u64, n as u64, &path, &tree.root()));
                }
            }
        }
    }
}
