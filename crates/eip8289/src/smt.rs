//! General-purpose binary sparse Merkle tree.

use alloc::vec::Vec;
use alloy_primitives::{
    B256,
    map::{DefaultHashBuilder, HashMap},
};
use sha2::{Digest, Sha256};

/// Number of bits in a sparse Merkle path.
pub const SPARSE_MERKLE_TREE_DEPTH: usize = 256;

/// A fixed-shape inclusion or non-inclusion proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleProof {
    /// Sibling hashes ordered from the leaf level to the root.
    pub siblings: [B256; SPARSE_MERKLE_TREE_DEPTH],
}

impl SparseMerkleProof {
    /// Verifies this proof for `key`, `value`, and `root`.
    ///
    /// A zero value verifies non-inclusion.
    pub fn verify(&self, key: B256, value: B256, root: B256) -> bool {
        let mut node = value;
        let key = key.0;

        for (height, sibling) in self.siblings.iter().enumerate() {
            let bit = path_bit(&key, height);
            node = if bit == 0 { hash_node(node, *sibling) } else { hash_node(*sibling, node) };
        }

        node == root
    }
}

/// A depth-256 binary sparse Merkle tree over 256-bit keys and values.
///
/// Only non-default nodes are materialized. A zero value represents an absent leaf. Internal nodes
/// are `SHA256(left || right)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleTree {
    nodes: HashMap<NodePosition, B256>,
    zero_hashes: Vec<B256>,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Creates an empty tree.
    pub fn new() -> Self {
        let mut zero_hashes = Vec::with_capacity(SPARSE_MERKLE_TREE_DEPTH + 1);
        zero_hashes.push(B256::ZERO);
        for height in 0..SPARSE_MERKLE_TREE_DEPTH {
            let child = zero_hashes[height];
            zero_hashes.push(hash_node(child, child));
        }

        Self {
            nodes: HashMap::with_capacity_and_hasher(0, DefaultHashBuilder::default()),
            zero_hashes,
        }
    }

    /// Returns the current root.
    #[inline]
    pub fn root(&self) -> B256 {
        self.nodes
            .get(&NodePosition::root())
            .copied()
            .unwrap_or(self.zero_hashes[SPARSE_MERKLE_TREE_DEPTH])
    }

    /// Returns the value at `key`, or zero when the key is absent.
    #[inline]
    pub fn value(&self, key: B256) -> B256 {
        self.nodes.get(&NodePosition::leaf(key.0)).copied().unwrap_or(B256::ZERO)
    }

    /// Sets `value` at `key`, returning the new root.
    ///
    /// Setting a zero value removes the leaf and any newly-default ancestors.
    pub fn update(&mut self, key: B256, value: B256) -> B256 {
        let mut prefix = key.0;
        let mut node = value;
        self.set_node(NodePosition::new(0, prefix), node);

        for height in 0..SPARSE_MERKLE_TREE_DEPTH {
            let bit = path_bit(&prefix, height);
            let mut sibling_prefix = prefix;
            toggle_path_bit(&mut sibling_prefix, height);
            let sibling = self
                .nodes
                .get(&NodePosition::new(height as u16, sibling_prefix))
                .copied()
                .unwrap_or(self.zero_hashes[height]);

            node = if bit == 0 { hash_node(node, sibling) } else { hash_node(sibling, node) };
            clear_path_bit(&mut prefix, height);
            self.set_node(NodePosition::new((height + 1) as u16, prefix), node);
        }

        node
    }

    /// Creates a fixed 256-sibling proof for `key`.
    pub fn prove(&self, key: B256) -> SparseMerkleProof {
        let mut siblings = [B256::ZERO; SPARSE_MERKLE_TREE_DEPTH];
        let mut prefix = key.0;

        for (height, sibling) in siblings.iter_mut().enumerate() {
            let mut sibling_prefix = prefix;
            toggle_path_bit(&mut sibling_prefix, height);
            *sibling = self
                .nodes
                .get(&NodePosition::new(height as u16, sibling_prefix))
                .copied()
                .unwrap_or(self.zero_hashes[height]);
            clear_path_bit(&mut prefix, height);
        }

        SparseMerkleProof { siblings }
    }

    fn set_node(&mut self, position: NodePosition, node: B256) {
        if node == self.zero_hashes[position.height as usize] {
            self.nodes.remove(&position);
        } else {
            self.nodes.insert(position, node);
        }
    }
}

fn hash_node(left: B256, right: B256) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(left.as_slice());
    hasher.update(right.as_slice());
    B256::from_slice(&hasher.finalize())
}

const fn path_bit(key: &[u8; 32], height: usize) -> u8 {
    let bit = SPARSE_MERKLE_TREE_DEPTH - 1 - height;
    (key[bit / 8] >> (7 - bit % 8)) & 1
}

const fn toggle_path_bit(key: &mut [u8; 32], height: usize) {
    let bit = SPARSE_MERKLE_TREE_DEPTH - 1 - height;
    key[bit / 8] ^= 1 << (7 - bit % 8);
}

const fn clear_path_bit(key: &mut [u8; 32], height: usize) {
    let bit = SPARSE_MERKLE_TREE_DEPTH - 1 - height;
    key[bit / 8] &= !(1 << (7 - bit % 8));
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct NodePosition {
    height: u16,
    prefix: [u8; 32],
}

impl NodePosition {
    const fn new(height: u16, prefix: [u8; 32]) -> Self {
        Self { height, prefix }
    }

    const fn leaf(prefix: [u8; 32]) -> Self {
        Self::new(0, prefix)
    }

    const fn root() -> Self {
        Self::new(SPARSE_MERKLE_TREE_DEPTH as u16, [0; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::b256;

    #[test]
    fn empty_root_is_a_256_level_zero_tree() {
        let tree = SparseMerkleTree::new();
        let key = B256::repeat_byte(0x42);

        assert!(tree.prove(key).verify(key, B256::ZERO, tree.root()));
        assert_eq!(
            tree.root(),
            b256!("b178c245c947ea7e21ecede07728941a6ab1b706143c06873baff8ebd6de6308")
        );
    }

    #[test]
    fn updates_are_order_independent() {
        let first_key = B256::repeat_byte(0x11);
        let second_key = B256::repeat_byte(0x22);
        let first_value = B256::repeat_byte(0xaa);
        let second_value = B256::repeat_byte(0xbb);
        let mut left = SparseMerkleTree::new();
        let mut right = SparseMerkleTree::new();

        left.update(first_key, first_value);
        left.update(second_key, second_value);
        right.update(second_key, second_value);
        right.update(first_key, first_value);

        assert_eq!(left.root(), right.root());
    }

    #[test]
    fn inclusion_and_non_inclusion_proofs_verify() {
        let present = B256::repeat_byte(0x33);
        let absent = B256::repeat_byte(0x44);
        let value = B256::repeat_byte(0xcc);
        let mut tree = SparseMerkleTree::new();
        tree.update(present, value);

        assert!(tree.prove(present).verify(present, value, tree.root()));
        assert!(!tree.prove(present).verify(present, B256::repeat_byte(0xdd), tree.root()));
        assert!(tree.prove(absent).verify(absent, B256::ZERO, tree.root()));
    }

    #[test]
    fn zero_update_restores_empty_root() {
        let key = B256::repeat_byte(0x55);
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();

        tree.update(key, B256::repeat_byte(0xee));
        tree.update(key, B256::ZERO);

        assert_eq!(tree.root(), empty_root);
        assert_eq!(tree.value(key), B256::ZERO);
    }
}
