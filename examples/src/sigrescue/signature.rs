use crate::utils::rescue::{Hash, Rescue128};
use winterfell::{
    crypto::MerkleTree,
    math::{fields::f128::BaseElement, FieldElement},
};

pub struct AggPublicKey {
    keys: Vec<[BaseElement; 2]>,
    tree: MerkleTree<Rescue128>,
}

impl AggPublicKey {
    pub fn new(keys: Vec<[BaseElement; 2]>) -> Self {
        let mut leaves: Vec<Hash> = Vec::new();
        for key in keys.iter() {
            leaves.push(Rescue128::digest(key));
        }

        // pad the list of keys with zero keys to make sure the number of leaves is a power of two
        let num_leaves = if leaves.len().is_power_of_two() {
            leaves.len()
        } else {
            leaves.len().next_power_of_two()
        };
        let zero_hash = Rescue128::digest(&[BaseElement::ZERO, BaseElement::ZERO]);
        for _ in leaves.len()..num_leaves {
            leaves.push(zero_hash);
        }

        // build a Merkle tree of all leaves
        let tree = MerkleTree::new(leaves).unwrap();

        AggPublicKey { keys, tree }
    }

    /// Returns a 32-byte representation of the aggregated public key.
    pub fn root(&self) -> Hash {
        *self.tree.root()
    }

    /// Returns the number of individual keys aggregated into this key.
    pub fn num_keys(&self) -> usize {
        self.keys.len()
    }

    /// Returns a Merkle path to the specified leaf.
    pub fn get_leaf_path(&self, index: usize) -> Vec<Hash> {
        self.tree.prove(index).unwrap()
    }
}
