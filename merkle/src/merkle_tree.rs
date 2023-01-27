use crate::prelude::*;
use crate::Hasher;
use num_bigint::BigUint;
use std::collections::HashMap;

pub struct SparseMerkleTree<T: Hasher> {
    leaves: HashMap<BigUint, T::Hash>,
}

impl<T: Hasher> Default for SparseMerkleTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Hasher> SparseMerkleTree<T> {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
        }
    }

    // pub fn root(&self) -> Option<T::Hash> {
    // }

    pub fn include(&self, address: BigUint, leaf: T::Hash) -> bool {
        true
    }

    pub fn exclude(&self, address: BigUint, leaf: T::Hash) -> bool {
        true
    }

    pub fn update(&mut self, address: BigUint, leaf: T::Hash) -> &mut Self {
        self.leaves.insert(address, leaf);
        self
    }
}
