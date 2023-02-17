use crate::prelude::*;
use halo2curves::pasta::Fp;
use num_bigint::BigUint;
use std::collections::HashMap;
use std::vec::Vec;

pub struct SparseMerkleTree {
    leaves: HashMap<BigUint, Fp>,
    layers: Vec<Vec<One>>,
}
pub struct Leaf {
    address: BigUint,
    hash: Fp,
}
pub struct One {
    is_left: bool,
    hash: Fp,
}
impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: HashMap::new(),
            layers: Vec::new(),
        }
    }

    pub fn include(&self, address: BigUint, leaf: Fp) -> Vec<One> {
        let ret = Vec::new();

        return ret;
    }

    pub fn exclude(&self, address: BigUint, leaf: Fp) -> bool {
        true
    }

    pub fn update(&mut self, leaf: Leaf) -> &mut Self {
        self.leaves.insert(leaf.address, leaf.hash);

        // ここでlayerを構築

        self
    }
}
