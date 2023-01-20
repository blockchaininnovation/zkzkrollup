use halo2_gadgets::poseidon::primitives::{
    self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier,
};
use halo2curves::pasta::{pallas, vesta, EqAffine, Fp};

pub struct MerkleTree {
    leaves: Vec<Vec<Fp>>,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let mut leaves = Vec::new();
        for i in 0..depth {
            let elements = vec![Fp::zero(); 1 << i];
            leaves.push(elements);
        }
        Self { leaves }
    }

    fn calculate_leaf(balance: Fp, nonce: Fp) -> Fp {
        let message = [balance, nonce];
        let poseidon_hasher =
            poseidon::Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init();
        let result = poseidon_hasher.hash(message);
        result
    }
}
