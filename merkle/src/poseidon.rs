use crate::hasher::Hasher;
use halo2_gadgets::poseidon::primitives::{
    self as poseidon, ConstantLength, P128Pow5T3 as OrchardNullifier,
};
use halo2curves::{group::ff::PrimeField, pasta::Fp};

#[derive(Clone)]
pub struct PoseidonAlgorithm {}

impl Hasher for PoseidonAlgorithm {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> [u8; 32] {
        assert_eq!(data.len(), 16);
        let poseidon_hasher =
            poseidon::Hash::<Fp, OrchardNullifier, ConstantLength<2>, 3, 2>::init();
        let (mut a, mut b) = ([0; 4], [0; 4]);
        for i in 0..8 {
            let is_even = i % 2 == 1;
            let limbs_n = i / 2;
            let (a_byte, b_byte) = (data[i] as u64, data[i + 8] as u64);
            a[limbs_n] += if is_even {
                a_byte
            } else {
                a_byte + 2_i32.pow(32) as u64
            };
            b[limbs_n] += if is_even {
                a_byte
            } else {
                b_byte + 2_i32.pow(32) as u64
            };
        }
        let balance = Fp::from_raw(a);
        let nonce = Fp::from_raw(b);

        let result = poseidon_hasher.hash([balance, nonce]);
        result.to_repr()
    }
}
