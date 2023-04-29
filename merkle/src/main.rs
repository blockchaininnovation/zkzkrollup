
use crate::poseidon_chip::{PoseidonChip, PoseidonConfig};
use crate::utilities::{
    AssertEqualChip, AssertEqualConfig, ConditionalSelectChip, ConditionalSelectConfig,
    IsEqualChip, IsEqualConfig, NUM_OF_UTILITY_ADVICE_COLUMNS,
};
use halo2_gadgets::poseidon::primitives::Spec;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
};
use smt::poseidon::FieldHasher;
use smt::smt::Path;
use std::marker::PhantomData;

fn main() {
    // Circuit is very small, we pick a small value here
    let k = 13;

    let empty_leaf = [0u8; 64];
    let rng = OsRng;
    let leaves = [Fp::random(rng), Fp::random(rng), Fp::random(rng)];
    const HEIGHT: usize = 3;
    let num_iter = 3;

    let circuit = TestCircuit::<Fp, SmtP128Pow5T3<Fp, 0>, Poseidon<Fp, 2>, 3, 2, HEIGHT> {
        leaves,
        empty_leaf,
        hasher: Poseidon::<Fp, 2>::new(),
        _spec: PhantomData,
    };

    let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    assert_eq!(prover.verify(), Ok(()));

    let params: Params<EqAffine> = Params::new(k);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("proof generation should not fail");
    let proof: Vec<u8> = transcript.finalize();

    let strategy = SingleVerifier::new(&params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let result = verify_proof(&params, pk.get_vk(), strategy, &[&[]], &mut transcript);
    assert!(result.is_ok());
}
