use chiplet::smt_chip::{PathChip, PathConfig};
use chiplet::utilities::{AssertEqualChip, AssertEqualConfig};
use smt::poseidon::FieldHasher;
use smt::smt::SparseMerkleTree;
use std::marker::PhantomData;

use halo2_curves::bn256::Fr;
use halo2_gadgets::poseidon::primitives::Spec;
use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};

#[derive(Clone)]
pub struct MerkleConfig<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    H: FieldHasher<F, 2>,
    const WIDTH: usize,
    const RATE: usize,
    const N: usize,
> {
    path_config: PathConfig<F, S, WIDTH, RATE, N>,
    advices: [Column<Advice>; 3],
    assert_equal_config: AssertEqualConfig<F>,
    _hasher: PhantomData<H>,
}

#[derive(Clone)]
pub struct MerkleCircuit<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    H: FieldHasher<F, 2>,
    const WIDTH: usize,
    const RATE: usize,
    const N: usize,
> {
    leaves: [F; 3],
    empty_leaf: [u8; 64],
    hasher: H,
    _spec: PhantomData<S>,
}
impl<
        F: FieldExt,
        S: Spec<F, WIDTH, RATE> + Clone,
        H: FieldHasher<F, 2> + Clone,
        const WIDTH: usize,
        const RATE: usize,
        const N: usize,
    > Circuit<F> for MerkleCircuit<F, S, H, WIDTH, RATE, N>
{
    type Config = MerkleConfig<F, S, H, WIDTH, RATE, N>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            leaves: [F::zero(), F::zero(), F::zero()],
            empty_leaf: [0u8; 64],
            hasher: H::hasher(),
            _spec: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let advices = [(); 3].map(|_| meta.advice_column());
        advices
            .iter()
            .for_each(|column| meta.enable_equality(*column));

        MerkleConfig {
            path_config: PathChip::<F, S, H, WIDTH, RATE, N>::configure(meta),
            advices,
            assert_equal_config: AssertEqualChip::configure(meta, [advices[0], advices[1]]),
            _hasher: PhantomData,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let smt = SparseMerkleTree::<F, H, N>::new_sequential(
            &self.leaves,
            &self.hasher.clone(),
            &self.empty_leaf,
        )
        .unwrap();
        let path = smt.generate_membership_proof(0);
        let root = path
            .calculate_root(&self.leaves[0], &self.hasher.clone())
            .unwrap();

        let (root_cell, leaf_cell, one) = layouter.assign_region(
            || "test circuit",
            |mut region| {
                let root_cell =
                    region.assign_advice(|| "root", config.advices[0], 0, || Value::known(root))?;

                let leaf_cell = region.assign_advice(
                    || "leaf",
                    config.advices[1],
                    0,
                    || Value::known(self.leaves[0]),
                )?;

                let one = region.assign_advice(
                    || "one",
                    config.advices[2],
                    0,
                    || Value::known(F::one()),
                )?;
                Ok((root_cell, leaf_cell, one))
            },
        )?;

        let path_chip = PathChip::<F, S, H, WIDTH, RATE, N>::from_native(
            config.path_config,
            &mut layouter,
            path,
        )?;
        let res = path_chip.check_membership(&mut layouter, root_cell, leaf_cell)?;

        let assert_equal_chip = AssertEqualChip::construct(config.assert_equal_config, ());
        assert_equal_chip.assert_equal(&mut layouter, res, one)?;

        Ok(())
    }
}

impl<
        F: FieldExt,
        S: Spec<F, WIDTH, RATE> + Clone,
        H: FieldHasher<F, 2> + Clone,
        const WIDTH: usize,
        const RATE: usize,
        const N: usize,
    > MerkleCircuit<F, S, H, WIDTH, RATE, N>
{
    pub fn new(leaves: [F; 3], empty_leaf: [u8; 64], hasher: H) -> Self {
        Self {
            leaves,
            empty_leaf,
            hasher,
            _spec: PhantomData,
        }
    }

    pub fn num_instance() -> Vec<usize> {
        vec![]
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![]
    }
}

#[cfg(test)]
mod test {
    use super::{MerkleCircuit, PhantomData};

    use rand::rngs::OsRng;
    use smt::poseidon::{Poseidon, SmtP128Pow5T3};

    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
    use halo2_proofs::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof};
    use halo2_proofs::poly::commitment::ParamsProver;
    use halo2_proofs::poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverGWC, VerifierGWC},
        strategy::SingleStrategy,
    };
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };

    #[test]
    fn merkle_tree_test() {
        let k = 13;

        let empty_leaf = [0u8; 64];
        let rng = OsRng;
        let leaves = [Fr::random(rng), Fr::random(rng), Fr::random(rng)];
        const HEIGHT: usize = 3;

        let circuit = MerkleCircuit::<Fr, SmtP128Pow5T3<Fr, 0>, Poseidon<Fr, 2>, 3, 2, HEIGHT> {
            leaves,
            empty_leaf,
            hasher: Poseidon::<Fr, 2>::new(),
            _spec: PhantomData,
        };

        let params: ParamsKZG<Bn256> = ParamsKZG::new(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
        create_proof::<
            KZGCommitmentScheme<Bn256>,
            ProverGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            _,
            Blake2bWrite<Vec<u8>, G1Affine, Challenge255<_>>,
            _,
        >(&params, &pk, &[circuit], &[&[]], OsRng, &mut transcript)
        .expect("proof generation should not fail");
        let proof: Vec<u8> = transcript.finalize();

        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let result = verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierGWC<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(&params, pk.get_vk(), strategy, &[&[]], &mut transcript);
        assert!(result.is_ok());
    }
}
