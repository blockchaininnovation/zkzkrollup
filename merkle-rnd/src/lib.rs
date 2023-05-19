mod chip;
mod r#const;

use chip::{MerkleChip, MerkleChipConfig};
use halo2_proofs::{
    arithmetic::{Field, FieldExt},
    plonk::{Assignment, Circuit, ConstraintSystem, Error},
};
use halo2curves::pasta::Fp;

#[derive(Clone)]
struct MerkleCircuit {
    // private inputs
    leaf: Option<Fp>,
    path: Option<Fp>,
    // public inputs: root is calculated within the circuit
    c_bits: Option<Vec<Fp>>,
}

impl<F: FieldExt> Circuit<F> for MerkleCircuit {
    type Config = MerkleChipConfig;

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        MerkleChip::configure(cs)
    }

    fn synthesize(&self, cs: &mut impl Assignment<F>, config: Self::Config) -> Result<(), Error> {
        let mut layouter = SingleChipLayouter::new(cs)?;
        let merkle_chip = MerkleChip::new(config);
        let mut layer_digest = merkle_chip.hash_leaf_layer(
            &mut layouter,
            self.leaf.as_ref().unwrap().clone(),
            self.path.as_ref().unwrap()[0],
            self.c_bits.as_ref().unwrap()[0].clone(),
        )?;
        for layer in 1..PATH_LEN {
            layer_digest = merkle_chip.hash_non_leaf_layer(
                &mut layouter,
                layer_digest,
                self.path.as_ref().unwrap()[layer].clone(),
                self.c_bits.as_ref().unwrap()[layer].clone(),
                layer,
            )?;
        }
        Ok(())
    }
}
