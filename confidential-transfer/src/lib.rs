use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::{
    bn256::{Bn256, Fr, G1Affine},
    secp256k1::{Fp, Fq},
};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::FieldChip;
use rand::rngs::OsRng;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct ConfidentialTransferConfig<F: PrimeField, FC: FieldChip<F>> {
    ecc_config: EccChip,
}
