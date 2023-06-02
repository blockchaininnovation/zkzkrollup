use halo2_base::gates::flex_gate::FlexGateConfig;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::utils::fe_to_bigint;
use halo2_base::AssignedValue;
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::fp::FpConfig;
use halo2_ecc::fields::FieldChip;
use num_bigint::BigInt;
use rand::rngs::OsRng;
use rand::Rng;
use snark_verifier::util::arithmetic::PrimeField;

#[derive(Debug, Clone)]
pub struct Point<F: PrimeField> {
    x: F,
    y: F,
}

#[derive(Debug, Clone)]
pub struct AssignedPoint<'a, F: PrimeField> {
    x: AssignedValue<'a, F>,
    y: AssignedValue<'a, F>,
}

#[derive(Debug, Clone)]
pub struct BabyJubConfig<F: PrimeField> {
    gate: FlexGateConfig<F>,
}

impl<F: PrimeField> BabyJubConfig<F> {
    pub fn new(gate: FlexGateConfig<F>) -> Self {
        Self { gate }
    }

    pub fn load_point<'a>(point: &Value<Point<F>>) -> AssignedPoint<'a, F> {}
}
