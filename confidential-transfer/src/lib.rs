use ::halo2_proofs::halo2curves::CurveAffine;
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
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
use halo2_ecc::fields::fp::FpConfig;
use halo2_ecc::fields::FieldChip;
use rand::rngs::OsRng;
use rand::Rng;
use snark_verifier_sdk::halo2::aggregation::BaseFieldEccChip;

// https://crypto.stanford.edu/~buenz/papers/zether.pdf
// Section 6

#[derive(Debug, Clone)]
pub struct BalanceEnc {
    l: G1Affine,
    r: G1Affine,
}

#[derive(Debug, Clone)]
pub struct ConfidentialTransferConfig {
    ecc_config: BaseFieldEccChip,
}

impl ConfidentialTransferConfig {
    pub fn new(ecc_config: BaseFieldEccChip) -> Self {
        Self { ecc_config }
    }

    pub fn transfer(
        &self,
        ctx: &mut Context<Fr>,
        sender_private_key: &Fr,
        recipient_public_key: &G1Affine,
        sender_balance: u32,
        sender_balance_enc: &BalanceEnc,
        recipient_balance_enc: &BalanceEnc,
        transfer_amount: u32,
        randomness: &Fr,
    ) -> Result<(BalanceEnc, BalanceEnc), Error> {
        let assigned_base_point = self
            .ecc_config
            .assign_constant_point(ctx, G1Affine::generator());
        let assigned_sender_private = self.ecc_config.assign_scalar();
    }
}
