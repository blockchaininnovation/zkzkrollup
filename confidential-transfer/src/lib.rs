mod babyjub;

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
use halo2_base::{gates::range::RangeConfig, utils::PrimeField, Context};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::fp::FpConfig;
use halo2_ecc::fields::FieldChip;
use num_bigint::BigInt;
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
        sender_priv_key: &Fr,
        recipient_pub_key: &G1Affine,
        sender_balance: u32,
        sender_balance_enc: &BalanceEnc,
        recipient_balance_enc: &BalanceEnc,
        transfer_amount: u32,
        rand: &Fr,
    ) -> Result<(BalanceEnc, BalanceEnc), Error> {
        let field_chip = self.ecc_config.field_chip();
        let assigned_base_point = self
            .ecc_config
            .assign_constant_point(ctx, G1Affine::generator());
        let assigned_sender_priv =
            field_chip.load_private(ctx, Value::known(fe_to_bigint(sender_priv_key)));
        let assigned_recipient_pub = self.ecc_config.load_private(
            ctx,
            (
                Value::known(recipient_pub_key.x),
                Value::known(recipient_pub_key.y),
            ),
        );
        let assigned_transfer_amount =
            field_chip.load_private(ctx, Value::known(BigInt::from(transfer_amount)));
        field_chip.range_check(ctx, &assigned_transfer_amount, 32);
        let assigned_balance =
            field_chip.load_private(ctx, Value::known(BigInt::from(sender_balance)));
        let assigned_remaining_balance =
            field_chip.sub_no_carry(ctx, &assigned_balance, &assigned_transfer_amount);
        field_chip.range_check(ctx, &assigned_remaining_balance, 32);

        let assigned_rand = field_chip.load_private(ctx, Value::known(fe_to_bigint(rand)));
        // let amount_enc_rand = self.ecc_config.scalar_mult(ctx, &assigned_base_point, &assigned_rand.limbs().to_vec(), max_bits, window_bits)
    }
}
