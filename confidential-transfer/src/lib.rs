use halo2_base::gates::GateInstructions;
// use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{Circuit, ConstraintSystem};
use halo2_base::halo2_proofs::poly::{commitment::Params, kzg::commitment::ParamsKZG};
use halo2_base::halo2_proofs::{circuit::Layouter, plonk::Error};
use halo2_base::halo2_proofs::{
    circuit::{floor_planner::V1, Cell, Value},
    dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
    plonk::{Any, Column, Instance, ProvingKey, VerifyingKey},
};
use halo2_base::utils::fe_to_bigint;
use halo2_base::{
    gates::range::RangeConfig, gates::RangeInstructions, utils::PrimeField, Context, QuantumCell,
};
use halo2_base::{gates::range::RangeStrategy::Vertical, SKIP_FIRST_PASS};
use halo2_ecc::ecc::{EcPoint, EccChip};
use halo2_ecc::fields::fp::FpConfig;
use halo2_ecc::fields::FieldChip;
use halo2_native_ec::*;
use num_bigint::BigInt;
use rand::rngs::OsRng;
use rand::Rng;

// https://crypto.stanford.edu/~buenz/papers/zether.pdf
// Section 6

#[derive(Debug, Clone)]
pub struct BalanceEnc<F: PrimeField> {
    l: Point<F>,
    r: Point<F>,
}

#[derive(Debug, Clone)]
pub struct AssignedBalanceEnc<'a, F: PrimeField> {
    l: AssignedPoint<'a, F>,
    r: AssignedPoint<'a, F>,
}

#[derive(Debug, Clone)]
pub struct ConfidentialTransferConfig<F: PrimeField> {
    ecc_config: NativeECConfig<F>,
    range: RangeConfig<F>,
}

impl<F: PrimeField> ConfidentialTransferConfig<F> {
    pub fn new(ecc_config: NativeECConfig<F>, range: RangeConfig<F>) -> Self {
        Self { ecc_config, range }
    }

    pub fn transfer(
        &self,
        ctx: &mut Context<F>,
        sender_priv_key: &F,
        recipient_pub_key: &Point<F>,
        sender_balance: u32,
        sender_balance_enc: &BalanceEnc<F>,
        recipient_balance_enc: &BalanceEnc<F>,
        transfer_amount: u32,
        rand: &F,
    ) -> Result<(AssignedBalanceEnc<F>, AssignedBalanceEnc<F>), Error> {
        let gate = &self.ecc_config.gate;
        let assigned_base_point = self.ecc_config.load_base_point(ctx);
        let assigned_sender_priv = gate.load_witness(ctx, Value::known(*sender_priv_key));
        let assigned_recipient_pub = self.ecc_config.load_point_checked(ctx, recipient_pub_key);
        let assigned_transfer_amount =
            gate.load_witness(ctx, Value::known(F::from(transfer_amount as u64)));
        self.range.range_check(ctx, &assigned_transfer_amount, 32);
        let assigned_balance = gate.load_witness(ctx, Value::known(F::from(sender_balance as u64)));
        let assigned_remaining_balance = gate.sub(
            ctx,
            QuantumCell::Existing(&assigned_balance),
            QuantumCell::Existing(&assigned_transfer_amount),
        );
        self.range.range_check(ctx, &assigned_remaining_balance, 32);

        let assigned_rand = gate.load_witness(ctx, Value::known(*rand));
        let rand_point = self
            .ecc_config
            .scalar_mul(ctx, &assigned_base_point, &assigned_rand);

        {
            let balance_point =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_base_point, &assigned_balance);
            let sender_balance_enc_r = self
                .ecc_config
                .load_point_checked(ctx, &sender_balance_enc.r);
            let randomized_pk =
                self.ecc_config
                    .scalar_mul(ctx, &sender_balance_enc_r, &assigned_sender_priv);
            let expected_c_l = self.ecc_config.add(ctx, &balance_point, &randomized_pk);
            let sender_balance_enc_l = self
                .ecc_config
                .load_point_checked(ctx, &sender_balance_enc.l);
            let is_eq = self.ecc_config.is_equal(ctx, , point_b)
        }

        let new_sender_balance_enc = {
            let remaining_balance_point =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_base_point, &assigned_remaining_balance);
            let randomized_pk = self
                .ecc_config
                .scalar_mul(ctx, &rand_point, &assigned_sender_priv);
            let c_l = self
                .ecc_config
                .add(ctx, &remaining_balance_point, &randomized_pk);
            let c_r = rand_point.clone();
            AssignedBalanceEnc { l: c_l, r: c_r }
        };

        let new_recipient_balance_enc = {
            let assigned_recipient_c_r = self
                .ecc_config
                .load_point_checked(ctx, &recipient_balance_enc.r);
            let new_c_r = self
                .ecc_config
                .add(ctx, &assigned_recipient_c_r, &rand_point);
            let randomized_pk =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_recipient_pub, &assigned_rand);
            let transfer_amount_point =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_base_point, &assigned_transfer_amount);
            let assigned_recipient_c_l = self
                .ecc_config
                .load_point_checked(ctx, &recipient_balance_enc.l);
            let new_c_l = self
                .ecc_config
                .add(ctx, &assigned_recipient_c_l, &transfer_amount_point);
            let new_c_l = self.ecc_config.add(ctx, &new_c_l, &randomized_pk);
            AssignedBalanceEnc {
                l: new_c_l,
                r: new_c_r,
            }
        };
        Ok((new_sender_balance_enc, new_recipient_balance_enc))

        // let amount_enc_rand = self.ecc_config.scalar_mult(ctx, &assigned_base_point, &assigned_rand.limbs().to_vec(), max_bits, window_bits)
    }

    fn assign_balance_enc<'a>(
        &self,
        ctx: &mut Context<F>,
        balance_enc: &BalanceEnc<F>,
    ) -> Result<AssignedBalanceEnc<'a, F>, Error> {
        let l = self.ecc_config.load_point_checked(ctx, &balance_enc.l);
        let r = self.ecc_config.load_point_checked(ctx, &balance_enc.r);
        Ok(AssignedBalanceEnc { l, r })
    }
}
