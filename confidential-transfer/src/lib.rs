use halo2_base::gates::GateInstructions;
use halo2_base::AssignedValue;
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
        sender_priv_key: &AssignedValue<F>,
        recipient_pub_key: &AssignedPoint<F>,
        sender_balance: u32,
        sender_balance_enc: &AssignedBalanceEnc<F>,
        recipient_balance_enc: &AssignedBalanceEnc<F>,
        transfer_amount: u32,
        rand: &F,
    ) -> Result<(AssignedBalanceEnc<F>, AssignedBalanceEnc<F>), Error> {
        let gate = &self.ecc_config.gate;
        let assigned_base_point = self.ecc_config.load_base_point(ctx);
        let assigned_sender_priv = sender_priv_key;
        let assigned_recipient_pub = recipient_pub_key;
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
            let sender_balance_enc_r = &sender_balance_enc.r;
            let randomized_pk =
                self.ecc_config
                    .scalar_mul(ctx, &sender_balance_enc_r, &assigned_sender_priv);
            let expected_c_l = self.ecc_config.add(ctx, &balance_point, &randomized_pk);
            let sender_balance_enc_l = &sender_balance_enc.l;
            let is_eq = self
                .ecc_config
                .is_equal(ctx, &expected_c_l, &sender_balance_enc_l);
            gate.assert_is_const(ctx, &is_eq, F::one());
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
            let assigned_recipient_c_r = &recipient_balance_enc.r;
            let new_c_r = self
                .ecc_config
                .add(ctx, &assigned_recipient_c_r, &rand_point);
            let randomized_pk =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_recipient_pub, &assigned_rand);
            let transfer_amount_point =
                self.ecc_config
                    .scalar_mul(ctx, &assigned_base_point, &assigned_transfer_amount);
            let assigned_recipient_c_l = &recipient_balance_enc.l;
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

    pub fn assign_balance_enc<'a>(
        &self,
        ctx: &mut Context<F>,
        balance_enc: &BalanceEnc<F>,
    ) -> Result<AssignedBalanceEnc<'a, F>, Error> {
        let l = self.ecc_config.load_point_checked(ctx, &balance_enc.l);
        let r = self.ecc_config.load_point_checked(ctx, &balance_enc.r);
        Ok(AssignedBalanceEnc { l, r })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_base::gates::flex_gate::FlexGateConfig;
    use halo2_base::halo2_proofs::circuit::SimpleFloorPlanner;
    use halo2_base::halo2_proofs::plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ConstraintSystem,
    };
    use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver, ParamsVerifier};
    use halo2_base::halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_base::halo2_proofs::poly::kzg::multiopen::{ProverGWC, VerifierGWC};
    use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
    use halo2_base::halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    };
    use halo2_base::halo2_proofs::{
        dev::{CircuitCost, FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::{Bn256, Fr, G1Affine, G1},
        plonk::{Any, Circuit},
    };
    use halo2_base::{gates::range::RangeStrategy::Vertical, ContextParams, SKIP_FIRST_PASS};
    use rand::rngs::OsRng;
    use std::marker::PhantomData;
    use std::{collections::HashSet, path::Path};

    #[derive(Debug, Clone)]
    pub struct TestCircuit1<F: PrimeField> {
        rand0: F,
        rand1: F,
        rand2: F,
        priv_key0: F,
        priv_key1: F,
        balance0: u32,
        balance1: u32,
        transfer_amount: u32,
    }

    impl<F: PrimeField> Circuit<F> for TestCircuit1<F> {
        type Config = ConfidentialTransferConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;
        fn without_witnesses(&self) -> Self {
            Self {
                rand0: F::one(),
                rand1: F::one(),
                rand2: F::one(),
                priv_key0: F::one(),
                priv_key1: F::one(),
                balance0: 2,
                balance1: 0,
                transfer_amount: 1,
            }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let range = RangeConfig::configure(
                meta,
                halo2_base::gates::range::RangeStrategy::Vertical,
                &[Self::NUM_ADVICE],
                &[Self::LOOKUO_ADVICE],
                Self::NUM_FIXED,
                Self::K - 1,
                0,
                Self::K,
            );
            let ecc_config = NativeECConfig::configure(range.gate().clone());
            // let base_point = Point::base_point();
            // println!("base_point {:?}", base_point);
            ConfidentialTransferConfig::new(ecc_config, range)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let mut first_pass = SKIP_FIRST_PASS;
            layouter.assign_region(
                || "regex",
                |region| {
                    if first_pass {
                        first_pass = false;
                        return Ok(());
                    }
                    let gate = config.ecc_config.gate.clone();
                    let mut aux = Context::new(
                        region,
                        ContextParams {
                            max_rows: gate.max_rows,
                            num_context_ids: 1,
                            fixed_columns: gate.constants.clone(),
                        },
                    );
                    let ctx = &mut aux;
                    let ecc_config = &config.ecc_config;
                    let base_point = config.ecc_config.load_base_point(ctx);
                    let (assigned_priv_key, sender_balance_enc) = {
                        let assigned_rand = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(self.rand0));
                        let rand_point = ecc_config.scalar_mul(ctx, &base_point, &assigned_rand);
                        let assigned_priv_key = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(self.priv_key0));
                        let rand_pk = ecc_config.scalar_mul(ctx, &rand_point, &assigned_priv_key);
                        let assigned_balance = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(F::from(self.balance0 as u64)));
                        let balance_point =
                            config
                                .ecc_config
                                .scalar_mul(ctx, &base_point, &assigned_balance);
                        let c_l = config.ecc_config.add(ctx, &balance_point, &rand_pk);
                        (
                            assigned_priv_key,
                            AssignedBalanceEnc {
                                l: c_l,
                                r: rand_point,
                            },
                        )
                    };
                    let (assigned_pub_key, recipient_balance_enc) = {
                        let assigned_rand = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(self.rand1));
                        let rand_point = ecc_config.scalar_mul(ctx, &base_point, &assigned_rand);
                        let assigned_priv_key = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(self.priv_key1));
                        let pk = ecc_config.scalar_mul(ctx, &base_point, &assigned_priv_key);
                        let rand_pk = ecc_config.scalar_mul(ctx, &rand_point, &assigned_priv_key);
                        let assigned_balance = config
                            .ecc_config
                            .gate
                            .load_witness(ctx, Value::known(F::from(self.balance1 as u64)));
                        let balance_point =
                            config
                                .ecc_config
                                .scalar_mul(ctx, &base_point, &assigned_balance);
                        let c_l = config.ecc_config.add(ctx, &balance_point, &rand_pk);
                        (
                            pk,
                            AssignedBalanceEnc {
                                l: c_l,
                                r: rand_point,
                            },
                        )
                    };
                    let transfereed = config.transfer(
                        ctx,
                        &assigned_priv_key,
                        &assigned_pub_key,
                        self.balance0,
                        &sender_balance_enc,
                        &recipient_balance_enc,
                        self.transfer_amount,
                        &self.rand2,
                    )?;
                    // let new_rand_pk =
                    //     ecc_config.scalar_mul(ctx, &transfereed.0.r, &assigned_priv_key);

                    // let (expected_sender_enc, expected_recipient_enc) = {
                    //     let assigned_rand0 = config
                    //         .ecc_config
                    //         .gate
                    //         .load_witness(ctx, Value::known(self.rand0));
                    //     let assigned_rand1 = config
                    //         .ecc_config
                    //         .gate
                    //         .load_witness(ctx, Value::known(self.rand1));
                    //     let assigned_rand2 = config
                    //         .ecc_config
                    //         .gate
                    //         .load_witness(ctx, Value::known(self.rand2));
                    //     let new_rand = config.ecc_config.gate.add(
                    //         ctx,
                    //         QuantumCell::Existing(&assigned_rand0),
                    //         QuantumCell::Existing(&assigned_rand2),
                    //     );
                    //     let rand_point = ecc_config.scalar_mul(ctx, &base_point, &new_rand);
                    //     let assigned_priv_key0 = config
                    //         .ecc_config
                    //         .gate
                    //         .load_witness(ctx, Value::known(self.priv_key0));
                    //     let rand_pk = ecc_config.scalar_mul(ctx, &rand_point, &assigned_priv_key0);
                    //     let assigned_balance = config.ecc_config.gate.load_witness(
                    //         ctx,
                    //         Value::known(F::from((self.balance0 - self.transfer_amount) as u64)),
                    //     );
                    //     let balance_point =
                    //         config
                    //             .ecc_config
                    //             .scalar_mul(ctx, &base_point, &assigned_balance);
                    //     let c_l = config.ecc_config.add(ctx, &balance_point, &rand_pk);
                    //     let expected_sender_enc = AssignedBalanceEnc {
                    //         l: c_l,
                    //         r: rand_point.clone(),
                    //     };

                    //     let assigned_priv_key1 = config
                    //         .ecc_config
                    //         .gate
                    //         .load_witness(ctx, Value::known(self.priv_key1));
                    //     let rand_pk = ecc_config.scalar_mul(ctx, &rand_point, &assigned_priv_key1);
                    //     let assigned_balance = config.ecc_config.gate.load_witness(
                    //         ctx,
                    //         Value::known(F::from((self.balance1 + self.transfer_amount) as u64)),
                    //     );
                    //     let balance_point =
                    //         config
                    //             .ecc_config
                    //             .scalar_mul(ctx, &base_point, &assigned_balance);
                    //     let c_l = config.ecc_config.add(ctx, &balance_point, &rand_pk);
                    //     let expected_recipient_enc = AssignedBalanceEnc {
                    //         l: c_l,
                    //         r: rand_point,
                    //     };
                    //     (expected_sender_enc, expected_recipient_enc)
                    // };
                    // let is_eq =
                    //     config
                    //         .ecc_config
                    //         .is_equal(ctx, &transfereed.0.l, &expected_sender_enc.l);
                    // gate.assert_is_const(ctx, &is_eq, F::one());
                    // let is_eq =
                    //     config
                    //         .ecc_config
                    //         .is_equal(ctx, &transfereed.0.r, &expected_sender_enc.r);
                    // gate.assert_is_const(ctx, &is_eq, F::one());
                    // let is_eq = config.ecc_config.is_equal(
                    //     ctx,
                    //     &transfereed.1.l,
                    //     &expected_recipient_enc.l,
                    // );
                    // gate.assert_is_const(ctx, &is_eq, F::one());
                    // let is_eq = config.ecc_config.is_equal(
                    //     ctx,
                    //     &transfereed.1.r,
                    //     &expected_recipient_enc.r,
                    // );
                    // gate.assert_is_const(ctx, &is_eq, F::one());

                    Ok(())
                },
            )?;
            Ok(())
        }
    }

    impl<F: PrimeField> TestCircuit1<F> {
        const NUM_ADVICE: usize = 25;
        const NUM_FIXED: usize = 1;
        const LOOKUO_ADVICE: usize = 1;
        const K: usize = 15;
    }

    #[test]
    fn test_add_and_mul() {
        let rand0 = Fr::random(&mut OsRng);
        let rand1 = Fr::random(&mut OsRng);
        let rand2 = Fr::random(&mut OsRng);
        let priv_key0 = Fr::random(&mut OsRng);
        let priv_key1 = Fr::random(&mut OsRng);
        let circuit = TestCircuit1 {
            rand0,
            rand1,
            rand2,
            priv_key0,
            priv_key1,
            balance0: 100,
            balance1: 10,
            transfer_amount: 70,
        };
        let prover = MockProver::<Fr>::run(TestCircuit1::<Fr>::K as u32, &circuit, vec![]).unwrap();
        prover.verify().unwrap();
    }
}
