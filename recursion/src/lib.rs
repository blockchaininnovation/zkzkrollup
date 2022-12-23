mod utils;
use halo2_wrong_ecc::EccConfig;
use halo2wrong::curves::bn256::{Bn256, Fq, Fr, G1Affine};
use halo2wrong::curves::pasta::pallas::Base;
use halo2wrong::curves::CurveAffine;
use halo2wrong::halo2::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::AccumulatorStrategy,
        },
        Rotation, VerificationStrategy,
    },
    transcript::{TranscriptReadBuffer, TranscriptWriterBuffer},
};
use itertools::Itertools;
use maingate::{
    big_to_fe, decompose_big, fe_to_big, AssignedValue, MainGate, MainGateConfig,
    MainGateInstructions, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
};
use plonk_verifier::{
    loader::{
        self,
        evm::{self, encode_calldata, EvmLoader, ExecutorBuilder},
        halo2::EccInstructions,
        native::NativeLoader,
    },
    pcs::{
        kzg::{Gwc19, Kzg, KzgAccumulator, KzgAs, KzgSuccinctVerifyingKey},
        AccumulationScheme, AccumulationSchemeProver,
    },
    system::{
        self,
        halo2::{compile, transcript::evm::EvmTranscript, Config},
    },
    util::arithmetic::fe_to_limbs,
    verifier::{self, PlonkVerifier},
};
use rand::{rngs::OsRng, RngCore};
use std::io::Read;
use std::marker::PhantomData;
use std::rc::Rc;
pub use utils::{Snark, SnarkWitness};

type Plonk = verifier::Plonk<Kzg<Bn256, Gwc19>>;
type BaseFieldEccChip = halo2_wrong_ecc::BaseFieldEccChip<G1Affine, NUMBER_OF_LIMBS, BIT_LEN_LIMB>;
type Halo2Loader<'a> = loader::halo2::Halo2Loader<'a, G1Affine, BaseFieldEccChip>;
type As = KzgAs<Kzg<Bn256, Gwc19>>;
const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 68;
// https://github.com/privacy-scaling-explorations/plonk-verifier/blob/5c31088f8530470227c411b5d168b445cb59858b/src/system/halo2/test/kzg/halo2.rs
const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 60;
type PoseidonTranscript<'a, L, S> =
    system::halo2::transcript::halo2::PoseidonTranscript<G1Affine, L, S, T, RATE, R_F, R_P>;

#[derive(Debug, Clone)]
pub struct Halo2AccumulatorConfig {
    /// Configuration for [`BaseFieldEccChip`].
    ecc_config: EccConfig,
}

impl Halo2AccumulatorConfig {
    pub fn new(ecc_config: EccConfig) -> Self {
        Self { ecc_config }
    }

    fn ecc_chip_config(&self) -> EccConfig {
        self.ecc_config.clone()
    }
}

const LIMBS: usize = 4;
const BITS: usize = 68;

#[derive(Clone)]
pub struct Halo2AccumulatorChip {
    config: Halo2AccumulatorConfig,
    svk: KzgSuccinctVerifyingKey<G1Affine>,
    snarks: Vec<SnarkWitness>,
    instances: Vec<Fr>,
    as_proof: Value<Vec<u8>>,
}

impl Halo2AccumulatorChip {
    pub fn new(
        config: Halo2AccumulatorConfig,
        params: &ParamsKZG<Bn256>,
        snarks: impl IntoIterator<Item = Snark>,
    ) -> Self {
        let svk = params.get_g()[0].into();
        let snarks = snarks.into_iter().collect_vec();
        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let mut transcript =
                    PoseidonTranscript::<NativeLoader, _>::new(snark.proof.as_slice());
                let proof =
                    Plonk::read_proof(&svk, &snark.protocol, &snark.instances, &mut transcript)
                        .unwrap();
                Plonk::succinct_verify(&svk, &snark.protocol, &snark.instances, &proof).unwrap()
            })
            .collect_vec();

        let (accumulator, as_proof) = {
            let mut transcript = PoseidonTranscript::<NativeLoader, _>::new(Vec::new());
            let accumulator =
                As::create_proof(&Default::default(), &accumulators, &mut transcript, OsRng)
                    .unwrap();
            (accumulator, transcript.finalize())
        };

        let KzgAccumulator { lhs, rhs } = accumulator;
        let instances = [lhs.x, lhs.y, rhs.x, rhs.y]
            .map(fe_to_limbs::<_, _, LIMBS, BITS>)
            .concat();

        Self {
            config,
            svk,
            snarks: snarks.into_iter().map_into().collect(),
            instances,
            as_proof: Value::known(as_proof),
        }
    }

    pub fn ecc_chip(&self) -> BaseFieldEccChip {
        BaseFieldEccChip::new(self.config.ecc_config.clone())
    }

    pub fn loader<'a>(
        &self,
        ctx: <BaseFieldEccChip as EccInstructions<'a, G1Affine>>::Context,
    ) -> Rc<Halo2Loader<'a>> {
        Halo2Loader::new(self.ecc_chip(), ctx)
    }

    pub fn accumulate<'a>(
        &'a self,
        ctx: <BaseFieldEccChip as EccInstructions<'a, G1Affine>>::Context,
        params: &ParamsKZG<Bn256>,
        snarks: &[SnarkWitness],
        as_proof: Value<&'a [u8]>,
    ) -> Result<KzgAccumulator<G1Affine, Rc<Halo2Loader>>, Error> {
        let loader = self.loader(ctx);
        let svk: KzgSuccinctVerifyingKey<G1Affine> = params.get_g()[0].into();

        let assign_instances = |instances: &[Vec<Value<Fr>>]| {
            instances
                .iter()
                .map(|instances| {
                    instances
                        .iter()
                        .map(|instance| loader.assign_scalar(*instance))
                        .collect_vec()
                })
                .collect_vec()
        };

        let accumulators = snarks
            .iter()
            .flat_map(|snark| {
                let protocol = snark.protocol.loaded(&loader);
                let instances = assign_instances(&snark.instances);
                let mut transcript =
                    PoseidonTranscript::<Rc<Halo2Loader>, _>::new(&loader, snark.proof());
                let proof =
                    Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
                Plonk::succinct_verify(&svk, &protocol, &instances, &proof).unwrap()
            })
            .collect_vec();

        let acccumulator = {
            let mut transcript = PoseidonTranscript::<Rc<Halo2Loader>, _>::new(&loader, as_proof);
            let proof =
                As::read_proof(&Default::default(), &accumulators, &mut transcript).unwrap();
            As::verify(&Default::default(), &accumulators, &proof).unwrap()
        };

        Ok(acccumulator)
    }
}
/*
fn gen_srs(k: u32) -> ParamsKZG<Bn256> {
    ParamsKZG::<Bn256>::setup(k, OsRng)
}

fn gen_pk<C: Circuit<Fr>>(params: &ParamsKZG<Bn256>, circuit: &C) -> ProvingKey<G1Affine> {
    let vk = keygen_vk(params, circuit).unwrap();
    keygen_pk(params, vk, circuit).unwrap()
}

fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}

fn gen_evm_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );

    let loader = EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}

fn gen_verifier_circuit(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    num_instance: Vec<usize>,
) -> Vec<u8> {
    let svk = params.get_g()[0].into();
    let dk = (params.g2(), params.s_g2()).into();
    let protocol = compile(
        params,
        vk,
        Config::kzg().with_num_instance(num_instance.clone()),
    );

    let loader = Halo2Loader::new();
    EvmLoader::new::<Fq, Fr>();
    let protocol = protocol.loaded(&loader);
    let mut transcript = EvmTranscript::<_, Rc<EvmLoader>, _, _>::new(&loader);

    let instances = transcript.load_instances(num_instance);
    let proof = Plonk::read_proof(&svk, &protocol, &instances, &mut transcript).unwrap();
    Plonk::verify(&svk, &dk, &protocol, &instances, &proof).unwrap();

    evm::compile_yul(&loader.yul_code())
}
*/
