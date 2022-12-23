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
    },
    pcs::kzg::{Gwc19, Kzg, KzgSuccinctVerifyingKey},
    system::{
        self,
        halo2::{compile, transcript::evm::EvmTranscript, Config},
    },
    verifier::{self, PlonkVerifier},
    Protocol,
};
use rand::{rngs::OsRng, RngCore};
use std::io::Read;
use std::marker::PhantomData;
use std::rc::Rc;

#[derive(Clone)]
pub struct Snark {
    pub(crate) protocol: Protocol<G1Affine>,
    pub(crate) instances: Vec<Vec<Fr>>,
    pub(crate) proof: Vec<u8>,
}

impl Snark {
    pub fn new(protocol: Protocol<G1Affine>, instances: Vec<Vec<Fr>>, proof: Vec<u8>) -> Self {
        Self {
            protocol,
            instances,
            proof,
        }
    }
}

impl From<Snark> for SnarkWitness {
    fn from(snark: Snark) -> Self {
        Self {
            protocol: snark.protocol,
            instances: snark
                .instances
                .into_iter()
                .map(|instances| instances.into_iter().map(Value::known).collect_vec())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

#[derive(Clone)]
pub struct SnarkWitness {
    pub(crate) protocol: Protocol<G1Affine>,
    pub(crate) instances: Vec<Vec<Value<Fr>>>,
    pub(crate) proof: Value<Vec<u8>>,
}

impl SnarkWitness {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            instances: self
                .instances
                .iter()
                .map(|instances| vec![Value::unknown(); instances.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }

    pub fn proof(&self) -> Value<&[u8]> {
        self.proof.as_ref().map(Vec::as_slice)
    }
}
