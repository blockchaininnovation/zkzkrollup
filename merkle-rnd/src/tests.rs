use group::ff::PrimeField;
use group::{Curve, Group};
use halo2_gadgets::ecc::chip::*;
use halo2_gadgets::ecc::FixedPoints;
use halo2_gadgets::sinsemilla::primitives::{self as sinsemilla};
use halo2_gadgets::sinsemilla::CommitDomains;
use halo2_gadgets::sinsemilla::HashDomains;
use halo2curves::pasta::pallas;
use lazy_static::lazy_static;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TestHashDomain;
impl HashDomains<pallas::Affine> for TestHashDomain {
    fn Q(&self) -> pallas::Affine {
        *Q
    }
}

// This test does not make use of the CommitDomain.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TestCommitDomain;
impl CommitDomains<pallas::Affine, TestFixedBases, TestHashDomain> for TestCommitDomain {
    fn r(&self) -> FullWidth {
        FullWidth::from_parts(*R, &R_ZS_AND_US)
    }

    fn hash_domain(&self) -> TestHashDomain {
        TestHashDomain
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct TestFixedBases;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct FullWidth(pallas::Affine, &'static [(u64, [pallas::Base; H])]);
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct BaseField;
#[derive(Debug, Eq, PartialEq, Clone)]
pub(crate) struct Short;

pub(crate) const PERSONALIZATION: &str = "MerkleCRH";
lazy_static! {
    static ref BASE: pallas::Affine = pallas::Point::generator().to_affine();
    static ref ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS).unwrap();
    static ref ZS_AND_US_SHORT: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*BASE, NUM_WINDOWS_SHORT).unwrap();
    static ref COMMIT_DOMAIN: sinsemilla::CommitDomain =
        sinsemilla::CommitDomain::new(PERSONALIZATION);
    static ref Q: pallas::Affine = COMMIT_DOMAIN.Q().to_affine();
    static ref R: pallas::Affine = COMMIT_DOMAIN.R().to_affine();
    static ref R_ZS_AND_US: Vec<(u64, [pallas::Base; H])> =
        find_zs_and_us(*R, NUM_WINDOWS).unwrap();
}

impl FullWidth {
    pub(crate) fn from_pallas_generator() -> Self {
        FullWidth(*BASE, &ZS_AND_US)
    }

    pub(crate) fn from_parts(
        base: pallas::Affine,
        zs_and_us: &'static [(u64, [pallas::Base; H])],
    ) -> Self {
        FullWidth(base, zs_and_us)
    }
}

impl FixedPoint<pallas::Affine> for FullWidth {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        self.0
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        self.1
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        self.1.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for BaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoint<pallas::Affine> for Short {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        *BASE
    }

    fn u(&self) -> Vec<[[u8; 32]; H]> {
        ZS_AND_US_SHORT
            .iter()
            .map(|(_, us)| {
                [
                    us[0].to_repr(),
                    us[1].to_repr(),
                    us[2].to_repr(),
                    us[3].to_repr(),
                    us[4].to_repr(),
                    us[5].to_repr(),
                    us[6].to_repr(),
                    us[7].to_repr(),
                ]
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        ZS_AND_US_SHORT.iter().map(|(z, _)| *z).collect()
    }
}

impl FixedPoints<pallas::Affine> for TestFixedBases {
    type FullScalar = FullWidth;
    type ShortScalar = Short;
    type Base = BaseField;
}
