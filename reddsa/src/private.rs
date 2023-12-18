use crate::domain::{Scalar, Affine};
use crate::hash::sapling_hash;
use crate::public::PublicKey;
use crate::signature::Signature;

use halo2_base::halo2_proofs::halo2curves::group::cofactor::CofactorCurveAffine;
use rand_core::RngCore;

pub struct PrivateKey(pub(crate) Scalar);

impl PrivateKey {
    pub fn new(value: Scalar) -> Self {
        Self(value)
    }

    pub fn to_pub(&self) -> PublicKey {
        let point = Affine::generator() * self.0;
        PublicKey(Affine::from(point))
    }

    pub fn sign(&self, m: &[u8], mut rand: impl RngCore) -> Signature {
        // T uniformly at random
        let mut t = [0u8; 80];
        rand.fill_bytes(&mut t[..]);

        // vk
        let vk = self.to_pub();
        // r
        let r = sapling_hash(t, vk, m);
        // R
        let large_r = Affine::generator() * r;
    }
}
