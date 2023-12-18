use crate::{domain::Scalar, public::PublicKey};

// TODO: shoud implement
pub(crate) fn sapling_hash(t: [u8; 80], vk: PublicKey, m: &[u8]) -> Scalar {
    Scalar::one()
}
