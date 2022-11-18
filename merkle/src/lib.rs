pub fn add(left: usize, right: usize) -> usize {
    left + right
}

// #[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

use rs_merkle::{algorithms::Sha256, utils, Error, Hasher, MerkleProof, MerkleTree};
use std::convert::TryFrom;

#[cfg(test)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let leaf_values = ["a", "b", "c", "d", "e", "f"];
    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();
    let merkle_tree = MerkleTree::<Sha256>::from_leaves(&leaves);
    let indices_to_prove = vec![3, 4];
    let leaves_to_prove = leaves.get(3..5).ok_or("can't get leaves to prove")?;
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root")?;
    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();
    // Parse proof back on the client
    let proof = MerkleProof::<Sha256>::try_from(proof_bytes)?;
    assert!(proof.verify(
        merkle_root,
        &indices_to_prove,
        leaves_to_prove,
        leaves.len()
    ));
    Ok(())
}
