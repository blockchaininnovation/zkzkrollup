from .type import PublicInputs


class MainChainContract:
    merkle_root: int
    leaf_index: int

    # deposit user asset and emit event
    def deposit(jubjub_x: int, jubjub_y: int, amount: int):
        event(jubjub_x, jubjub_y, amount)

    # synchronize merkle tree
    def forge(proof: Proof, public_inputs: PublicInputs):
        assert self.verify(proof, public_inputs)
        assert merkle_root == public_inputs.prev_merkle_root
        self.update(public_inputs.new_merkle_root)

    # update merkle root
    def _update(new_merkle_root: int):
        merkle_root = new_merkle_root

    # verify proof
    def _verify(proof: Proof, public_inputs: PublicInputs) -> bool:

    # add new leaf and return new merkle root
    def _add_new_leaf() -> int:
        self.merkle_root
