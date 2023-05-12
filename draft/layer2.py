# define layer 2 operator
class L2Operator:
    # merkle tree
    merkle: L2MerkleTree
    root: int

    # return user data by address
    def get(address: Address) -> UserData:

    # geberate proof for batch transaction
    def prove(proofs: [Proof], public_inputs: [PublicInputs]) -> Proof:

    # sync with main chain
    def sync(proof: Proof, public_inputs: PublicInputs):


class L2MerkleTree:
    index: int
    root: int
    leaves: [UserData]

    # add leaf and calculate new merkle root
    def add(user_data: UserData):
        leaf = user_data.hash()
        leaves.append(leaf)
        new_root = hash(leaves)
        self.root = new_root

class L2UserData:
    balance: int
    nonce: int
    address: Address

    # generate hash leaf
    def hash() -> Address:


