class FiniteField(int):


class EllipticCurvePoints:
    x: int
    y: int


class EncryptedBalance:
    right: EllipticCurvePoints
    left: EllipticCurvePoints


class Signature((FiniteField, FiniteField)):


class Proof((EllipticCurvePoints, EllipticCurvePoints, EllipticCurvePoints)):


class PublicParams:
    generator: EllipticCurvePoints


class UserData:
    encrypted_balance: EncryptedBalance
    nonce: FiniteField
    address: FiniteField

    # generate hash leaf
    def hash() -> FiniteField:


class Transaction:
    sender_address: EllipticCurvePoints
    recipient_address: EllipticCurvePoints
    signature: (EllipticCurvePoints, EllipticCurvePoints)
    transfer_amount: FiniteField
    nonce: FiniteField


class MerkleProof:
    merkle_path: FiniteField
    nonce: FiniteField
    address: FiniteField
    signature: Signature


class PublicInputs:
    prev_merkle_root: FiniteField
    new_merkle_root: FiniteField


class MerkleTree:
    index: FiniteField
    root: FiniteField
    leaves: [UserData]

    # add leaf and calculate new merkle root
    def add(leaf: FiniteField) -> FiniteField:


class Layer2State:
    # merkle tree
    merkle: MerkleTree
    root: FiniteField

    # return user data by address
    def get(address: FiniteField) -> UserData:

    # geberate proof for batch transaction
    def prove(proofs: [Proof], public_inputs: [PublicInputs]) -> Proof:

    # sync with main chain
    def sync(proof: Proof, public_inputs: PublicInputs):


class User:
    private_key: FiniteField
    public_key: EllipticCurvePoints

    # sign transaction
    def sign(self, data: UserData) -> Signature:


def hash() -> FiniteField:

class MainChainContract:
    merkle_root: FiniteField
    leaf_index: FiniteField

    # deposit user asset
    def deposit() -> EllipticCurvePoints:
        # TODO: how to generate L2 key
        amount = msg.value
        address = msg.sender
        nonce = 0
        leaf = hash(amount, address, nonce)


    # update merkle root
    def update(new_merkle_root: FiniteField):
        merkle_root = new_merkle_root

    # verify proof
    def verify(proof: Proof, public_inputs: PublicInputs) -> bool:

    # add new leaf and return new merkle root
    def add_new_leaf() -> FiniteField:
        self.merkle_root

    # update merkle root
    def forge(proof: Proof, public_inputs: PublicInputs):
        assert self.verify(proof, public_inputs)
        assert merkle_root == public_inputs.prev_merkle_root
        self.update(public_inputs.new_merkle_root)


def confidential_transfer():
    # sender inputs
    transfer_amount = 1
    sender_private_key = 2
    sender_public_key = 3
    recipient_public_key = 4

    # addresses
    sender_address = sender_public_key.hash()
    recipient_address = recipient_public_key.hash()

    # get user data
    sender_data = Layer2State.get(sender_address)
    recipient_data = Layer2State.get(recipient_address)
