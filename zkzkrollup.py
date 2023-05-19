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


class TransactionProof:
    sender_raw_transfer_amount: FiniteField # private
    sender_private_key: FiniteField # private
    sender_after_balance: FiniteField # private
    randomness: FiniteField # private
    sender_public_key: EllipticCurvePoints
    recipient_public_key: EllipticCurvePoints
    sender_encrypted_balance: EncryptedBalance
    sender_transfer_amount: EncryptedBalance
    recipient_transfer_amount: EllipticCurvePoints


class MerkleProof:
    merkle_path: FiniteField
    nonce: FiniteField
    address: FiniteField
    signature: Signature


class PublicInputs:
    sender_public_key: EllipticCurvePoints
    recipient_public_key: EllipticCurvePoints
    sender_encrypted_balance: EncryptedBalance
    sender_transfer_amount: EncryptedBalance
    recipient_transfer_amount: EllipticCurvePoints
    merkle_path: FiniteField
    nonce: FiniteField
    address: FiniteField
    signature: Signature


class MerkleTree:
    leaves: [UserData]


class Layer2State:
    # merkle tree
    merkle: MerkleTree
    root: FiniteField

    # return user data by address
    def get(address: FiniteField) -> UserData:

    # geberate proof for batch transaction
    def prove(proofs: [Proof], public_inputs: [PublicInputs]) -> Proof:

    # sync with main chain
    def sync(proof: Proof, merkle_root: FiniteField):


class User:
    private_key: FiniteField
    public_key: EllipticCurvePoints

    # encrypt raw number
    def encrypt(num: int, randomness: int) -> EncryptedBalance:

    # sign transaction
    def sign(self, data: UserData) -> Signature:

    # generate proof for confidential transfer
    def prove(transfer: TransactionProof, merkle: MerkleProof) -> Proof:


class MainChainContract:
    merkle_root: FiniteField

    # verify proof
    # TODO: needs user data and to generate hash?
    def verify(proof: Proof, public_inputs: MerkleTree)


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

    # encrypt
    sender_transfer_amount = User(sender_private_key, sender_public_key).encrypt(transfer_amount)
    recipient_transfer_amount = User(sender_public_key).encrypt(transfer_amount)

    # transfer inputs
    transfer_randomness = 5
