from .type import EllipticCurvePoints, Signature

class L2BatchPublicInputs:
    prev_merkle_root: int
    new_merkle_root: int
    transactions: [L2TransactionPublicInput]


class L2TransactionPublicInput:
    sender_address: EllipticCurvePoints
    recipient_address: EllipticCurvePoints
    signature: (EllipticCurvePoints, EllipticCurvePoints)
    transfer_amount: int
    nonce: int


class L2MerkleProof:
    merkle_path: int
    nonce: int
    address: int
    signature: Signature
