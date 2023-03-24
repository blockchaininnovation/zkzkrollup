# define primitives
class FiniteField(int):


class Address(bytes):


class EllipticCurvePoints:
    x: int
    y: int


class Bn256PrivateKey(int):
    def gen() -> self:

    def sign(data: bytes):

    def public_key(self) -> Bn256PublicKey:


class Bn256PublicKey(EllipticCurvePoints):
    def hash() -> Address:


class JubjubPrivateKey(int):
    def gen() -> self:

    def sign(data: bytes):

    def public_key(self) -> JubjubPublicKey:


class JubjubPublicKey(EllipticCurvePoints):
    def hash() -> Address:


class Signature((int, int)):
    def verify() -> bool:


class Proof((EllipticCurvePoints, EllipticCurvePoints, EllipticCurvePoints)):


class PublicParams:
    generator: EllipticCurvePoints


# define layer 2 components
class L2UserData:
    balance: int
    nonce: int
    address: int

    # generate hash leaf
    def hash() -> int:


class L2TransactionPublicInput:
    sender_address: EllipticCurvePoints
    recipient_address: EllipticCurvePoints
    signature: (EllipticCurvePoints, EllipticCurvePoints)
    transfer_amount: int
    nonce: int


class L2MerkleProof:
    merkle_path: FiniteField
    nonce: FiniteField
    address: FiniteField
    signature: Signature


class L2BatchPublicInputs:
    prev_merkle_root: FiniteField
    new_merkle_root: FiniteField
    transactions: [L2TransactionPublicInput]


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


class L2Wallet:
    private_key: JubjubPrivateKey
    public_key: JubjubPublicKey
    address: Address


class L2State:
    # merkle tree
    merkle: MerkleTree
    root: FiniteField

    # return user data by address
    def get(address: FiniteField) -> UserData:

    # geberate proof for batch transaction
    def prove(proofs: [Proof], public_inputs: [PublicInputs]) -> Proof:

    # sync with main chain
    def sync(proof: Proof, public_inputs: PublicInputs):


# define layer 1 components
class Layer1Wallet:
    private_key: Bn256PrivateKey
    public_key: Bn256PublicKey
    address: Address


class MainChainContract:
    merkle_root: FiniteField
    leaf_index: FiniteField

    # deposit user asset and emit event
    def deposit(jubjub_x: int, jubjub_y: int, amount: int):
        event(jubjub_x, jubjub_y, amount)


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


def transfer():
    # sender inputs
    transfer_amount = 1
    sender_private_key = 2
    sender_public_key = 3
    recipient_public_key = 4

    # addresses
    sender_address = sender_public_key.hash()
    recipient_address = recipient_public_key.hash()

    # get user data
    sender_data = L2State.get(sender_address)
    recipient_data = L2State.get(recipient_address)

# 1. Alice deposit to layer 1
def deposit(sender_bn256_private_key: int, sender_jubjub_private_key: int):
    # sender info
    deposit_amount = 1
    sender_bn256_private_key = Bn256PrivateKey(2)
    sender_bn256_public_key = sender_bn256_private_key.public_key()
    sender_jubjub_private_key = JubjubPrivateKey(2)
    sender_jubjub_public_key = sender_jubjub_private_key.public_key()

    MainChainContract(sender_jubjub_public_key.x, sender_jubjub_public_key.y, deposit_amount)


# 2. Operator synchornize deposit on layer 2
def synchronize(x: int, y: int, amount: int):
    # deposit info
    nonce = 0
    address = EllipticCurvePoints(x, y).hash()
    user_data = L2UserData(amount, nonce, address)
    leaf = user_data.hash()
    L2MerkleTree().add(leaf)

# 3. Alice transfer to Bob on layer 2
def transfer()
