from .wallet import Bn256PrivateKey, JubjubPrivateKey

# transfer sender to recipient
def sender_to_recipient():
    # deposit transaction data
    deposit_amount = 1
    sender_l1_private_key = Bn256PrivateKey()
    sender_l1_public_key = sender_l1_private_key.public_key()
    sender_l2_private_key = JubjubPrivateKey()
    sender_l2_public_key = sender_l2_private_key.public_key()

    # 1. deposit
    MainChainContract(sender_l2_public_key.x, sender_l2_public_key.y, deposit_amount)

    # operator data
    
    operator = L2Operator()
    # synchronize data
    nonce = 0
    deposit_amount = 1
    public_key_x = 2
    public_key_y = 3
    deposit_address = EllipticCurvePoints(public_key_x, public_key_y).hash()

    # 2. synchronize
    user_data = L2UserData(amount, nonce, address)
    leaf = user_data.hash()
    L2MerkleTree().add(leaf)




# 2. Operator synchornize deposit on layer 2
def synchronize(x: int, y: int, amount: int):
    # deposit info
    nonce = 0
    address = EllipticCurvePoints(x, y).hash()


# 3. Alice transfer to Bob on layer 2
def transfer()
