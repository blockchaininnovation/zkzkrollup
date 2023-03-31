
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
