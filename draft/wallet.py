from .type import Address

# define Weierstrass and Edwards wallets
class L1Wallet:
    private_key: Bn256PrivateKey
    public_key: Bn256PublicKey
    address: Address


class L2Wallet:
    private_key: JubjubPrivateKey
    public_key: JubjubPublicKey
    address: Address



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
