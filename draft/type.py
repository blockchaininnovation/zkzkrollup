# define primitives
class EllipticCurvePoints:
    x: int
    y: int


class Proof((EllipticCurvePoints, EllipticCurvePoints, EllipticCurvePoints)):


class PublicParams:
    generator: EllipticCurvePoints


class Address(bytes):


class Signature((int, int)):
    def verify() -> bool:



