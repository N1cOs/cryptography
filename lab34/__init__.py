import elliptic
from .el_gamal import ElGamal, AlphabetCodec

CURVE = elliptic.Curve(-1, 1, 751)
GEN_POINT = elliptic.Point(0, 1)
PUBLIC_KEY = elliptic.Point(425, 663)
PRIVATE_KEY = 41

__all__ = [
    "CURVE",
    "GEN_POINT",
    "PUBLIC_KEY",
    "PRIVATE_KEY",
    "ElGamal",
    "AlphabetCodec",
]
