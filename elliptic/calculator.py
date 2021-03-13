import dataclasses
from typing import Optional, Tuple


@dataclasses.dataclass
class Curve:
    a: int
    b: int
    p: int


@dataclasses.dataclass(frozen=True)
class Point:
    x: int
    y: int


CipherPoint = Tuple[Point, Point]


class Calculator:
    def __init__(
        self,
        curve: Curve,
        gen_point: Point,
        *,
        public_key: Optional[Point] = None,
        private_key: Optional[int] = None,
    ):
        self.curve = curve
        self.gen_point = gen_point
        self.public_key = public_key
        self.private_key = private_key

    def encrypt_point(self, pt: Point, gen_factor: int) -> CipherPoint:
        if self.public_key is None:
            raise ValueError("failed to encrypt point: public key is None")
        pt1 = self.times(self.gen_point, gen_factor)
        pt2 = self.sum(pt, self.times(self.public_key, gen_factor))
        return pt1, pt2

    def decrypt_point(self, cipher: CipherPoint) -> Point:
        if self.private_key is None:
            raise ValueError("failed to decrypt point: private key is None")

        pt1, pt2 = cipher
        return self.sub(pt2, self.times(pt1, self.private_key))

    def times(self, pt: Point, n: int) -> Optional[Point]:
        res = None
        summed = pt
        while n > 0:
            if n & 1 == 1:
                res = self.sum(res, summed)

            summed = self.sum(summed, summed)
            n >>= 1
        return res

    def sum(self, pt1: Optional[Point], pt2: Optional[Point]) -> Optional[Point]:
        if pt1 is None:
            # O + P2 = P2
            return pt2
        if pt2 is None:
            # P1 + O = P1
            return pt1

        if pt1.x == pt2.x and pt1.y != pt2.y:
            # P - P = O
            return None

        if pt1 == pt2:
            l = self._mod_div(3 * pt1.x ** 2 + self.curve.a, 2 * pt1.y)
        else:
            l = self._mod_div(pt2.y - pt1.y, pt2.x - pt1.x)

        x3 = l ** 2 - pt1.x - pt2.x
        y3 = l * (x3 - pt1.x) + pt1.y
        return Point(x3 % self.curve.p, -y3 % self.curve.p)

    def sub(self, pt1: Optional[Point], pt2: Optional[Point]) -> Optional[Point]:
        if pt2 is None:
            return pt1

        neg_pt2 = Point(pt2.x, -pt2.y % self.curve.p)
        return self.sum(pt1, neg_pt2)

    def _mod_div(self, a: int, b: int) -> int:
        b_inv = self._mod_inverse(b)
        return (a * b_inv) % self.curve.p

    def _mod_inverse(self, val: int) -> int:
        for i in range(self.curve.p):
            t = val * i
            if t % self.curve.p == 1:
                return i
        raise ValueError(f"val={val} and p={self.curve.p} have same prime factor")
