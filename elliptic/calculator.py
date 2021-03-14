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
        log: bool = False,
    ):
        self.curve = curve
        self.gen_point = gen_point
        self.public_key = public_key
        self.private_key = private_key
        self.log = log

    def encrypt_point(self, pt: Point, gen_factor: int) -> CipherPoint:
        if self.public_key is None:
            raise ValueError("failed to encrypt point: public key is None")

        if self.log:
            print(f"encrypt_point: P={pt}, k={gen_factor}")

        pt1 = self.times(self.gen_point, gen_factor)
        pt2 = self.sum(pt, self.times(self.public_key, gen_factor))

        if self.log:
            print(f"encrypt_point: C1={pt1}, C2={pt2}")
            print("-" * 80)

        return pt1, pt2

    def decrypt_point(self, cipher: CipherPoint) -> Point:
        if self.private_key is None:
            raise ValueError("failed to decrypt point: private key is None")

        pt1, pt2 = cipher
        if self.log:
            print(f"decrypt_point: C={cipher}, n_b={self.private_key}")

        pt = self.sub(pt2, self.times(pt1, self.private_key))
        if self.log:
            print(f"decrypt_point: P={pt}")
            print("-" * 80)

        return pt

    def times(self, pt: Point, n: int) -> Optional[Point]:
        if self.log:
            print(f"times: P*n: P={pt}, n={n}")

        terms = []
        factors = [False] * 12

        i = 0
        summed = pt
        while n > 0:
            if n & 1 == 1:
                factors[i] = True

            terms.append(summed)
            summed = self.sum(summed, summed)

            n >>= 1
            i += 1

        powers_log = []
        powers_val = []
        res = None
        for i, f in enumerate(factors):
            if f:
                res = self.sum(res, terms[i])
                powers_log.append(f"2^{i}")
                powers_val.append(terms[i])

        if self.log:
            print(f"times: P*n =", end=" ")

            for i, p in enumerate(reversed(powers_log)):
                if i == len(powers_log) - 1:
                    end = " = "
                else:
                    end = " + "
                print(f"{p}*P", end=end)

            for i, p in enumerate(reversed(powers_val)):
                if i == len(powers_log) - 1:
                    end = " = "
                else:
                    end = " + "
                print(f"{p}", end=end)

        return res

    def sum(self, pt1: Optional[Point], pt2: Optional[Point]) -> Optional[Point]:
        if self.log:
            print(f"sum: P1+P2: P1={pt1}, P2={pt2}")

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
            a, b = 3 * pt1.x ** 2 + self.curve.a, 2 * pt1.y
            l = self._mod_div(a, b)

            if self.log:
                msg = f"lambda = [3 * ({pt1.x})^2 + ({self.curve.a})] / [2 * ({pt1.y})] = {a} / {b} = {l}"
                print(f"sum: {msg}")
        else:
            a, b = pt2.y - pt1.y, pt2.x - pt1.x
            l = self._mod_div(a, b)

            if self.log:
                msg = f"lambda = [({pt2.y}) - ({pt1.y})] / [({pt2.x}) - ({pt1.x})] = {a} / {b} = {l}"
                print(f"sum: {msg}")

        x3 = l ** 2 - pt1.x - pt2.x
        y3 = l * (x3 - pt1.x) + pt1.y
        pt3 = Point(x3 % self.curve.p, -y3 % self.curve.p)

        if self.log:
            print(f"sum: x3 = ({l}) ^ 2 - ({pt1.x}) - ({pt2.x}) = {x3}")
            print(f"sum: y3 = ({l}) * [({x3}  - ({pt1.x}))] + ({pt1.y}) = {y3}")
            print(f"sum: P3: {pt3}")

        return pt3

    def sub(self, pt1: Optional[Point], pt2: Optional[Point]) -> Optional[Point]:
        if pt2 is None:
            return pt1

        neg_pt2 = Point(pt2.x, -pt2.y % self.curve.p)
        if self.log:
            print(f"sub: P1-P2: P1={pt1}, -P2={neg_pt2}")

        res = self.sum(pt1, neg_pt2)
        if self.log:
            print(f"sub: P1-P2: {res}")

        return res

    def _mod_div(self, a: int, b: int) -> int:
        b_inv = self._mod_inverse(b)
        return (a * b_inv) % self.curve.p

    def _mod_inverse(self, val: int) -> int:
        for i in range(self.curve.p):
            t = val * i
            if t % self.curve.p == 1:
                return i
        raise ValueError(f"val={val} and p={self.curve.p} have same prime factor")
