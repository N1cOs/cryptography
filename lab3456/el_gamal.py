import json
from typing import Dict
from typing import List

import elliptic


class AlphabetCodec:
    def __init__(self, path: str = "alphabet.json"):
        self._direct = self._load(path)
        self._reverse = {v: k for k, v in self._direct.items()}
        assert len(self._direct) == len(self._reverse)

    def encode(self, symbol: str) -> elliptic.Point:
        pt = self._direct.get(symbol)
        if pt is None:
            raise ValueError(f"missing symbol in alphabet: {symbol}")
        return pt

    def decode(self, pt: elliptic.Point) -> str:
        sym = self._reverse.get(pt)
        if sym is None:
            raise ValueError(f"missing point in alphabet: {pt}")
        return sym

    def _load(self, path: str) -> Dict[str, elliptic.Point]:
        with open(path, "r") as f:
            raw = json.load(f)
            return {k: elliptic.Point(v[0], v[1]) for k, v in raw.items()}


class ElGamal:
    def __init__(self, calc: elliptic.Calculator, codec: AlphabetCodec):
        self.calc = calc
        self.codec = codec

    def encrypt(self, text: str, gen_factors: List[int]) -> List[elliptic.CipherPoint]:
        if len(text) != len(gen_factors):
            raise ValueError("length of `text` and `gen_factors` must be equal")

        res = []
        for sym, gen_factor in zip(text, gen_factors):
            pt = self.codec.encode(sym)
            res.append(self.calc.encrypt_point(pt, gen_factor))
        return res

    def decrypt(self, cipher: List[elliptic.CipherPoint]) -> str:
        syms = []
        for c in cipher:
            pt = self.calc.decrypt_point(c)
            syms.append(self.codec.decode(pt))
        return "".join(syms)
