import argparse
import copy
import os
from typing import List

Int2DMatrix = List[List[int]]


class Rijndael:
    """
    An implementation of Rijndael algorithm with OFB mode.

    See Also:
        - https://autonome-antifa.org/IMG/pdf/Rijndael.pdf
        - https://medium.com/quick-code/understanding-the-advanced-encryption-standard-7d7884277e7
        - https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
        - https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Output_feedback_(OFB)
    """

    # fmt: off
    Sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
    )

    # fmt: off
    InvSbox = (
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
    )

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != len(iv):
            raise ValueError("length of key and iv must be equal")

        nk = len(key)
        block_size = 128
        if nk == 16:
            nr = 10
        elif nk == 24:
            nr = 12
        elif nk == 32:
            nr = 14
        else:
            raise ValueError("key's len must be one of: [16, 24, 32]")

        # number of rounds
        self.nr = nr
        # number of columns in State
        self.nb = block_size // 32
        self.iv = self._to_matrix(iv)
        self.key = self._to_matrix(key)

    def encrypt(self, data: bytes) -> bytes:
        """
        Encrypts data by blocks with adding padding if necessary.
        Each block is encrypted with OFB mode.
        """
        block_size = 16
        padding = block_size - len(data) % block_size
        data += b"\x00" * padding

        res = []
        last_block = copy.deepcopy(self.iv)
        for i in range(len(data) // block_size):
            self._encrypt_block(last_block)
            block = self._to_matrix(data[:block_size])
            # xor current block with previous one
            self.add_round_key(block, last_block)
            res.extend(self._flat(block))
            data = data[block_size:]

        return bytes(res)

    def _encrypt_block(self, block: Int2DMatrix):
        self.add_round_key(block, self.key)
        for i in range(self.nr - 1):
            self.sub_bytes(block)
            self.shift_rows(block)
            self.mix_columns(block)
            self.add_round_key(block, self.key)
        self.sub_bytes(block)
        self.shift_rows(block)
        self.add_round_key(block, self.key)

    def decrypt(self, data: bytes) -> bytes:
        """
        Decrypts data by blocks with discarding padding if necessary.
        Each block is decrypted with OFB mode.
        """
        res = []
        block_size = 16
        last_block = copy.deepcopy(self.iv)
        for i in range(len(data) // block_size):
            self._encrypt_block(last_block)
            block = self._to_matrix(data[:block_size])
            # xor ciphertext with previous block
            self.add_round_key(block, last_block)
            for b in self._flat(block):
                if b == 0:
                    break
                res.append(b)
            data = data[block_size:]
        return bytes(res)

    def _decrypt_block(self, block: Int2DMatrix):
        self.add_round_key(block, self.key)
        for i in range(self.nr - 1):
            self.inv_shift_rows(block)
            self.inv_sub_bytes(block)
            self.add_round_key(block, self.key)
            self.inv_mix_columns(block)
        self.inv_shift_rows(block)
        self.inv_sub_bytes(block)
        self.add_round_key(block, self.key)

    def sub_bytes(self, state: Int2DMatrix):
        """
        Replaces each value in `state` matrix with corresponding value from `Sbox`.
        """
        for i in range(4):
            for j in range(self.nb):
                byte = state[i][j]
                state[i][j] = self.Sbox[byte]

    def inv_sub_bytes(self, state: Int2DMatrix):
        """
        Replaces each value in `state` matrix with corresponding value from `InvSbox`.
        """
        for i in range(4):
            for j in range(self.nb):
                byte = state[i][j]
                state[i][j] = self.InvSbox[byte]

    def shift_rows(self, s: Int2DMatrix):
        """
        Shifts bytes of the last three rows cyclically to the left.
        """
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]

    def inv_shift_rows(self, s: Int2DMatrix):
        """
        Shifts bytes of the last three rows cyclically to the right.
        Inverse to `shift_rows` method.
        """
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]

    def mix_columns(self, state: Int2DMatrix):
        """
        Mixes columns by multiplying current `state` in predefined matrix
        which depends on current `state`.
        """
        for i in range(self.nb):
            self._mix_column(state[i])

    def inv_mix_columns(self, state: Int2DMatrix):
        """
        Performs inverse mixing of columns.
        """
        for i in range(self.nb):
            self._inv_mix_column(state[i])
            self._mix_column(state[i])

    def add_round_key(self, state: Int2DMatrix, key: Int2DMatrix):
        """
        Adds round `key` to a `current` state.
        """
        for i in range(4):
            for j in range(self.nb):
                state[i][j] ^= key[i][j]

    def _inv_mix_column(self, c: List[int]):
        """
        See Also:
            - Section 4.1.3 of `The Design of Rijndael`.
        """
        u = self._xtime(self._xtime(c[0] ^ c[2]))
        v = self._xtime(self._xtime(c[1] ^ c[3]))
        c[0] ^= u
        c[1] ^= v
        c[2] ^= u
        c[3] ^= v

    def _mix_column(self, c: List[int]):
        """
        See Also:
            - Section 5.1 of specification.
        """
        t = c[0] ^ c[1] ^ c[2] ^ c[3]
        u = c[0]
        c[0] ^= self._xtime(c[0] ^ c[1]) ^ t
        c[1] ^= self._xtime(c[1] ^ c[2]) ^ t
        c[2] ^= self._xtime(c[2] ^ c[3]) ^ t
        c[3] ^= self._xtime(c[3] ^ u) ^ t

    def _xtime(self, byte: int) -> int:
        byte <<= 1
        if byte & 0x80:
            byte ^= 0x1b
        return byte & 0xff

    @staticmethod
    def _to_matrix(data: bytes) -> Int2DMatrix:
        res = []
        rows_elems = len(data) // 4
        for i in range(4):
            row = []
            for j in range(rows_elems):
                row.append(data[i * rows_elems + j])
            res.append(row)
        return res

    @staticmethod
    def _flat(matrix: Int2DMatrix) -> List[int]:
        res = []
        for i in range(4):
            for b in matrix[i]:
                res.append(b)
        return res


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="path to file which will be encrypted and then decrypted",
    )
    args = parser.parse_args()

    key = os.urandom(16)
    iv = os.urandom(16)
    aes = Rijndael(key, iv)

    with open(args.file, "rb") as f:
        encrypted = aes.encrypt(f.read())
        with open(args.file + ".enc", "wb") as ef:
            ef.write(encrypted)

        with open(args.file + ".dec", "wb") as df:
            df.write(aes.decrypt(encrypted))
