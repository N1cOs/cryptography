import argparse
import itertools as it
from typing import List, Callable


def mirror_horizontally(matrix):
    """
    Mirrors `matrix` around y axis.
    Example:
        [                   [
            [1, 2, 3],          [3, 2, 1],
            [4, 5, 6],  --->    [6, 5, 4],
            [7, 8, 9]           [9, 8, 7]
        ]                   ]
    """
    res = []
    for row in range(len(matrix)):
        new_row = []
        for column in range(len(matrix[0]) - 1, -1, -1):
            new_row.append(matrix[row][column])
        res.append(new_row)
    return res


def mirror_vertically(matrix):
    """
    Mirrors `matrix` around x axis.
    Example:
        [                   [
            [1, 2, 3],          [7, 8, 9],
            [4, 5, 6], --->     [4, 5, 6],
            [7, 8, 9]           [1, 2, 3]
        ]                   ]
    """
    res = []
    for row in range(len(matrix) - 1, -1, -1):
        new_row = []
        for column in range(len(matrix[0])):
            new_row.append(matrix[row][column])
        res.append(new_row)
    return res


class CardanGrille:
    """
    An implementation of Cardan grille algorithm.

    See Also:
        - https://sites.google.com/site/anisimovkhv/publication/umr/kriptografia/lr2
    """

    def __init__(self, mask: List[List[bool]], transformations: List[Callable]):
        self.mask = mask
        self.transformations = transformations

    def encrypt(self, data: bytes) -> bytes:
        res = []
        encrypted = 0
        size = len(self.mask)

        mask = self.mask.copy()
        transformations = it.cycle(self.transformations)
        while True:
            grille = [[0 for _ in range(size)] for _ in range(size)]
            for _ in range(size):
                for i in range(size):
                    for j in range(size):
                        if encrypted == len(data):
                            self._write_grille(res, grille)
                            return bytes(res)

                        if mask[i][j]:
                            if grille[i][j] != 0:
                                raise ValueError(
                                    "rewriting not 0 value in grille, check transformations"
                                )

                            grille[i][j] = data[encrypted]
                            encrypted += 1
                transform = next(transformations)
                mask = transform(mask)
            self._write_grille(res, grille)

    def decrypt(self, data: bytes) -> bytes:
        res = []
        size = len(self.mask)

        grille = self.mask.copy()
        transformations = it.cycle(self.transformations)
        while data:
            window = self._read_grille(data, size)

            for _ in range(size):
                for i in range(size):
                    for j in range(size):
                        # skipping 0 values because of the padding in encryption stage
                        if window[i][j] == 0:
                            continue
                        if grille[i][j]:
                            res.append(window[i][j])
                transform = next(transformations)
                grille = transform(grille)

            off = size * size
            data = data[off:]
        return bytes(res)

    @staticmethod
    def _write_grille(target: List[int], grille: List[List[int]]):
        """
        Writes grille to `target` list from top to bottom
        and from left to right.
        """
        for i in range(len(grille)):
            for j in range(len(grille[0])):
                target.append(grille[j][i])

    @staticmethod
    def _read_grille(data: bytes, size: int) -> List[List[int]]:
        """
        Reads grille from specified `data` and fill grille
        from top to bottom and from left to right.
        """
        grille = [[0 for _ in range(size)] for _ in range(size)]
        it = iter(data)
        for i in range(size):
            for j in range(size):
                grille[j][i] = next(it)
        return grille


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="path to file which will be encrypted and then decrypted",
    )
    args = parser.parse_args()

    mask = [
        [True, False, True, False],
        [False, False, False, False],
        [False, True, False, True],
        [False, False, False, False],
    ]
    transformations = [
        mirror_horizontally,
        mirror_vertically,
        mirror_horizontally,
        mirror_vertically,
    ]
    cardan = CardanGrille(mask, transformations)

    with open(args.file, "rb") as f:
        encrypted = cardan.encrypt(f.read())
        with open(args.file + ".enc", "wb") as ef:
            ef.write(encrypted)

        with open(args.file + ".dec", "wb") as df:
            df.write(cardan.decrypt(encrypted))
