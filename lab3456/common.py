import inspect
from os import path

import elliptic


def get_module_dir():
    return path.dirname(inspect.getfile(inspect.currentframe()))


ALPHABET_PATH = path.join(get_module_dir(), "alphabet.json")
CURVE = elliptic.Curve(-1, 1, 751)
GEN_POINT = elliptic.Point(0, 1)
PUBLIC_KEY = elliptic.Point(425, 663)
PRIVATE_KEY = 41
