import common
import el_gamal as eg
import elliptic

if __name__ == "__main__":
    calc = elliptic.Calculator(
        common.CURVE, common.GEN_POINT, private_key=common.PRIVATE_KEY
    )

    codec = eg.AlphabetCodec()
    el_gamal = eg.ElGamal(calc, codec)

    cipher = [
        (elliptic.Point(283, 493), elliptic.Point(314, 127)),
        (elliptic.Point(425, 663), elliptic.Point(561, 140)),
        (elliptic.Point(568, 355), elliptic.Point(75, 433)),
        (elliptic.Point(440, 539), elliptic.Point(602, 627)),
        (elliptic.Point(188, 93), elliptic.Point(395, 414)),
        (elliptic.Point(179, 275), elliptic.Point(25, 604)),
        (elliptic.Point(72, 254), elliptic.Point(47, 349)),
        (elliptic.Point(72, 254), elliptic.Point(417, 137)),
        (elliptic.Point(188, 93), elliptic.Point(298, 225)),
        (elliptic.Point(56, 419), elliptic.Point(79, 111)),
    ]
    print(el_gamal.decrypt(cipher))
