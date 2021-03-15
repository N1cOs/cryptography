import common
import el_gamal as eg
import elliptic

if __name__ == "__main__":
    calc = elliptic.Calculator(common.CURVE, public_key=common.PUBLIC_KEY)

    codec = eg.AlphabetCodec(common.ALPHABET_PATH)
    el_gamal = eg.ElGamal(calc, common.GEN_POINT, codec)

    text = "уверовать"
    gen_factors = [6, 14, 5, 7, 12, 11, 4, 9, 19]
    encrypted = el_gamal.encrypt(text, gen_factors)
    for cipher in encrypted:
        print(cipher)
