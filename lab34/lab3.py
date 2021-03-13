import elliptic
import lab34

if __name__ == "__main__":
    calc = elliptic.Calculator(
        lab34.CURVE, lab34.GEN_POINT, public_key=lab34.PUBLIC_KEY
    )

    codec = lab34.AlphabetCodec()
    el_gamal = lab34.ElGamal(calc, codec)

    text = "уверовать"
    gen_factors = [6, 14, 5, 7, 12, 11, 4, 9, 19]
    encrypted = el_gamal.encrypt(text, gen_factors)
    for cipher in encrypted:
        print(cipher)
