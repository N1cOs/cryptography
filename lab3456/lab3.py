import elliptic
import lab3456

if __name__ == "__main__":
    calc = elliptic.Calculator(
        lab3456.CURVE, lab3456.GEN_POINT, public_key=lab3456.PUBLIC_KEY
    )

    codec = lab3456.AlphabetCodec()
    el_gamal = lab3456.ElGamal(calc, codec)

    text = "уверовать"
    gen_factors = [6, 14, 5, 7, 12, 11, 4, 9, 19]
    encrypted = el_gamal.encrypt(text, gen_factors)
    for cipher in encrypted:
        print(cipher)
