import elliptic
import lab3456

if __name__ == "__main__":
    calc = elliptic.Calculator(lab3456.CURVE, lab3456.GEN_POINT)

    p = elliptic.Point(59, 386)
    p2 = calc.times(p, 2)

    q = elliptic.Point(70, 195)
    q3 = calc.times(q, 3)

    r = elliptic.Point(72, 254)
    print(calc.sub(calc.sum(p2, q3), r))
