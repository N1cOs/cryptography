import elliptic
import lab3456

if __name__ == "__main__":
    calc = elliptic.Calculator(lab3456.CURVE, lab3456.GEN_POINT)

    p = elliptic.Point(36, 87)
    print(calc.times(p, 111))
