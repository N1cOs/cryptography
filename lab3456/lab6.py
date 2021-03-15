import common
import elliptic

if __name__ == "__main__":
    calc = elliptic.Calculator(common.CURVE)

    p = elliptic.Point(36, 87)
    print(calc.times(p, 111))
