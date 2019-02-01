#
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 0.1
#    Date: 06/11/18
#

import sys
from generateECC import *
import math
import time

def run(babyStep = True, brute = True):
    """ generates an Eliptic Curve to perform operations over """

    C = CurveOverFp(0, 1, 7, 729787)
    P = Point(1,3)
    o = C.order(P)
    n, Q = generate_keypair(C, P, o//4)


    print(str(n) + "P:", Q)

    if brute:
        start = time.time()
        n = crack_brute_force(C, P, o, Q)                             # factor n
        print("n:", n, "Time: %.2f s" % (time.time() - start))

    if babyStep:
        start = time.time()
        n = crack_baby_giant(C, P, o, Q)                             # factor n
        print("n:", n, "Time: %.2f s" % (time.time() - start))


if __name__ == '__main__':

    if len(sys.argv) == 3:
        run(int(sys.argv[1]), int(sys.argv[2]))
    elif len(sys.argv) == 2:
        run(int(sys.argv[1]))
    else:
        run()
