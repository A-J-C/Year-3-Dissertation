#
#    File: pohlig_hellman.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.3
#    Date: 06/02/18
#
#    Functionality: uses pohlig_hellman method to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 pohlig_hellman.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#           for base-point G and public-point Q
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')
filePath = ""

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')
    filePath = "../"

# to make it backwards compatable with Python < 3.6
try:
    import secrets
except ImportError:
    from utils import secrets

import pickle
import time
from ECC import baby_step
from ECC.curves import *
from ECC.solver import Solver
from utils.helper import extended_gcd


############ GLOBAL CONSTANT #########

# we load the first million primes from memory
with open(filePath + "utils/millionPrimes.pkl", "rb") as f:
    primes = pickle.load(f)


############ PRIME FACTORISATION #########
def xgcd(a, b):
    """return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    x0, x1, y0, y1 = 0, 1, 1, 0
    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1
    return b, x0, y0

def primeFac(n):
    """ given a number returns a list of its prime factors """

    factors = {}
    p = 0

    while n != 1:                                                       # until n is 1 we don't have all the prime factors

        prime = primes[p]
        pCount = 0

        while n % prime == 0:                                           # while we can divide with no remainder
            n = int(n/prime)                                            # perform division
            pCount += 1                                                 # increment our count

        if pCount != 0:                                                 # see if it ever worked
            factors[prime] = pCount                                     # add to dictionary

        p += 1                                                          # get next prime

    return factors


############ MAIN CODE #########

class PHSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ baby-step giant-step uses a hash table to speed up
            finding a solution """

        # sanity check
        if self.G is None or self.curve is None or self.Q is None:
            print("Can't solve not all parameters are set")
            return False                                                # unsuccessful

        self.count = 0                                                  # initial count
        self.start = time.time()

        order = self.curve.order(self.G)                                # get order of generator

        ############ POHLIG HELLMAN ############
        factors = primeFac(order)                                       # get factor decomposition
        self.k = 0
        print(factors)
        for prime, power in factors.items():                            # loop over our dictionary
            newOrd = prime ** power                                     # calculate this subgroups order
            num = order // newOrd                                       # calculate number from order

            Gnum = self.G * num                                         # calculate two points on the curve
            Qnum = self.Q * num

            # now solve the smaller problem of Qnum = k_num * Gnum with order newOrd
            # using BSGS

            BSGS = baby_step.BGSolver(self.curve, Qnum, Gnum, False)    # initialise solver
            solved = BSGS.solve()                                       # specify the sub group order

            if not solved:
                print("Failed")
                return 0

            k_num = BSGS.k                                              # extract multiplier
            self.count += BSGS.count                                    # increment count

            # chinese remainder theorem
            gcd, quotient = extended_gcd(num, newOrd)

            add_k = k_num * num * quotient

            self.k += add_k

        print(order)
        print(self.k)
        self.k = self.k % order                                         # modulo

        self.time = time.time() - self.start

        if self.verbose:
            print("k:", self.k)
            print("Time taken: %.3f s" % (self.time))                   # print time taken
            print("Numbers checked:", self.count)                       # print total count

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = PHSolver()

    if len(sys.argv) >= 8:
        c_a = int(sys.argv[1])
        c_b = int(sys.argv[2])
        c_fp = int(sys.argv[3])
        G_x = int(sys.argv[4])
        G_y = int(sys.argv[5])
        Q_x = int(sys.argv[6])
        Q_y = int(sys.argv[7])
        C = Curve(c_a, c_b, c_fp)
        G = Point(G_x, G_y, C)
        Q = Point(Q_x, Q_y, C)
        solver.setCurve(C)
        solver.setG(G)
        solver.setQ(Q)
    if len(sys.argv) == 9:
        solver.setVerbose(int(sys.argv[8]))

    s = solver.solve()
    if not s:
        print("Input not of correct form: python3 pohlig_hellman.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]")
