#
#    File: mov_attack.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 08/04/19
#
#    Functionality: uses MOV attack and index calculus to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 mov_attack.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#           for base-point G and public-point Q
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

# to make it backwards compatable with Python < 3.6
try:
    import secrets
except ImportError:
    from utils import secrets

import time
from ECC.curves import *
from ECC.solver import Solver
from utils.helper import modInverse


############ MAIN CODE #########

class MOVSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ first determines if curve is suceptible to a MOV attack
            if it is then converts ECDLP tp DLP and runs Index-Calculus
            to solve it """

        # sanity check
        if self.G is None or self.curve is None or self.Q is None:
            print("Can't solve not all parameters are set")
            return False                                            # unsuccessful

        self.count = 1                                              # initial count
        self.start = time.time()


        ############ CHECK IF CURVE IS SUCEPTIBLE ############
        degree = 2
        card = self.curve.card
        p = self.curve.fp
        found = False

        if p % 4 == 3 and isPrime((p+1)/4):
            embedding = (pow(self.curve.fp, degree) - 1) / card

            if embedding == int(embedding):
                found = True

        if not found:
            if self.verbose:
                print("Not Suceptible to MOV attack")
            return False


        ############ IF IT IS CONVERT ECDLP TO DLP ############

        G2, curve2 = secondCurve(self.curve, degree)

        if G2 == False:
            if self.verbose:
                print("Couldn't perform ECDLP to DLP reduction")
            return False

        # calculate group
        m = curve2.group()

        # convert our two EC points into rational points over F_p^degree field
        dlpG = curve2.weil(G2, self.G, m)
        dlpQ = curve2.weil(G2, self.Q, m)

        print(dlpG, dlpQ, m)
        ############ SOLVE DLP ############

        self.k = cyclicLog(dlpQ, dlpG, m)

        self.time = time.time() - self.start

        # set space
        self.space = int(m) // 100
        self.count = self.space

        if self.verbose:
            print("k:", self.k)
            print("Time taken: %.3f s" % (self.time))                   # print time taken
            print("Space used: %d" % (self.space))                      # print space used
            print("Numbers checked:", self.count)                       # print total count

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = MOVSolver()

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
        print("(Possibly) Input not of correct form: python3 mov_attack.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]")
