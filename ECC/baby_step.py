#
#    File: baby_step.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.3
#    Date: 20/03/19
#
#    Functionality: uses the babystep-giant-step method to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 baby_step.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#           for base-point G and public-point Q
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

import math
import time
from ECC.curves import *
from ECC.solver import Solver
from IPython.display import display, clear_output


############ MAIN CODE #########

class BGSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self, order = False):
        """ baby-step giant-step uses a hash table to speed up
            finding a solution """

        # sanity check
        if self.G is None or self.curve is None or self.Q is None:
            print("Can't solve not all parameters are set")
            return False                                            # unsuccessful

        ############ FIND MULTIPLIER #########
        self.count = 1                                              # initial count
        self.start = time.time()

        # sanity check
        if self.G == self.Q:
            self.k = 1
            babySteps = {}
        else:
            if not order:                                               # if order not yet set
                order = self.curve.order(self.G)                        # get order of base point

            sqrtO = int(math.ceil(math.sqrt(order)))                    # root G's order

            # form hash table of nG ∀ 0 < n < sqrtO
            babySteps = {}                                              # store hash table as dictionary

            P = self.curve.pointAtInf()                                 # get starting point
            babySteps[str(P)] = 0                                       # initial point

            for n in range(1, sqrtO + 1):
                P += self.G                                             # increment to next nG
                babySteps[str(P)] = n                                   # create look up table
                self.count += 1                                         # increment count

                # for demo purposes
                if self.demo and self.count % 100 == 0:
                    clear_output(wait=True)
                    display(str(self.count) + ".G = " + str(P))

            # giant steps
            for i in range(sqrtO):
                P = self.Q - self.G * (i*sqrtO)                         # Q - i.sqrtO.G
                self.count += 1                                         # increment count

                # for demo purposes
                if self.demo and self.count % 100 == 0:
                    clear_output(wait=True)
                    display(str(self.Q) + " - " + str(self.G) + " * "
                            + str(i*sqrtO) + " = " + str(P))


                if str(P) in babySteps:                                 # if it is in out lookup table
                    n = babySteps[str(P)]
                    self.k = n + i*sqrtO

                    # for demo purposes
                    if self.demo:
                        clear_output(wait=True)
                        display(str(self.Q) + " - " + str(self.G) + " * "
                                + str(i*sqrtO) + " = " + str(P))

                    break                                               # break out of for loop
            else:
                # sanity check
                if self.verbose:
                    print ("Point not found")

                return 0

        self.time = time.time() - self.start

        # set space
        self.space = len(babySteps) * 2

        if self.verbose:
            print("k:", self.k)
            print("Time taken: %.3f s" % (self.time))               # print time taken
            print("Space used: %d bytes" % (self.space * 4))        # print space used
            print("Numbers checked:", self.count)                   # print total count

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = BGSolver()

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
        print("Input not of correct form: python3 baby_step.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]")
