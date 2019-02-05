#
#    File: baby_step.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 03/02/18
#
#    Functionality: uses the babystep-giant-step method to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 baby_step.py PK_C PK_Q PK_G [verbose]
#

############ IMPORTS #########

import sys
import math

# needed for pydocs to correctly find everything
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from ECC.solver import Solver


############ MAIN CODE #########

class BGSolver(Solver):
    """ inherits from the default solver Class """

    def __init__(self, C = None, Q = None, G = None, v = True):
        super(BGSolver, self).__init__(C, Q, G, v)

    def solve(self):
        """ baby-step giant-step uses a hash table to speed up
            finding a solution """

        # sanity check
        if self.G == None or self.curve == None or self.Q == None:
            print("Can't solve not all parameters are set")
            return False                                            # unsuccessful

        ############ FIND MULTIPLIER #########
        self.count = 1                                              # initial count

        order = self.curve.order(self.G)                            # get order of base point

        sqrtO = int(math.ceil(math.sqrt(order)))                    # root G's order

        # form hash table of nG ∀ 0 < n < sqrtO
        babySteps = {}                                              # store hash table as dictionary

        P = self.curve.pointAtInf()                                 # get starting point
        babySteps[str(P)] = 0                                       # initial point

        for n in range(1, sqrtO):
            P += self.G                                             # increment to next nG
            babySteps[str(P)] = n                                   # create look up table
            self.count += 1                                         # increment count

        # giant steps
        for i in range(sqrtO):
            P = Q - self.G * (i*sqrtO)                              # Q - i.sqrtO.G
            self.count += 1                                         # increment count

            if str(P) in babySteps:                                 # if it is in out lookup table
                n = babySteps[str(P)]
                self.k = n + i*sqrtO
                break                                               # break out of for loop
        else:
            # sanity check
            print ("Point not found")
            return 0

        if self.verbose:
            print("k:", self.k)

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = BGSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    solver.solve()
