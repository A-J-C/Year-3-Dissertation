#
#    File: brute_force.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 27/01/18
#
#    Functionality: uses a brute force attack to discover a private RSA key from
#                   a given public key pair
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 brute_force.py PK_n PK_e [verbose]
#

############ IMPORTS #########

import sys
import math

from RSA.solver import Solver


############ MAIN CODE #########

class BFSolver(Solver):
    """ inherits from the default solver Class """

    def __init__(self, n, e, v):
        super(BFSolver, self).__init__(n, e, v)

    def solve(self):
        """ brute force by checking all odd numbers below sqrt(n) """

        # sanity check
        if self.n == 0:
            print("Can't solve for n = 0")
            return False                                            # unsuccessful

        ############ FIND FACTOR #########
        candidate = int(math.floor(math.sqrt(self.n)))              # get square root

        # ensure odd
        if not candidate & 1:
            candidate -= 1

        self.count = 1                                              # initial count

        # loop through all odd numbers looking for candidate
        while self.n % candidate != 0 or candidate <= 0:
            candidate -= 2
            self.count += 1                                         # increment count

        # sanity check
        if candidate <= 0:
            print ("No prime factors found.")
            return 0

        # set p and q once candidate found
        self.p = candidate
        self.q = int(self.n / self.p)

        if self.verbose:
            print("p:", self.p)
            print("q:", self.q)

        # finds private key
        # return value is True or False depending on success
        return self.findPrivateKey()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = BFSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    solver.solve()
