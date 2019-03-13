#
#    File: fermats.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.2
#    Date: 12/02/19
#
#    Functionality: uses fermat's factorisation method to discover a private RSA
#                   key from a given public key pair
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 fermats.py PK_n PK_e [verbose]
#

############ IMPORTS #########

import math
import sys
import time

# needed for pydocs to correctly find everything
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from RSA.solver import Solver


############ MAIN CODE #########

class FFSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ try different a's until a^2 - n = b^2
            relying on the fact that every odd number is the difference
            of two squares """

        # sanity check
        if not (self.n & 1):
            print("Can't solve for even n")
            return False                                            # unsuccessful

        ############ FIND FACTOR #########
        self.start = time.time()                                    # start timer
        self.count = 1                                              # initial count

        a = int(math.ceil(math.sqrt(self.n)))                       # get square root
        bSquared = a*a - self.n                                     # get b^2
        b = math.sqrt(bSquared)                                     # will be same as int(b) if bSquared is a perfect square

        # iterate a until we find the correct pair
        while b != int(b):
            self.count += 1                                         # increment count
            a += 1                                                  # check next a
            bSquared = a*a - self.n
            b = math.sqrt(bSquared)

        # by fermat's method
        self.p = int(a - b)
        self.q = int(a + b)

        if self.verbose:
            print("p:", self.p)
            print("q:", self.q)

        # finds private key
        # return value is True or False depending on success
        return self.findPrivateKey()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = FFSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    s = solver.solve()

    if not s:
        print("Input not of correct form: python3 fermats.py PK_n PK_e [verbose]")
