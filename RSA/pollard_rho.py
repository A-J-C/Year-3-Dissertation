#
#    File: pollard_rho.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.3
#    Date: 06/02/18
#
#    Functionality: uses Pollard's Rho method to discover a private RSA key from
#                   a given public key pair
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 pollard_rho.py PK_n PK_e [verbose]
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
from RSA.solver import Solver
from utils import helper


############ EXTRA FUNCTIONS #########

def g(x, n, c):
    """ polynomial function for semi-randomness """
    return (x ** 2 + c) % n


############ MAIN CLASS #########

class RhoSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ uses pollardsRho for prime factorisation relies on birthday paradox,
            picking enough numbers should result in a collision """

        # sanity check
        if self.n == 0:
            print("Can't solve for n = 0")
            return False                                            # unsuccessful

        self.start = time.time()                                    # set timer
        self.count = 0                                              # reset

        x = y = 2
        d = c = 1

        # will probably find a factor, so need to loop with random numbers until we find it
        while d == 1:
            x = y = c
            while d == 1:
                x = g(x, self.n, c)                                 # first runner
                y = g(g(y, self.n, c), self.n, c)                   # second runner
                d = helper.gcd(abs(x - y), self.n)                  # detects when two runners meet at the finish line, signifying a full cycle
                self.count += 1                                     # increment count

            if d == self.n:                                         # if we didn't find a factor
                d = 1                                               # reset d
                c = secrets.randbelow(self.n)                       # get new random c
                x = y = secrets.randbelow(self.n - 1) + 1           # get new non-zero random start point

        if d == self.n:
            print("Couldn't find the private key.")
            return False                                            # unsuccessful

        # set p and q once candidate found
        self.p = d
        self.q = int(self.n / self.p)

        if self.verbose:
            print("p:", self.p)
            print("q:", self.q)

        # finds private key
        # return value is True or False depending on success
        return self.findPrivateKey()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = RhoSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    solver.solve()
