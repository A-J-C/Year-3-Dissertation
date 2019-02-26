#
#    File: knj_factorisation.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 26/02/18
#
#    Functionality: uses "KNJ-Factorisation" first outlined in the paper
#        "Modified Trial Division Algorithm Using KNJ-Factorization Method
#         To Factorize RSA Public Key Encryption".
#         It is fairly basic in that it is brute force, considering only primes
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 knj_factorisation.py PK_n PK_e [verbose]
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
from utils import generate_prime


############ MAIN CODE #########

class KNJSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ brute force all primes to factorise a given semi-prime """

        # sanity check
        if self.n == 0:
            print("Can't solve for n = 0")
            return False                                            # unsuccessful

        ############ FIND FACTOR #########
        self.start = time.time()                                    # start timer

        candidate = int(math.floor(math.sqrt(self.n)))              # get square root

        # ensure odd
        if not candidate & 1:
            candidate -= 1

        self.count = 1                                              # initial count

        # if small enough use a sieve to get the numbers we need
        # to search
        if candidate <= 2**20:                                      # if it's small enough for us to calculate smaller primes for
            primesList = generate_prime.getKBitPrimes(candidate)    # get list using sieve
            candidatesList = primesList[::-1]                       # reverse list

            # loop through all possible primes
            for prime in candidatesList:
                self.count += 1                                     # increment count

                # check if it is a factor
                if self.n % prime == 0:
                    candidate = prime                               # if it is set it as the candidate
                    break                                           # then break

        # else we just have to brute force
        else:

            # loop through all odd numbers looking for candidate
            while self.n % candidate != 0 or candidate <= 0:
                candidate -= 2
                self.count += 1                                     # increment count

        # sanity check
        if self.n % candidate != 0:
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
    solver = KNJSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    solver.solve()
