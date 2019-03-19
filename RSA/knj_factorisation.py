#
#    File: knj_factorisation.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.3
#    Date: 19/03/19
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

import bisect
import math
import pickle
import sys
import time

# needed for pydocs to correctly find everything
sys.path.append('Programming/')
filePath = ""

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')
    filePath = "../"

from RSA.solver import Solver
from utils import generate_prime


############ GLOBAL CONSTANT #########

# we load the first million primes from memory
with open(filePath + "utils/millionPrimes.pkl", "rb") as f:
    primes = pickle.load(f)


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

        # if canddiate is small enough then use stored primes
        if candidate <= primes[-1]:                                 # if it's small enough

            # binary search to find closest element in list
            # by using inbuilt bisect function
            closest = bisect.bisect_left(primes, candidate)
            candidatesList = primes[closest::-1]                    # reverse section of list we are interested in
            self.space = closest

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

    s = solver.solve()

    if not s:
        print("Input not of correct form: python3 knj_factorisation.py PK_n PK_e [verbose]")
