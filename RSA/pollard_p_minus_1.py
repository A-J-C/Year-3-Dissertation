#
#    File: pollard_p_minus_1.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 10/02/19
#
#    Functionality: uses Pollard's p-1 method to discover a private RSA key from
#                   a given public key pair
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 pollard_p_minus_1.py PK_n PK_e [verbose]
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

import math
import pickle
import time
from RSA.solver import Solver
from utils import helper


############ GLOBAL CONSTANT #########

# we load the first million primes from memory
with open(filePath + "utils/millionPrimes.pkl", "rb") as f:
    primes = pickle.load(f)

setOfBounds = [(0,0), (10, 50), (50, 100), (100, 250), (250, 500), (500, 1000), (1000, 2500), (2500, 10000), (10000, 25000), (25000, 50000), (50000, 999999)]


############ MAIN CLASS #########

class PSolver(Solver):
    """ inherits from the default solver Class """

    def calcM(self, bound):
        """ given a bound calculates M which is the product of all prime powers
            less than the bound """

        M = 1                                                           # 1 is identity for multiplication

        for prime in primes:                                            # loop over all our primes / extra numbers

            if prime > bound:                                           # stop when we surpass the bound
                break

            logBound = math.log(bound, prime)                           # log bound with respect to our prime
            logBound = int(logBound)                                    # we take the floor of that number  (note this will never be less than 1)
            powPrime = pow(prime, logBound, self.n)                     # raise the prime to the power of the log prime

            M *= powPrime                                               # we are calculating the product

        return M                                                        # return product


    def solve(self):
        """ uses pollards p-1 for prime factorisation relies on
            fermat's little theorem and properties of smooth numbers
            relies on the fact that p-1 may have many small factors
            theoretical runtime: O(q) where q is the largest factor
            of p - 1, where p is the largest prime factor or semi-prime N"""

        # sanity check
        if self.n == 0:
            print("Can't solve for n = 0")
            return False                                            # unsuccessful

        found = False                                               # initially not found
        fail = False
        self.start = time.time()                                    # set timer
        self.count = 0                                              # reset

        a = 2                                                       # most things should work with 2
        b = 1                                                       # start with smallest bounds

        bound1, bound2 = setOfBounds[b]

        while not found and not fail:

            # STAGE 1                                               # checks all primes below bound1
            self.count += 1                                         # increment count

            M = self.calcM(primes[bound1])                          # get new calculation of M (exponential)
            aM = pow(a, M, self.n)                                  # a^M % n
            d = helper.gcd(aM - 1, self.n)                          # gcd(p * r, p * q) = p

            #print(primes[bound1], d)

            if d > 1 and d < self.n:
                found = True                                        # we have found a factor
                break

            elif d == self.n:
                bound1 = bound1 - 1                                 # try again with smaller bound
                bound2 = bound1

                if bound1 == setOfBounds[b - 1][0]:                 # then we have failed
                    fail = True
                    break

            # STAGE 2 EXTENSION
            # uses cache so only need multiplication not exponentiation
            prevPrime = primes[bound1]
            cache = {}                                              # cache for dynamic programming
            savepoint = aM                                          # for backtracking
            saveP = 0

            for p in range(bound1 + 1, bound2 + 1):                 # go though each prime between two bounds

                self.count += 1                                     # extra check
                #print(primes[bound1], primes[p])
                prime = primes[p]                                   # extract prime
                delta = prime - prevPrime                           # get delta

                if delta not in cache:                              # check if we already know the answer
                    powMod = pow(aM, delta, self.n)                 # else get answer
                    cache[delta] = powMod                           # and store it for later

                aM = (aM * cache[delta]) % self.n                   # "adding" a factor
                prevPrime = prime                                   # update

                if p % 50 == 0 or p == bound2:                      # batch check gcd as matches sparse
                    d = helper.gcd(aM - 1, self.n)

                    if d > 1 and d < self.n:                        # we have found a factor
                        found = True
                        break

                    elif d == self.n:                               # we need to backtrack at this point as p-1 is primes[p] powersmooth

                        aM = savepoint                              # revert to savepoint
                        end = min(bound2, saveP + 50)
                        prevPrime = primes[p - 1]

                        for p in range(saveP, end):                 # re run last set of calculations
                            prime = primes[p]                       # run as before
                            delta = prime - prevPrime               # gaurenteed to be in cache

                            aM = (aM * cache[delta]) % self.n
                            prevPrime = prime

                            d = helper.gcd(aM - 1, self.n)          # get gcd

                            if d > 1 and d < self.n:                # we have found a factor
                                found = True
                                break
                        else:
                            fail = True                             # failed if we don't find a factor

                    savepoint = aM                                  # else update save point
                    saveP = p

            if d == 1:
                if b < len(setOfBounds) - 1:                        # if no p - 1 is B-powersmooth
                    b += 1                                              # then try bigger B
                    bound1, bound2 = setOfBounds[b]
                else:
                    fail = True

        # set space
        self.space = len(cache) * 2

        # set p and q once candidate found
        self.p = d
        self.q = int(self.n / self.p)

        if self.verbose:
            print("p:", self.p)
            print("q:", self.q)

            if fail:
                print("Failed")

        # finds private key
        # return value is True or False depending on success
        if self.p in [1, self.n]:                                   # failed to find a route
            return 0
        else:
            return self.findPrivateKey()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = PSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    s = solver.solve()

    if not s:
        print("Input not of correct form: python3 pollard_p_minus_1.py PK_n PK_e [verbose]")
