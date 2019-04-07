#
#    File: quadratic_sieve.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 05/04/19
#
#    Functionality: uses Quadratic Sieve method to discover a private RSA key from
#                   a given public key pair
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 quadratic_sieve.py PK_n PK_e [verbose]
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
from bisect import bisect_left
from RSA.solver import Solver
from utils import helper


############ GLOBAL CONSTANT #########

# we load the first million primes from memory
with open(filePath + "utils/millionPrimes.pkl", "rb") as f:
    primes = pickle.load(f)


############ EXTRA FUNCTIONS #########

def quadRes(p, n):
    """ returns True if n is a quadratic residue mod p """

    lamb = 1
    alpha = (n - 1) // 2
    p = p % n

    while alpha != 0:
        if alpha % 2:
            alpha -= 1
            lamb = (lamb * p) % n
        else:
            p = (p ** 2) % n
            alpha = alpha // 2

    return lamb


def divX(n, X):
    """ takes as many factors of X as possible out of number n """
    if n == 0:
        return 0

    while not n % X:
        n = n // X

    return n


def divXCount(n, X):
    """ as above with additional counter """
    if n == 0:
        return 0

    counter = 0

    while not n % X:
        n = n // X
        counter += 1

    return n, counter


def shanksTonelli(n, p):
    """ implemented shanks tonelli algotihm
        to solve x^2 = n (mod p) """

    # sanity check that it passes quad res rule
    if quadRes(n, p) != 1:
        return False

    # take factors of 2 out and keep a count
    # p - 1 = q * 2 ^ s
    q, m = divXCount(p - 1, 2)

    # find a z which is a quadratic non residue mod p
    z = 2
    while p - 1 != quadRes(z, p) and z != p:
        z += 1

    # following wiki algo https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)


    t2 = 0

    while t % p != 1:

        i = 1
        tPrime = t ** 2 % p
        while tPrime % p != 1:
            tPrime = tPrime ** 2 % p
            i += 1

        b = pow(c, pow(2, m - i - 1), p)
        m = i
        c = b * b % p
        t = t * c % p
        r = r * b % p

    return r, p - r


def buildExponentMat(residPrimes, smooth):
    """ builds matrix around exponent vectors mod 2 """

    # construct matrix
    expMatrix = [[0] * len(smooth) for i in range(len(residPrimes))]

    # loop over each smooth number (going down matrix
    for i in range(len(smooth)):
        num = smooth[i]

        for j in range(len(residPrimes)):
           prime = residPrimes[j]

           while not num % prime:
               num = num // prime
               expMatrix[j][i] = (expMatrix[j][i] + 1) % 2

    return expMatrix


def gauss(expMatrix):
    """ gaussian elimination around pivot mod 2 so
        all linear combinations are either 1 or 0 """

    noRows = len(expMatrix)
    noCols = len(expMatrix[0])
    
    # tracks "used" rows
    used = [False for i in range(noCols)]

    # loop for each row in matrix
    for r in range(noRows): 

        # loop for each column in row
        for c in expMatrix[r]:

            # find pivot 
            if expMatrix[r][c]:

                # set as pivot
                used[c] = True

                for i in range(noRows):

                    # enumerate column
                    if expMatrix[i][c] == 1 and i != r:

                        # combine rows mod 2 
                        for j in range(noCols):
                            expMatrix[i][j] = (expMatrix[i][j] + expMatrix[r][i]) % 2
                break

    # swap rows and columns 
    expMatrix = list(map(list, zip(*expMatrix)))
    
    # extract all free rows i.e. unused ones
    # forcing everything to be a list
    linearDeps = [(expMatrix[i], i) for i in range(noCols) if not used[i]]

    # if they were all used then can't continue
    if not linearDeps:
        return False, False, False

    return expMatrix, linearDeps, used


def solveRow(linearDeps, expMatrix, used, row):
    """ solves a row of the matix to produce solution vector """
    
    solVector, indices = [],[]
    free = linearDeps[row][0] 
    
    for i in range(len(free)):
        if free[i] == 1:
            indices.append(i)
            
    for r in range(len(expMatrix)): #rows with 1 in the same column will be dependent
        for i in indices:
            if expMatrix[r][i] == 1 and used[r]:
                solVector.append(r)
                break

    solVector.append(linearDeps[row][1])
    return solVector


def solveCongruence(solution_vec,smooth_nums,xlist,N):

    solution_nums = [smooth_nums[i] for i in solution_vec]
    x_nums = [xlist[i] for i in solution_vec]

    Asquare = 1
    for n in solution_nums:
        Asquare *= n

    b = 1
    for n in x_nums:
        b *= n

    # newton's method for square root as math library couldn't
    # handle big numbers
    
    a = Asquare
    y = (a + 1) // 2

    while y < a:
        a = y
        y = (a + Asquare // a) // 2    

    factor = helper.gcd(b-a,N)
    return factor


############ MAIN CLASS #########

class QSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ uses quadratic sieve for prime factorisation """

        # sanity check
        if self.n == 0:
            print("Can't solve for n = 0")
            return False                                            # unsuccessful

        self.start = time.time()                                    # set timer
        self.count = 0                                              # reset

        ##### DATA COLLECTION #####
        bits = int(math.log(self.n, 2)) 
        multiplier = bits // 2
        solved = False

        # trying multiple times with bigger bounds
        while not solved and multiplier <= (bits // 4) * 3:
            
            multiplier += max(bits // 10, 1)
            
            ### DEFINE BOUNDS AND GET PRIMES
            # set bound limit
            bound = min(bits * 20 * multiplier, primes[-1])
            bound = bisect_left(primes, bound)

            print("trying new bound %d" % bound)
            
            # get subset of all possible prime factors which are B-smooth
            primesSub = primes[:bound]
            
            # filter list as we are only interested in square conguences
            residPrimes = list(filter(lambda p: quadRes(self.n, p) == 1, primesSub))

            if self.verbose:
                print("%d residual primes found" % len(residPrimes))
                
            #### SIEVE FOR SMOOTH NUMBERS
            # sieve to find B-smooth numbers matching f(x) = x**2 - self.n
            rootN = int(math.sqrt(self.n))

            # sanity check
            if rootN == math.sqrt(self.n):
                d = rootN
                solved = True
                
            else:
                # start sieve at square root and go upto our max bound
                sieve = [x ** 2 - self.n for x in range(rootN , rootN + primes[bound])]
                sieveOrig = sieve[::]
                sieveLen = len(sieve)

                # use sieve and residualPrimes to find enough B-smooth congruent numbers
                # is 2 in residual Primes take as many factors of 2 as possible out of each number in sieve
                if residPrimes[0] == 2:
                    sieve = list(map(lambda s: divX(s, 2), sieve))

                # for every other residual prime
                for prime in residPrimes[1:]:

                    # resid where resid**2 = self.n mod prime
                    for resid in shanksTonelli(self.n, prime):
                        start = resid - rootN % prime

                        # from our sieve we now every primeth term will be divisible
                        for i in range(start, sieveLen, prime):
                            sieve[i] = divX(sieve[i], prime)

                ### EXTRACT SMOOTH NUMBERS
                smooth, indices = [], []

                for s in range(sieveLen):
                    if sieve[s] == 1:
                        smooth += [sieveOrig[s]]
                        indices += [s + rootN]

                    if len(smooth) > len(residPrimes):
                        break
                else:   
                    if self.verbose:
                        print("Not enough smooth numbers to compute sieve")
                    continue


                ##### DATA PROCESSING #####

                ### BUILD EXPONENT MATRIX (MOD 2)
                expMatrix = buildExponentMat(residPrimes, smooth)

                ### GAUSIAN ELIMINATION
                expMatrix, linearDeps, used = gauss(expMatrix)

                # didn't work
                if not used:
                    if self.verbose:
                        print("Couldn't find the private key.")
                    continue                                               # unsuccessful
                
                ### SOLVE CONGRUENCE (repeats if trivial factor found)
                for i in range(len(linearDeps)):
                    solVector = solveRow(linearDeps, expMatrix, used, i)
                    d = solveCongruence(solVector, smooth, indices, self.n)
                    self.count += 1

                    if d not in [1, self.n]:
                        solved = True
                        break
                else:
                    if self.verbose:
                        print("Couldn't find the private key.")
                    continue                                               # unsuccessful


        if not solved:
            if self.verbose:
                print("Failed to find private key")
            return False
        
        # set p and q once candidate found
        self.p = d
        self.q = int(self.n / self.p)
        self.space = len(expMatrix) * len(expMatrix[0])

        if self.verbose:
            print("p:", self.p)
            print("q:", self.q)

        # finds private key
        # return value is True or False depending on success
        return self.findPrivateKey()


############ COMMAND LINE INTERFACE #########

solv = QSolver(1811706971, 985590479, True)
solv.solve()

"""
if __name__ == '__main__':
    solver = QSolver()

    if len(sys.argv) >= 3:
        solver.setN(int(sys.argv[1]))
        solver.setE(int(sys.argv[2]))
    if len(sys.argv) == 4:
        solver.setVerbose(int(sys.argv[3]))

    s = solver.solve()

    if not s:
        print("Input not of correct form: python3 pollard_rho.py PK_n PK_e [verbose]")
"""
