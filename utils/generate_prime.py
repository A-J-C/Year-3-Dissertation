#
#    File: generate_prime.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.1
#    Date: 26/02/19
#
#    Functionality: Provides the functions needed to generatae k-bit primes,
#    doing so using Fermat tests and repeated applications of
#    Miller-Rabin to produce probable primes. Followed by a
#    single Lucas test.
#
#    Instructions: intended use is to import this file as a module and to
#                  use the getPrime(n) function to generate a k-bit prime.
#
#    CLI: for testing can be used from command line -
#       python3 generate_prime.py [bitLength] [verbose mode] [even more output]
#


############ IMPORTS #########

# to make it backwards compatable with Python < 3.6
try:
    import secrets                              # cryptographically strong random numbers https://docs.python.org/3/library/secrets.htm
except ImportError:
    from utils import secrets

import math                                     # handles artihmetic operations
import sys                                      # handles system CLI interaction
import time                                     # provides a timing functionality


############ GENERATION #########

def getOddNumber(k):
    """ uses secrets module to generate a random k-bit number then ensures it is odd """
    num = secrets.randbits(k - 1)               # random k-1 bits
    num += math.pow(2, k - 1)                   # added to ensure number is k bits long
    num = int(num)                              # cast to int

    # ensure odd
    if not num & 1:                             # if number isn't odd
        num += 1                                # make it odd

    return num                                  # return number as int

def getRounds(k):
    """ returns the recommended number of rounds needed given by FIPS """

    if k < 512:                                 # depending on number of bits
        return 10                               # different numebers of MR rounds
    elif k < 1024:                              # are recommended, in the official
        return 7                                # US government standard
    elif k < 1536:
        return 4
    else:
        return 3


def getKBitPrimes(k = 2 ** 10, n = 2 ** 20):
    """ uses modified sieve of eratosthenes to get all primes
        smaller than n or k, whichever is lowest """

    lim = min(k + 1, n + 1)                     # we don't want to generate any primes larger than n

    numList = [True] * lim                      # initialise boolean list
    primes = []                                 # initialise list of primes

    for i in range(2, lim):                     # loop through list from index 2
        if numList[i]:                          # if it is True
            primes.append(i)                    # must be prime

            for j in range(i*i, lim, i):        # loop through multiples
                numList[j] = False              # setting them to false

    return primes                               # return ptimes


def getListOfPrimes(k = 40, n = 1000000):
    """ uses modified sieve of eratosthenes to get all primes
        smaller than n or a function of k, whichever is lowest """

    low = 2 ** (k - 1)                          # smallest number k bits could be
    lim = min(int(math.sqrt(low)), n + 1)       # we don't want to generate any primes larger than n

    numList = [True] * lim                      # initialise boolean list
    primes = []                                 # initialise list of primes

    for i in range(2, lim):                     # loop through list from index 2
        if numList[i]:                          # if it is True
            primes.append(i)                    # must be prime

            for j in range(i*i, lim, i):        # loop through multiples
                numList[j] = False              # setting them to false

    return primes                               # return ptimes


def trialDivision(c, primes):
    """ tests a possible number against provided list of primes """

    for prime in primes:                        # for each prime
        if c % prime == 0:                      # check if c is a multiple
            return False                        # if it is return that it definitely isn't prime

    return True                                 # else reutrn that it might be prime


def powerRemainder(w, d, n):
    """ w ** d mod n """

    b = bin(d).lstrip('0b')                     # get binary representation of d
    r = 1

    for i in b:                                 # for each digit in binary
        r = r ** 2                              # square r
        if i == '1':                            # if digit is 1
            r = r * w                           # times r by w
        r %= n                                  # mod r by n

    return r                                    # return answer


def millerRabin(n, r):
    """ runs r rounds of miller rabin to check if n is a probable prime
        following NIST-FIPS-186-4 """

    if n < 2:                                   # 0, 1 and negative numbers are considered not prime
        return False

    ############ CALCULATING d AND i #########
    # find the values d and i s.t. 2^i * d = n - 1
    d = n - 1
    i = 0

    while not d & 1:
        d >>= 1
        i += 1

    ############ TEST ONE WITNESS FOR EACH MR-ROUND #########
    for _ in range(r):

        # get random witness
        w = secrets.SystemRandom().randrange(2, n - 1)

        # use power-remainder method
        z = powerRemainder(w, d, n)

        # if z is 1 or n -1 then w is not a witness for n being a composite number
        if z not in (1, n - 1):

            # check no j s.t. (w^(2^j)) ^ d = -1 (mod n)
            for j in range(i):

                #  get next z
                z = powerRemainder(w, 2 ** j * d, n)

                if z == 1:                      # n is definitely composite
                    return False                # return False
                elif z == n -1 :                # n is prime or the witness is a strong liar
                    break                       # break to next witness

            else:
                return False                    # if the inner loop didn't break, n is composite

    return True                                 # if no witness can be found for n being composite, it is a probable prime



def checks(candidate, primeList, r = 10):
    """ given a candidate and list of primes checks for pseudo-primes """

    ############ 6k BASIC CHECK #########
    # all primes > 3 are of the form 6k + 1 or 6k -1 so skip testing any not of this form
    mod6 = candidate % 6

    if candidate > 3 and mod6 != 1 and mod6 != 5:
        return False                                    # if check fails return False

    ############ TRIAL-DIVISION CHECK #########
    if not trialDivision(candidate, primeList):
        return False                                    # if check fails return False

    ############ Miller-Rabin CHECK #########
    return millerRabin(candidate, r)


def isPrime(n, primes = False):
    """ given a number n checks if it is a pseudo-prime """

    k = math.log(n, 2)                          # number of bits in n
    r = getRounds(k)

    if not primes:
        primes = getListOfPrimes(k)

    return checks(n, primes, r)                 # run checks


def getPrime(k = 50, verbose = True, extraOutput = False):
    """ returns a prime number that is k bits long """

    # sanity check
    if k < 1:
        print("Number of bits in prime must be greater than 0")
        return False                            # unsuccessful

    ############ START TIMER #########
    start = time.time()                         # start timing

    if extraOutput:                             # if we are in verose mode
        print("="*50,
              "\nGenerating ", k, "bit prime... ")

    ############ GET ROUNDS OF Miller-Rabin #########
    r = getRounds(k)

    if extraOutput:
        print(r, "rounds of Miller-Rabin needed (according to FISC)")

    ############ GET PRIME LIST FOR TRIAL DIVISION #########
    # get prime list (only do it once for the lowest number k bits could be to speed up
    primeList = getListOfPrimes(k)

    if extraOutput:
        print("Trial-Division prime list generated, size: ", len(primeList))


    ############ GENERATE PROBABLE PRIME #########
    prime = False
    numCandidates = 0

    # loop till probable prime is found
    while not prime:
        numCandidates += 1                      # increment candidate count

        candidate = getOddNumber(k)             # get an odd number as next candidate

        if extraOutput:
            print("New candidate...", candidate)

        prime = checks(candidate, primeList, r) # run checks


    ############ OUTPUT #########
    if verbose:
        print("Prime of ", k, "bits found:", candidate)
        print("Checked %d candidates in %.2f s" % (numCandidates, time.time() - start))

    return candidate

############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    if len(sys.argv) == 2:
        getPrime(int(sys.argv[1]))
    elif len(sys.argv) == 3:
        getPrime(int(sys.argv[1]), int(sys.argv[2]))
    elif len(sys.argv) == 4:
        getPrime(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    else:
        getPrime()
