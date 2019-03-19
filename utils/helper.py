#
#    File: helper.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.2
#    Date: 06/02/19
#
#    Functionality: helper functions that multiple other files use
#
#    Instructions: intended use is to import this file as a module and to
#                  use the functions provided as needed
#

############ MATHMATICAL FUNCTIONS #########

def gcd(p, q):
    """ return gcd of p and q using Euclid's algorithm """
    while q != 0:
        p, q = q, p % q

    return p


def extended_gcd(p, q):
    """ explicid Euclid's Extended algorithm for gcd """

    qOrig, y, x = q, 0, 1

    while q != 0:
        # x and y track quotients
        x, y = y, x - (p // q) * y
        p, q = q, p % q

    # make x mod q to ensure it is postive
    return x % qOrig, x


def modInverse(p, q) :
    """ return modular multiplicative inverse using Euclid's Extended aglorithm """
    qOrig, y, x = q, 0, 1

    # if q is 1 no point in algo
    if q == 1:
        return 0

    # loop till p is less than 1
    while p > 1:
        # x and y track quotients
        x, y = y, x - (p // q) * y
        p, q = q, p % q

        if q == 0 and p != 1:               # means modInverse doesn't exist
            return 0                        # so return before // 0 error

    # make x mod q to ensure it is postive
    return x % qOrig


def primeFac(n):
    """ given a number returns a list of its prime factors """

    factors = {}
    p = 0

    while n != 1:                                                       # until n is 1 we don't have all the prime factors

        prime = primes[p]

        pCount = 0

        while n % prime == 0:                                           # while we can divide with no remainder
            n = int(n/prime)                                            # perform division
            pCount += 1                                                 # increment our count

        if pCount != 0:                                                 # see if it ever worked
            factors[prime] = pCount                                     # add to dictionary

        p += 1                                                          # get next prime

        if p == len(primes):                                            # if we have run out of primes
            factors[n] = 1                                              # add the remaining amount
            break                                                       # break out of while loop

    return factors
