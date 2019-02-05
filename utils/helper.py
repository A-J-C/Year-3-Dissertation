#
#    File: helper.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 27/01/18
#
#    Functionality: helper functions that multiple other files use
#
#    Instructions: intended use is to import this file as a module and to
#                  use the functions provided as needed
#

def gcd(p, q):
    """ return gcd of p and q using Euclid's algorithm """
    while q != 0:
        p, q = q, p % q

    return p


def modInverse(p, q) :
    """ return modular multiplicative inverse using Euclid's Extended aglorithm """
    qOrig, y, x = q, 0, 1

    # if q is 1 no point in algo
    if (q == 1) :
        return 0

    # loop till p is less than 1
    while (p > 1) :
        # x and y track quotients
        x, y = y, x - (p // q) * y
        p, q = q, p % q

    # make x mod q to ensure it is postive
    return x % qOrig
