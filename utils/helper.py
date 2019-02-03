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

#Number Theoretic Functions ----------------------------------------------------------------------

def divisors(n):
    divs = [0]
    for i in range(1, abs(n) + 1):
        if n % i == 0:
            divs.append(i)
            divs.append(-i)
    return divs

#Extended Euclidean algorithm.
def euclid(sml, big):
    #When the smaller value is zero, it's done, gcd = b = 0*sml + 1*big.
    if sml == 0:
        return (big, 0, 1)
    else:
        #Repeat with sml and the remainder, big%sml.
        g, y, x = euclid(big % sml, sml)
        #Backtrack through the calculation, rewriting the gcd as we go. From the values just
        #returned above, we have gcd = y*(big%sml) + x*sml, and rewriting big%sml we obtain
        #gcd = y*(big - (big//sml)*sml) + x*sml = (x - (big//sml)*y)*sml + y*big.
        return (g, x - (big//sml)*y, y)

#Compute the multiplicative inverse mod n of a with 0 < a < n.
def mult_inv(a, n):
    g, x, y = euclid(a, n)
    #If gcd(a,n) is not one, then a has no multiplicative inverse.
    if g != 1:
        raise ValueError('multiplicative inverse does not exist')
    #If gcd(a,n) = 1, and gcd(a,n) = x*a + y*n, x is the multiplicative inverse of a.
    else:
        return x % n
