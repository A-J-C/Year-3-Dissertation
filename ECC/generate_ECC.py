#
#    File: generate_ECC.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 01/02/18
#
#    Functionality: produces a pulic/private key pair for ECC
#
#    Instructions: intended use is to import this file as a module and to
#                  use the class KeyGen to create ECC keys
#
#    CLI: for testing can be used from command line -
#           python3 generate_ECC.py [bitLength] [verbose mode]
#

############ IMPORTS #########

import sys
import secrets
import math

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from ECC import curves
from utils import generate_prime


############ GENERATION CLASS #########

class KeyGen:
    """ used to generate an ECC curve over a n-bit prime field """

    def __init__(self, n = 64, verbose = False):
        self.n = n                      # n-bit field
        self.fp = 0                     # prime our field is over
        self.G = None                   # generator point for curve
        self.Q = None                   # pulbic-key point on curve
        self.curve = None               # public-key curve
        self.k = k                      # private key
        self.verbose = verbose          # verbose mode for additonal output


    ############ SETTERS #########

    def setN(self, n):
        """ sets value for bit length of Fp """
        self.n = n

    def setFp(self, fp):
        """ directly set value of prime field """
        self.fp = fp

    def setG(self, g):
        """ sets generator point """
        self.G = g

    def setQ(self, q):
        """ sets public-key point value """
        self.Q = q

    def setCurve(self, curve):
        """ sets curve directly """
        self.curve = curve

    def setVerbose(self, verbose):
        """ sets additional output or not """
        self.verbose = verbose


    ############ COMPUTATION FUNCTIONS #########

    def initialiseCurve(self):
        # sanity check
        if self.fp == 0:
            self.generatePrime()

        self.curve = Curve(fp = fp, verbose = self.verbose)         # create new curve
        self.curve.generateCurve()                                  # creates a and b coefficients


    def generatePrime(self):
        """ generates prime of bit-length n """

        # sanity check
        if self.n <= 1:
            print("Number of bits must be greater than 1")
            return False                                            # unsuccessful

        self.fp = generate_prime.getPrime(self.n, self.verbose)

        if self.verbose:
            print("fp:", self.fp)
            print()                                                 # makes output look nicer

        return True                                                 # successful


    def generateKeys(self):
        """ generates a publickey, private key pair from the curve """

        self.G = self.curve.G                                       # get generator


        return True                                                 # successful


    ############ OUTPUT FUNCTIONS #########

    def printKeys(self):
        """ prints out current value of keys """

        if self.verbose:
            print("Public-Key: (%d, %d)" % (self.n, self.e))
            print("Private-Key:", self.d)
            print("n is %d bits" % math.ceil(math.log(self.n, 2)))
            print()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    rsaKey = KeyGen()

    if len(sys.argv) >= 2:
        rsaKey.setK(int(sys.argv[1]))
    if len(sys.argv) == 3:
        rsaKey.setVerbose(int(sys.argv[2]))

    rsaKey.generateKeys()
    rsaKey.printKeys()
