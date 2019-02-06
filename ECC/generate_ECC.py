#
#    File: generate_ECC.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.1
#    Date: 06/02/18
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

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

import math
import secrets
from ECC import curves
from utils import generate_prime


############ HELPER FUNCTIONS #########

def getRandCurve(n, v):
    """ returns a random curve over a random prime n-bits long """

    p = generate_prime.getPrime(n, v)                               # get a random n-bit prime
    a = secrets.randbelow(10)                                       # generate random coefficient
    b = secrets.randbelow(10)                                       # generate random coefficient

    C = curves.Curve(a, b, p, v)                                    # create curve

    return C


############ GENERATION CLASS #########

class KeyGen:
    """ used to generate an ECC curve over a n-bit prime field """

    def __init__(self, n = 10, verbose = True):
        self.n = n                                                  # n-bit field
        self.p = 0                                                  # prime our field is over
        self.G = None                                               # generator point for curve
        self.Q = None                                               # pulbic-key point on curve
        self.curve = None                                           # public-key curve
        self.k = 0                                                  # private key
        self.verbose = verbose                                      # verbose mode for additonal output


    ############ SETTERS #########

    def setN(self, n):
        """ sets value for bit length of Fp """
        self.n = n

    def setP(self, p):
        """ directly set value of prime field """
        self.p = p

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

    def generateCurve(self):
        """ tries random a, b and p coefficients, until a curve with G
            order > Fp/4 is produced
            where p is n bits long """

        # sanity check
        if self.n <= 1:
            print("Number of bits must be greater than 1")
            return False                                            # unsuccessful

        order, p = 0, 1
        C, G = None, None
        checks = 0

        while order < p/2:                                          # loop till order big enough
            checks += 1
            C = getRandCurve(self.n, self.verbose)                  # get random curve of correct size

            while not C.valid():                                    # if not valid
                C = getRandCurve(self.n, self.verbose)              # try again

            G = C.getG()                                            # get generator point
            order = C.ord                                           # get order of curve
            p = C.fp                                                # get prime field

        if self.verbose:
            print("Checked %d curves" % checks)

        self.curve = C                                              # we now have a good curve
        self.G = G                                                  # and generator
        self.p = p


    def generateKeys(self):
        """ generates a publickey, private key pair from the curve """

        if self.curve is None or self.curve.ord == 0:
            return False                                            # curve not set up correctly

        self.k = secrets.randbelow(self.curve.ord)                  # get random number below order

        self.Q = self.G * self.k                                    # Q = kP

        if self.verbose:
            self.printKeys()

        return True

    ############ OUTPUT FUNCTIONS #########

    def printKeys(self):
        """ prints out current value of keys """

        print(("Public-Key: {\n" +
               "    Curve: %s\n" +
               "    Base-Point: %s\n" +
               "    Public-Point: %s\n" +
               "}") % (self.curve, self.G, self.Q))
        print("Private-Key:", self.k)
        print("n is %d bits" % math.ceil(math.log(self.p, 2)))
        print()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    eccKey = KeyGen(verbose=True)

    if len(sys.argv) >= 2:
        eccKey.setN(int(sys.argv[1]))
    if len(sys.argv) == 3:
        eccKey.setVerbose(int(sys.argv[2]))

    eccKey.generateCurve()
    eccKey.generateKeys()
