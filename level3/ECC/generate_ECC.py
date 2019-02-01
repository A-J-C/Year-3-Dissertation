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
if __package__:
    from ECC import curves
else:
    import curves
    import helper


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

    def generatePrime(self):
        """ generates prime of bit-length n """

        # sanity check
        if self. <= 1:
            print("Number of bits must be greater than 1")
            return False                                            # unsuccessful

        self.fp = generate_prime.getPrime(bit, self.verbose)

        if self.verbose:
            print("fp:", self.fp)
            print()                                                 # makes output look nicer

        return True                                                 # successful


    def generatePublicKey(self):
        """ generates a k-bit key from two primes (will either be k or k-1) """

        # sanity check
        if self.p == 0 or self.q == 0:
            print ("Please ensure p and q are generated first")
            return False                                            # unsuccessful

        # calculate n
        self.n = self.p * self.q

        # calculate Euler's totient
        self.phi = (self.p - 1) * (self.q - 1)

        # generate an e coprime to phi
        self.e = secrets.randbelow(self.phi)

        # keep generating until we are sure it is coprime
        while (helper.gcd(self.e, self.phi) != 1):
            self.e = secrets.randbelow(self.phi)

        if self.verbose:
            print("n:", self.n)
            print("e:", self.e)
            print("n bit length:", math.ceil(math.log(self.n, 2)))

        return True                                                 # successful


    def generatePrivateKey(self):
        """ generate private key, for reversing trapdoor function """

        # sanity check
        if self.e == 0:
            print ("Please ensure e is calculated first")
            return False                                            # unsuccessful

        # satisfies e.d = 1 (mod phi)
        # need to find the modular inverse of e
        self.d = helper.modInverse(self.e, self.phi)

        if self.verbose:
            print("Private-Key, d:", self.d)

        return True                                                 # successful


    def generateKeys(self):
        """ generates both public and private keys """
        success = self.generatePrimes()
        if not success:
            return False                                            # unsuccessful

        success = self.generatePublicKey()
        if not success:
            return False                                            # unsuccessful

        success= self.generatePrivateKey()
        return success


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
