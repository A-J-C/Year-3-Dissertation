#
#    File: generate_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 27/01/18
#
#    Functionality: utilises other programs to generate a k-bit semiprime
#                   (a product of two not necessarily distnct primes)
#
#    Instructions: intended use is to import this file as a module and to
#                  use the class KeyGen to create RSA keys
#
#    CLI: for testing can be used from command line -
#           python3 generate_RSA.py [bitLength] [verbose mode]
#

############ IMPORTS #########

import sys
import secrets
import math

# needed for pydocs to correctly find everything
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from utils import generate_prime
from utils import helper


############ GENERATION CLASS #########

class KeyGen:
    """ used to generate a k-bit RSA key """

    def __init__(self, k = 64, verbose = False):
        self.p = 0              # first prime
        self.q = 0              # second prime
        self.n = 0              # semi-prime n = p.q
        self.e = 0              # pulbic exponent
        self.phi = 0            # totient of n
        self.d = 0              # private key
        self.k = k              # bit length of n
        self.verbose = verbose  # verbose mode for additonal output


    ############ SETTERS #########

    def setK(self, k):
        """ sets value for bit length of n """
        self.k = k

    def setP(self, p):
        """ sets value for first prime """
        self.p = p

    def setQ(self, q):
        """ sets value for second prime """
        self.q = q

    def setN(self, n):
        """ sets value for semi-prime """
        self.n = n

    def setE(self, e):
        """ sets value for second part of public key """
        self.e = e

    def setPHI(self, phi):
        """ sets totient value for n """
        self.phi = phi

    def setVerbose(self, verbose):
        """ sets additional output or not """
        self.verbose = verbose


    ############ COMPUTATION FUNCTIONS #########

    def generatePrimes(self):
        """ generates two primes of bit-length k/2 """

        # n * n bits will be at most 2n bits and at least 2n - 1
        # this follows FIPS 186-4 that p and q should have the same bitlength
        bit = int(math.floor(self.k / 2.0))

        # sanity check
        if bit <= 1:
            print("Number of bits must be greater than 1")
            return False                                            # unsuccessful

        self.p = generate_prime.getPrime(bit, self.verbose)         # False to limit output
        self.q = generate_prime.getPrime(bit, self.verbose)

        if self.verbose:
            print()
            print("p:", self.p)
            print("q:", self.q)
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

        if success and self.verbose:
            self.printKeys()

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
    rsaKey = KeyGen(verbose = True)

    if len(sys.argv) >= 2:
        rsaKey.setK(int(sys.argv[1]))
    if len(sys.argv) == 3:
        rsaKey.setVerbose(int(sys.argv[2]))

    rsaKey.generateKeys()
    rsaKey.printKeys()
