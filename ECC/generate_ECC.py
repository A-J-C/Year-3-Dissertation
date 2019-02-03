#
#    File: generate_ECC.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
<<<<<<< HEAD
#    Version: 1.1
#    Date: 01/02/18
=======
#    Version: 2.0
#    Date: 03/02/18
>>>>>>> working
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
<<<<<<< HEAD
if __package__:
    from RSA import generate_prime
    from RSA import helper
else:
    import generate_prime
    import helper


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
=======
if not __package__:
    sys.path.append('../')

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
        self.generateCurve()                                        # generate parameters
>>>>>>> working


    ############ SETTERS #########

<<<<<<< HEAD
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
=======
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
>>>>>>> working

    def setVerbose(self, verbose):
        """ sets additional output or not """
        self.verbose = verbose


    ############ COMPUTATION FUNCTIONS #########

<<<<<<< HEAD
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
        return success

=======
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
        
        while order < p/4:                                          # loop till order big enough
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

        self.k = secrets.randbelow(self.curve.ord)                  # get random number below order

        self.Q = self.G * self.k                                    # Q = kP

        if self.verbose:
            self.printKeys()
>>>>>>> working

    ############ OUTPUT FUNCTIONS #########

    def printKeys(self):
        """ prints out current value of keys """

<<<<<<< HEAD
        if self.verbose:
            print("Public-Key: (%d, %d)" % (self.n, self.e))
            print("Private-Key:", self.d)
            print("n is %d bits" % math.ceil(math.log(self.n, 2)))
            print()
=======
        print(("Public-Key: {\n" +
              "    Curve: %s\n" +
              "    Base-Point: %s\n" +
              "    Public-Point: %s\n" +
              "}") % (self.curve, self.G, self.Q))
        print("Private-Key:", self.k)
        print("n is %d bits" % math.ceil(math.log(self.p, 2)))
        print()
>>>>>>> working


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
<<<<<<< HEAD
    rsaKey = KeyGen()

    if len(sys.argv) >= 2:
        rsaKey.setK(int(sys.argv[1]))
    if len(sys.argv) == 3:
        rsaKey.setVerbose(int(sys.argv[2]))

    rsaKey.generateKeys()
    rsaKey.printKeys()
=======
    eccKey = KeyGen(verbose=True)

    if len(sys.argv) >= 2:
        eccKey.setN(int(sys.argv[1]))
    if len(sys.argv) == 3:
        eccKey.setVerbose(int(sys.argv[2]))

    eccKey.generateCurve()
    eccKey.generateKeys()

>>>>>>> working
