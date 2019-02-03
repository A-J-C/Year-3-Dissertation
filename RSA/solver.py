#
#    File: solver.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 27/01/18
#
#    Functionality: a super class for all algorithms to inherit from, providing a
#                   consistent interface, and eliminating redundant functions
#
#    Instructions: intended use is to import this as a module into algorithm files
#                  and allow the algorithms to inherit from the Solver class
#


############ IMPORTS #########

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')
    
from RSA.generate_RSA import KeyGen


############ FUNCTIONS #########

class Solver(KeyGen):
    """ class for other reduction algorithms to extend from,
        it itslef extends the key generation class to allow it to
        utilise several functions """

    def __init__(self, n = 0, e = 0, verbose = True):
        super(Solver, self).__init__()              # initalises all variables
        self.n = n                                  # public key
        self.e = e                                  # public exponent
        self.verbose = verbose                      # defines additional output
        self.count = 0                              # counts number of checks

    def findPrivateKey(self):
        """ generates the correct private key, once p and q have been
            calculated, and provided n and e from the public key are
            provided """

        # sanity check
        if self.n == 0 or self.e == 0 or self.p == 0 or self.q == 0:
            print ("Please ensure all varaibles are correctly set")
            return False                            # unsuccessful

        # calculate totient
        self.phi = (self.p - 1) * (self.q - 1)

        # generate private key
        self.generatePrivateKey()

        # output more stats
        if self.verbose:
            print("Numbers checked:", self.count)   # print total count

        # sanity check
        if self.d == 0:
            print("Failed to calculate private key")
            return False                            # unsuccessful

        return True                                 # successful