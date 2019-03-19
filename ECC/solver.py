#
#    File: solver.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.2
#    Date: 06/02/19
#
#    Functionality: a super class for all algorithms to inherit from, providing a
#                   consistent interface, and eliminating redundant functions
#
#    Instructions: intended use is to import this as a module into algorithm files
#                  and allow the algorithms to inherit from the Solver class
#


############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from ECC.generate_ECC import KeyGen


############ CLASS #########

class Solver(KeyGen):
    """ class for other reduction algorithms to extend from,
        it itslef extends the key generation class to allow it to
        utilise several functions """

    def __init__(self, C = None, Q = None, G = None, v = True):
        super(Solver, self).__init__(verbose = v)           # initalises all variables
        self.setCurve(C)                                    # set curve
        self.setQ(Q)                                        # set public point
        self.setG(G)                                        # set base point
        self.count = 0                                      # counts number of checks
        self.start = 0                                      # for timing
        self.time = 0
        self.space = 1                                      # constant space
