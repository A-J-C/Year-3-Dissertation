#
#    File: brute_force.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 03/02/18
#
#    Functionality: uses a brute force attack to discover a private ECC key from
#                   a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 baby_step.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#

############ IMPORTS #########

import sys
import math

# needed for pydocs to correctly find everything
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from ECC.solver import Solver


############ MAIN CODE #########

class BFSolver(Solver):
    """ inherits from the default solver Class """

    def __init__(self, C = None, Q = None, G = None, v = True):
        super(BFSolver, self).__init__(C, Q, G, v)

    def solve(self):
        """ brute force by adding base point to itself until
            inf point is reached """

        # sanity check
        if self.G == None or self.curve == None or self.Q == None:
            print("Can't solve not all parameters are set")
            return False                                            # unsuccessful

        ############ FIND MULTIPLIER #########
        self.count = 1                                              # initial count
        P = self.G                                                  # copy point

        # loop through all numbers looking for candidate until infinity
        while P != self.Q and P != self.curve.pointAtInf():
            P += self.G                                             # add another G
            self.count += 1                                         # increment count

        # sanity check
        if P != self.Q:
            print ("Point not found")
            return 0

        # set k once candidate found
        self.k = self.count

        if self.verbose:
            print("k:", self.k)

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = BFSolver()

    if len(sys.argv) >= 8:
        c_a = int(sys.argv[1])
        c_b = int(sys.argv[2])
        c_fp = int(sys.argv[3])
        G_x = int(sys.argv[4])
        G_y = int(sys.argv[5])
        Q_x = int(sys.argv[6])
        Q_y = int(sys.argv[7])
        C = Curve(c_a, c_b, c_fp)
        G = Point(G_x, G_y, C)
        Q = Point(Q_x, Q_y, C)
        solver.setCurve(C)
        solver.setG(G)
        solver.setQ(Q)
    if len(sys.argv) == 9:
        solver.setVerbose(int(sys.argv[8]))

    s = solver.solve()
    if not s:
        print("Input not of correct form: python3 brute_force.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]")
