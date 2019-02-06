#
#    File: pollard_rho.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 05/02/18
#
#    Functionality: uses pollard's rho method to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 pollard_rho.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#           for base-point G and public-point Q
#
#   Note: this algorithm works very poorly for anything above 10 bits
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

import secrets
import time
from ECC.curves import *
from ECC.solver import Solver
from utils.helper import modInverse


############ EXTRA FUNCTIONS #########

def g(arr, n, points):
    """ polynomial function for semi-randomness """
    P, a, b = arr                                                   # extract
    xCoord = P.x                                                    # extract x coord
    xCoord = bin(P.x)                                               # get binary representation
    xCoord = "0" * 4 + xCoord[2:]                                   # pad front with 0's
    ind = int(xCoord[-4:], 2)                                       # get random point by "hashing P"
    Q = points[ind]                                                 # extract random point
    return P + Q[0], (a + Q[1]) % n, (b + Q[2]) % n                 # return the addition


############ MAIN CODE #########

class PRSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ baby-step giant-step uses a hash table to speed up
            finding a solution """

        # sanity check
        if self.G is None or self.curve is None or self.Q is None:
            print("Can't solve not all parameters are set")
            return False                                            # unsuccessful

        self.count = 1                                              # initial count
        self.start = time.time()

        order = self.curve.order(self.G)                            # get order of generator

        ############ POLLARD'S RHO + FLOYD'S EXTENSION ############
        found = False

        # will probably find a factor, so need to loop with random numbers until we find it
        while not found:

            ############ GENERATE RANDOM FUNCTION POINTS ############
            points = []                                                 # list of points to inform our random function

            for _ in range(17):
                a = secrets.randbelow(order)
                b = secrets.randbelow(order)
                P = (self.G * a) + (self.Q * b)                         # linear combination
                points.append([P, a, b])                                # add to list


            ############ RANDOM START POINTS ############
            Y, aY, bY = X, aX, bX = points.pop()                        # random starting points

            ############ FLOYD'S CYCLE DETECTION ############
            while not found:
                X, aX, bX = g((X, aX, bX), order, points)               # first runner
                Y, aY, bY = g(g((Y,aY,bY),order,points),order,points)   # second runner
                found = X == Y                                          # detect match
                self.count += 1                                         # increment count

            if bX == bY and aX == aY:                                   # if we arrive at identical combinations
                found = False                                           # reset and try again
            else:
                inv = modInverse((bX - bY) % order, order)              # get mod inverse

                if inv == 0:                                            # if no mod inverse exists
                    found = False                                       # need to randomly try again
                else:                                                   # we have found k
                    self.k = ((aY - aX) * inv) % order                  # so set it

        self.time = time.time() - self.start

        if self.verbose:
            print("k:", self.k)
            print("Time taken: %.3f s" % (self.time))                   # print time taken

        self.time = time.time() - self.start                            # time function

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = PRSolver()

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
        print("Input not of correct form: python3 pollard_rho.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]")
