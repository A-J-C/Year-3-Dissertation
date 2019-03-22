#
#    File: pollard_lambda.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.2
#    Date: 22/03/19
#
#    Functionality: uses pollard's lambda method to caclualte
#                   a private ECC key from a given public key set
#
#    Instructions: intended use is to import this file and use the Class as defined
#
#    CLI: for testing can be used from command line -
#           python3 pollard_lambda.py curve_a curve_b curve_fp G_x G_y Q_x Q_y [verbose]
#           for base-point G and public-point Q
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

# to make it backwards compatable with Python < 3.6
try:
    import secrets
except ImportError:
    from utils import secrets

import math
import time
from ECC.curves import *
from ECC.solver import Solver
from utils.helper import modInverse


############ EXTRA FUNCTIONS #########

def g(P, n, order):
    """ polynomial function for semi-randomness """

    xCoord = P.x                                                    # extract x coord
    xCoord = bin(xCoord)                                            # get binary representation
    xCoord = "0" * 4 + xCoord[2:]                                   # pad front with 0's
    ind = int(xCoord[-4:], 2) + 1                                   # get random point by "hashing P"

    moves = pow(2, int(ind + math.sqrt(n)) % n)                     # pollard said should be a power 2

    if moves % order == 0:                                          # ensure we actually move
        moves += 2

    return moves


############ MAIN CODE #########

class PLSolver(Solver):
    """ inherits from the default solver Class """

    def solve(self):
        """ baby-step giant-step uses a hash table to speed up
            finding a solution """

        # sanity check
        if self.G is None or self.curve is None or self.Q is None:
            print("Can't solve not all parameters are set")
            return False                                                # unsuccessful

        self.count = 1                                                  # initial count
        self.start = time.time()

        order = self.curve.order(self.G)                                # get order of generator

        ############ POLLARD'S LAMBDA METHOD ############
        a = order // 2                                                  # start of search interval
        b = order - 1                                                   # end of search interval

        found = False
        fail = False
        n = 1

        #print(order, a, b)
        # will probably find a factor, so need to loop with random numbers until we find it
        while (not found) and (not fail):
            n += 1                                                      # change pseudo random generator

            if n > 25:                                                  # give up
                fail = True
                break

            # TAME KNAGAROO
            len_T = 0                                                   # tame kangaroo starts with 0 moves
            pos_T = self.G * b                                          # tame starts at end

            # moves until setting trap
            trap = (g(self.G, n, order) + g(pos_T, n, order))           # trap moves dependant on our function
            trap = int(trap / 4)                                        # divide by a constant and ensure int

            # move until in position to place trap
            for t in range(trap):
                self.count += 1                                         # increment count
                moveT = g(pos_T, n, order)                              # get function on pos_T
                len_T = (len_T + moveT) % order                         # tracks total path length
                pos_T += self.G * moveT                                 # pseudo random jumps

            # WILD KANGAROO RELEASED
            len_W = 0                                                   # wild kangaroo starts making 0 moves
            pos_W = self.Q                                              # start at point we need to calculate

            moves = min(order * 100, 100000)                            # cap on number of moves
            while len_W < (len_T + b - a) and moves:                    # limit on how many random moves we make
                self.count += 1                                         # increment count
                moves -= 1                                              # decrement moves remaining

                moveW = g(pos_W, n, order)                              # get pseudo random move
                len_W = (len_W + moveW) % order                         # add to dist travelled
                pos_W += self.G * moveW                                 # update position

                if pos_W == pos_T:                                      # if fallen in trap
                    if self.verbose:
                        print(b, len_T, len_W)

                    self.k = (b + len_T - len_W) % order                # calculate k
                    found = True                                        # set to found
                    break

        self.time = time.time() - self.start

        if fail:
            if self.verbose:
                print("Failed")

            self.k = 1
            return 0

        # set space
        self.space = 20

        if self.verbose:
            print("k:", self.k)
            print("Time taken: %.3f s" % (self.time))                   # print time taken
            print("Numbers checked:", self.count)                       # print total count

        return True


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':
    solver = PLSolver()

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
