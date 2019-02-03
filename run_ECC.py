#
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 03/02/18
#
#    Functionality: utilises other programs to generate and subsequently break ECC
#                   keys using a variety of algorithms, while collecting diagnostics
#                   to compare and check the results of each of these algorithms
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 run_ECC.py [bitLength] [bruteForce] [babyStep]
#

############ IMPORTS #########

import math
import sys
import time
from generateECC import *


############ FUNCTIONS #########

def runSolver(keys, solver, name, verbose):
    """ runs a check on the solver, given the correct keys """

    if verbose:
        print("="*10, name, "="*10)

    start = time.time()

    solver.solve()                                                              # Elliptic Curve discrete log problem

    end = time.time() - start

    if verbose:
        print("Time: %.2f s" % (end))                                           # output statistics

    if verbose:
        if solver.k == keys.k:                                                  # check for correctness
            print("Success!")
        else:
            print("Fail!")

    return {"res": (solver.k == keys.k),                                        # return result as dict
            "time": end,
            "count": solver.count}


############ MASTER PROGRAM #########

def run(k = 10, brute = True, pRho = True, verbose = True):
    """ creates a k-bit ECC key, cracks it with several algorithms, and generates
        statistics to compare their performance """

    ############ TIMING #########
    start = time.time()

    ############ KEY GENERATION #########
    if verbose:
        print("\n" + "="*10, "GENERATING", "="*10)

    keys = generate_ECC.KeyGen(k, verbose)                                      # create new instance

    sanity = keys.generateKeys()                                                # get key and primes

    if not sanity:
        if verbose:
            print ("Please fix input and try again")
        return False

    keys.printKeys()                                                            # print generated keys

    ############ BRUTE FORCE ATTACK #########
    bf_res = {}
    if brute:
        bf = brute_force.BFSolver(keys.n, keys.e, verbose)                      # create new instance with public key info
        bf_res = runSolver(keys, bf, "BRUTE FORCE", verbose)                    # check solver

    ############ BABYSTEP-GIANTSTEP ATTACK #########
    bsgs_res = {}
    if babyStep:
        bg = baby_step.BGSolver(keys.n, keys.e, verbose)                        # create new instance with public key info
        bg_res = runSolver(keys, bg, "BABYSTEP_GIANTSTEP", verbose)             # check solver

    return bf_res, bsgs_res


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        tests(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5])
    elif len(sys.argv) == 5:
        run(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    elif len(sys.argv) == 4:
        run(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) == 3:
        run(int(sys.argv[1]), int(sys.argv[2]))
    elif len(sys.argv) == 2:
        run(int(sys.argv[1]))
    else:
        run()
