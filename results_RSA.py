#
#    File: results_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.0
#    Date: 19/03/19
#
#    Functionality: gathers results for RSA in given range
#
#    CLI: python3 results_RSA.py -h (to see possible flags)
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# to make it backwards compatable with Python < 3.6
try:
    import secrets
except ImportError:
    from utils import secrets

import argparse
import math
import threading
import matplotlib.pyplot as plt                                                 # for drawing graphs
from RSA import *
from utils.plots import *


############ GLOBAL VARIABLES #########

resCount_C = {}                                                                 # stores results as dictionary
resTime_C = {}                                                                  # stores results as dictionary
resSpace_C = {}                                                                 # stores results as dictionary
resCount_W = {}                                                                 # stores results as dictionary
resTime_W = {}                                                                  # stores results as dictionary
resSpace_W = {}                                                                 # stores results as dictionary
saveFile = ""


############ FUNCTIONS #########

def saveResults(saveFile):
    """ saves results to a csv file """

    with open(saveFile + "_C.csv", "w+") as file:                               # open file
        keys = sorted(list(resCount_C.keys()))                                  # important that in sorted order

        for key in keys:                                                        # loop over keys
            out = (str(key) + "," + str(resCount_C[key][0]) + "," +             # write out info
                    str(resTime_C[key][0]) + "," +
                    str(resSpace_C[key][0]) + "," +
                    str(resCount_C[key][1]) + "\n")

            file.write(out)                                                     # write to file

    with open(saveFile + "_W.csv", "w+") as file:                               # open file
        keys = sorted(list(resCount_W.keys()))                                  # important that in sorted order

        for key in keys:                                                        # loop over keys
            out = (str(key) + "," + str(resCount_W[key][0]) + "," +             # write out info
                    str(resTime_W[key][0]) + "," +
                    str(resSpace_W[key][0]) + "," +
                    str(resCount_W[key][1]) + "\n")

            file.write(out)                                                     # write to file


def getResults(solver, minBit, maxBit, saveFile, noResults):
    """ saves a results csv, given a solver, result index and bit range """

    for bit in range(minBit, maxBit + 1, 2):
        for i in range(noResults):

            keys = generate_RSA.KeyGen(bit)                                     # initialise keys
            keys.generateKeys()                                                 # generate keys

            solver.setN(keys.n)                                                 # setup solver
            solver.setE(keys.e)

            solver.solve()                                                      # solve problem

            k = int(math.ceil(math.log(keys.n, 2)))                             # get accurate bit length

            if solver.d == keys.d:                                              # if we got it right
                resTime = resTime_C                                             # update correct dictionaries
                resCount = resCount_C
                resSpace = resSpace_C
            else:
                resTime = resTime_W                                             # else update wrong dictionaries
                resCount = resCount_W
                resSpace = resSpace_W

            if k not in resTime:                                                # if we've not yet had a result for k
                resTime[k] = [solver.time, 1]                                   # then set
                resSpace[k] = [solver.space, 1]                                 # then set
                resCount[k] = [solver.count, 1]
            else:
                oldT, oldC = resTime[k]                                         # keeps a running average
                newC = oldC + 1                                                 # increment count
                newT = ((oldT * oldC) + solver.time) / newC                     # get new averagae
                resTime[k] = [newT, newC]                                       # without storing all variables

                oldS, oldC = resSpace[k]                                        # keeps a running average
                newS = ((oldS * oldC) + solver.space) / newC
                resSpace[k] = [newS, newC]                                      # without storing all variables

                oldCount, oldC = resCount[k]                                    # keeps a running average
                newCount = ((oldCount * oldC) + solver.count) / newC
                resCount[k] = [newCount, newC]                                  # without storing all variables

            if i % 10 == 0:
                saveResults(saveFile)                                           # every ten results save again


def results(algo = 0, minBit = 10, maxBit = 44, saveFile = "results", noResults = 100):
    """ generates results for a given algorithm """

    solver = None
    if algo == 0:
        solver = brute_force.BFSolver(verbose = False)
    elif algo == 1:
        solver = fermats.FFSolver(verbose = False)
    elif algo == 2:
        solver = pollard_rho.RhoSolver(verbose = False)
    elif algo == 3:
        solver = knj_factorisation.KNJSolver(verbose = False)
    elif algo == 4:
        solver = pollard_p_minus_1.PSolver(verbose = False)

    getResults(solver, minBit, maxBit, saveFile, noResults)


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--minbit", help="minimum bit size to test from", type=int, default=10)
    parser.add_argument("-u", "--maxbit", help="maximum bit size to test", type=int, default=40)
    parser.add_argument("-s", "--savefile", help="name of file to save results to", type=str, default="results")
    parser.add_argument("-n", "--noresults", help="number of results to take for each bit", type=int, default=100)
    parser.add_argument("-bf", "--bruteforce", help="turns bruteforce decryption on", action="store_true")
    parser.add_argument("-ff", "--fermats", help="turns fermats decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")
    parser.add_argument("-knj", "--KNJ_factorisation", help="turns KNJ_factorisation decryption on", action="store_true")
    parser.add_argument("-pp", "--pollard_p_minus_1", help="turns pollard_p_minus_1 decryption on", action="store_true")

    args = parser.parse_args()

    algo = 0

    if args.fermats:
        algo = 1
    elif args.pollard_rho:
        algo = 2
    elif args.KNJ_factorisation:
        algo = 3
    elif args.pollard_p_minus_1:
        algo = 4

    results(algo, args.minbit, args.maxbit, args.savefile, args.noresults)
