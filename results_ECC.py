#
#    File: results_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/19
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
from ECC import *
from utils.plots import *


############ GLOBAL VARIABLES #########

resCount = {}                                                                   # stores results as dictionary
resTime = {}                                                                    # stores results as dictionary
saveFile = ""


############ FUNCTIONS #########

def saveResults(saveFile):
    """ saves results to a csv file """

    with open(saveFile, "w+") as file:                                          # open file
        keys = sorted(list(resCount.keys()))                                    # important that in sorted order

        for key in keys:                                                        # loop over keys
            out = (str(key) + "," + str(resCount[key][0]) + "," +               # write out info
                    str(resTime[key][0]) + "," + str(resCount[key][1]) + "\n")

            file.write(out)                                                     # write to file


def getResults(solver, minBit, maxBit, saveFile):
    """ produces a graph, given a solver, result index and bit range """

    while True:
        for i in range(10):
            k = secrets.randbelow(maxBit - minBit) + minBit                         # get in range
            keys = generate_ECC.KeyGen(k, False)                                    # initialise keys
            keys.generateCurve()                                                    # get curve paramaters
            keys.generateKeys()                                                     # generate keys

            solver.setCurve(keys.curve)                                             # setup solver
            solver.setQ(keys.Q)
            solver.setG(keys.G)

            solver.solve()                                                          # solve problem

            k = int(math.ceil(math.log(keys.p, 2)))                                 # get accurate bit length

            if solver.k == keys.k:                                              # if we got it right
                if k not in resTime:                                            # if we've not yet had a result for k
                    resTime[k] = [solver.time, 1]                               # then set
                    resCount[k] = [solver.count, 1]
                else:
                    oldT, oldC = resTime[k]                                     # keeps a running average
                    newC = oldC + 1                                             # increment count
                    newT = ((oldT * oldC) + solver.time) / newC                 # get new averagae
                    resTime[k] = [newT, newC]                                   # without storing all variables

                    oldCount, oldC = resCount[k]                                # keeps a running average
                    newCount = ((oldCount * oldC) + solver.count) / newC
                    resCount[k] = [newCount, newC]                              # without storing all variables

        saveResults(saveFile)                                                   # every ten results save again

def results(algo = 0, minBit = 10, maxBit = 44, saveFile = "results.csv"):
    """ generates results for a given algorithm """

    solver = None
    if algo == 0:
        solver = brute_force.BFSolver(v = False)
    elif algo == 1:
        solver = pollard_rho.PRSolver(v = False)
    elif algo == 2:
        solver = baby_step.BGSolver(v = False)

    getResults(solver, minBit, maxBit, saveFile)

############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--minbit", help="minimum bit size to test from", type=int, default=10)
    parser.add_argument("-u", "--maxbit", help="maximum bit size to test", type=int, default=20)
    parser.add_argument("-s", "--savefile", help="name of file to save results to", type=str, default="results.csv")
    parser.add_argument("-bf", "--bruteforce", help="turns bruteforce decryption on", action="store_true")
    parser.add_argument("-bs", "--baby_step", help="turns baby_step-giant_step decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")

    args = parser.parse_args()

    algo = 0
    if args.pollard_rho:
        algo = 1
    elif args.baby_step:
        algo = 2

    results(algo, args.minbit, args.maxbit, args.savefile)
