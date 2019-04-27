#
#    File: graphs_ECC.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/19
#
#    Functionality: utilises other programs to generate and subsequently break ECC
#                   keys using a variety of algorithms, generating a few graphs
#                   to show general trends as we go
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 graphs_ECC.py  -h (to see possible flags)
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
import secrets
import threading
import matplotlib.pyplot as plt                                                 # for drawing graphs
from ECC import *
from utils.plots import *


############ GLOBAL VARIABLES #########

resCount = [{}, {}, {}, {}, {}]                                                 # stores results to graph as dictionaries
resTime = [{}, {}, {}, {}, {}]                                                  # stores results to graph as dictionaries
running = True                                                                  # to stop threads


############ FUNCTIONS #########


def getResults(solver, ind, minBit, maxBit, COUNT):
    """ produces a graph, given a solver, result index and bit range """

    for i in range(COUNT):
        k = secrets.randbelow(maxBit - minBit) + minBit                         # get in range
        keys = generate_ECC.KeyGen(k, False)                                    # initialise keys
        keys.generateCurve()                                                    # get curve paramaters
        keys.generateKeys()                                                     # generate keys

        solver.setCurve(keys.curve)                                             # setup solver
        solver.setQ(keys.Q)
        solver.setG(keys.G)

        solver.solve()                                                          # solve problem

        k = int(math.ceil(math.log(keys.p, 2)))                                 # get accurate bit length

        if solver.k == keys.k:                                                  # if we got it right
            if k not in resTime[ind]:                                           # if we've not yet had a result for k
                resTime[ind][k] = [solver.time, 1]                              # then set
                resCount[ind][k] = [solver.count, 1]
            else:
                oldT, oldC = resTime[ind][k]                                    # keeps a running average
                newC = oldC + 1                                                 # increment count
                newT = ((oldT * oldC) + solver.time) / newC                     # get new averagae
                resTime[ind][k] = [newT, newC]                                  # without storing all variables

                oldCount, oldC = resCount[ind][k]                               # keeps a running average
                newCount = ((oldCount * oldC) + solver.count) / newC
                resCount[ind][k] = [newCount, newC]                             # without storing all variables

def stop():
    global running
    input("Press Enter to stop.")                                               # wait for input
    running = False                                                             # stop running


def testGraphs(minBit = 10, bf_bit = 22, bsgs_bit = 30, ph_bit = 30,
               rho_bit = 30, mov_bit = 30, COUNT = 100):
    """ generates graphs testing all algorithms to show general trends
        uses a thread for each algorith, to ease congestion """

    global running, resCount, resTime                                           # to stop and reset program

    resCount = [{}, {}, {}, {}, {}]                                             # reset
    resTime = [{}, {}, {}, {}, {}]

    running = True

    bf = brute_force.BFSolver(v = False)                                        # define solvers
    bsgs = baby_step.BGSolver(v = False)
    ph = pohlig_hellman.PHSolver(v = False)
    rho = pollard_rho.PRSolver(v = False)
    mov = mov_attack.MOVSolver(v = False)

    solvers = [bf, bsgs, ph, rho, mov]
    max_bit = [bf_bit, bsgs_bit, ph_bit, rho_bit, mov_bit]

    labels = ["Brute-force", "Baby-Step, Giant-Step", "Pohlig-Hellman",
              "Pollard's Rho", "MOV-attack"]

    threading.Thread(target = stop).start()                                     # allows us to gracefully stop
    outFig, tPlt, cPlt = setupGraph()


    while running:

         for i in range(len(solvers)):                                          # loop over each solver
             getResults(solvers[i], i, minBit, max_bit[i], COUNT)               # collect a few results
             updateGraph(resTime, resCount, outFig, tPlt, cPlt, labels)         # update graph


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--minbit", help="minimum bit size to test from", type=int, default=10)
    parser.add_argument("-bf", "--bruteforce", help="maximum bit size for brute force", type=int, default=24)
    parser.add_argument("-bs", "--baby_step", help="maximum bit size for babystep-giantstep", type=int, default=34)
    parser.add_argument("-pr", "--pollard_rho", help="maximum bit size for Pollard's Rho", type=int, default=36)
    parser.add_argument("-pl", "--pollard_lambda", help="maximum bit size for Pollard's Lambda", type=int, default=36)
    parser.add_argument("-ph", "--pohlig_hellman", help="maximum bit size for Pohlig-Hellman", type=int, default=36)
    parser.add_argument("-ma", "--mov_attack", help="maximum bit size for MOV-attack", type=int, default=36)
    parser.add_argument("-c", "--count", help="count for each algorithm", type=int, default=44)

    args = parser.parse_args()

    testGraphs(args.minbit, args.bruteforce, args.baby_step, args.pohlig_hellman,
                args.pollard_lambda, args.pollard_rho, args.mov_attack, args.count)
