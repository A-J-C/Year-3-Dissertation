#
#    File: graphs_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/19
#
#    Functionality: utilises other programs to generate and subsequently break RSA
#                   keys using a variety of algorithms, generating a few graphs
#                   to show general trends as we go
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 graphs_RSA.py -h (to see possible flags)
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

resCount = [{}, {}, {}, {}]                                                     # stores results to graph as dictionaries
resTime = [{}, {}, {}, {}]                                                     # stores results to graph as dictionaries
running = True                                                                  # to stop threads


############ FUNCTIONS #########

def setupGraph():
    """ initial setup """
    outFig = plt.figure(figsize = (8, 8))                                       # define output figure
    tPlt = outFig.add_subplot(211)                                              # add sub plot to figure
    cPlt = outFig.add_subplot(212)                                              # add sub plot to figure

    outFig.show()                                                               # show figure
    outFig.canvas.draw()                                                        # first render

    return outFig, tPlt, cPlt


def updateGraph(outFig, tPlt, cPlt, labels):
    """ redraws the plot to take account of incoming data
        adapted to enable it to work with jupyter notebooks """

    tPlt.clear()                                                                # clear plot
    cPlt.clear()

    dataToPlot(resTime, tPlt, labels)                                           # plot data
    dataToPlot(resCount, cPlt, labels)

    tPlt.set_xlabel("Key-Size (bits)")
    cPlt.set_xlabel("Key-Size (bits)")
    tPlt.set_ylabel("log(Time (s))")
    cPlt.set_ylabel("log(Numbers Checked)")

    tPlt.legend()
    cPlt.legend()

    outFig.tight_layout()                                                       # looks nicer
    outFig.canvas.draw()                                                        # re draw
    plt.pause(0.001)                                                            # pause


def getResults(solver, ind, minBit, maxBit, COUNT):
    """ produces a graph, given a solver, result index and bit range """

    for i in range(COUNT):
        k = secrets.randbelow(maxBit - minBit) + minBit                         # get in range
        keys = generate_RSA.KeyGen(k)                                           # initialise keys
        keys.generateKeys()                                                     # generate keys

        solver.setN(keys.n)                                                     # setup solver
        solver.setE(keys.e)

        solver.solve()                                                          # solve problem

        k = int(math.ceil(math.log(keys.n, 2)))                                 # get accurate bit length

        if solver.d == keys.d:                                                  # if we got it right
            if k not in resTime[ind]:                                           # if we've not yet had a result for k
                resTime[ind][k] = [solver.time * 10000, 1]                      # then set
                resCount[ind][k] = [solver.count, 1]
            else:
                oldT, oldC = resTime[ind][k]                                    # keeps a running average
                newC = oldC + 1                                                 # increment count
                newT = ((oldT * oldC) + solver.time * 10000) / newC             # get new averagae
                resTime[ind][k] = [newT, newC]                                  # without storing all variables

                oldCount, oldC = resCount[ind][k]                               # keeps a running average
                newCount = ((oldCount * oldC) + solver.count) / newC
                resCount[ind][k] = [newCount, newC]                             # without storing all variables


def stop():
    global running
    input("Press Enter to stop.")                                               # wait for input
    running = False                                                             # stop running


def testGraphs(minBit = 10, bf_bit = 44, ff_bit = 50, knj_bit = 40,
                rho_bit = 54, COUNT = 100):
    """ generates graphs testing all algorithms to show general trends
        uses a thread for each algorith, to ease congestion """

    global running, resCount, resTime                                           # to stop and reset program

    resCount = [{}, {}, {}, {}]                                                 # reset
    resTime = [{}, {}, {}, {}]

    running = True

    bf = brute_force.BFSolver(verbose = False)
    ferm = fermats.FFSolver(verbose = False)
    knj = knj_factorisation.KNJSolver(verbose = False)
    rho = pollard_rho.RhoSolver(verbose = False)

    solvers = [bf, ferm, knj, rho]
    max_bit = [bf_bit, ff_bit, knj_bit, rho_bit]

    labels = ["Brute-force", "Fermat's", "KNJ", "Pollard's Rho"]

    threading.Thread(target = stop).start()                                     # allows us to gracefully stop
    outFig, tPlt, cPlt = setupGraph()

    while running:

         for i in range(len(solvers)):                                          # loop over each solver
             getResults(solvers[i], i, minBit, max_bit[i], COUNT)               # collect a few results
             updateGraph(outFig, tPlt, cPlt, labels)                            # update graph


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--minbit", help="minimum bit size to test from", type=int, default=20)
    parser.add_argument("-bf", "--bruteforce", help="maximum bit size for brute force", type=int, default=44)
    parser.add_argument("-ff", "--fermat", help="maximum bit size for fermat's method", type=int, default=44)
    parser.add_argument("-pr", "--pollard_rho", help="maximum bit size for Pollard's Rho", type=int, default=44)
    parser.add_argument("-knj", "--knj_fact", help="maximum bit size for KNJ", type=int, default=44)
    parser.add_argument("-c", "--count", help="count for each algorithm", type=int, default=44)

    args = parser.parse_args()

    testGraphs(args.minbit, args.bruteforce, args.fermat, args.knj_fact, args.pollard_rho, args.count)
