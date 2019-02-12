#
#    File: graphs_ECC.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/18
#
#    Functionality: utilises other programs to generate and subsequently break ECC
#                   keys using a variety of algorithms, generating a few graphs
#                   to show general trends as we go
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 graphs_ECC.py [minBit] [maxBitBruteForce] [maxBitBabyStep] [maxBitPollard'sRho]
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

import math
import secrets
import threading
import matplotlib.pyplot as plt                                                 # for drawing graphs
from ECC import *
from utils.plots import *


############ GLOBAL VARIABLES #########

resCount = [{}, {}, {}]                                                         # stores results to graph as dictionaries
resTime = [{}, {}, {}]                                                          # stores results to graph as dictionaries
running = True                                                                  # to stop threads


############ FUNCTIONS #########

def updateGraph():
    """ redraws the plot to take account of incoming data
        adapted to enable it to work with jupyter notebooks """

    outFig = plt.figure(figsize = (8, 8))                                       # define output figure
    tPlt = outFig.add_subplot(211)                                              # add sub plot to figure
    cPlt = outFig.add_subplot(212)                                              # add sub plot to figure

    outFig.show()                                                               # show figure
    outFig.canvas.draw()                                                        # first render

    while running:
        tPlt.clear()                                                            # clear plot
        cPlt.clear()

        dataToPlot(resTime, tPlt)                                               # plot data
        dataToPlot(resCount, cPlt)

        tPlt.set_xlabel("Key-Size (bits)")
        cPlt.set_xlabel("Key-Size (bits)")
        tPlt.set_ylabel("Time (s)")
        cPlt.set_ylabel("Numbers Checked")

        outFig.tight_layout()                                                   # looks nicer
        outFig.canvas.draw()                                                    # re draw
        plt.pause(0.001)                                                        # pause


def getResults(solver, ind, minBit, maxBit):
    """ produces a graph, given a solver, result index and bit range """

    while running:
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


def testGraphs(minBit = 10, bf_bit = 22, bsgs_bit = 30, rho_bit = 30):
    """ generates graphs testing all algorithms to show general trends
        uses a thread for each algorith, to ease congestion """

    global running                                                              # to stop program

    bf = brute_force.BFSolver(v = False)                                        # define solvers
    bsgs = baby_step.BGSolver(v = False)
    rho = pollard_rho.PRSolver(v = False)

    threading.Thread(target = getResults,                                       # launch Rho thread
                     args=(bf, 0, minBit, bf_bit)).start()

    threading.Thread(target = getResults,                                       # launch Rho thread
                     args=(bsgs, 1, minBit, bsgs_bit)).start()

    threading.Thread(target = getResults,                                       # launch Rho thread
                     args=(rho, 2, minBit, rho_bit)).start()

    threading.Thread(target = stop).start()                                     # allows us to gracefully stop

    updateGraph()                                                               # has to be run in main thread


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    if len(sys.argv) == 5:
        testGraphs(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]))
    elif len(sys.argv) == 4:
        testGraphs(int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
    elif len(sys.argv) == 3:
        testGraphs(int(sys.argv[1]), int(sys.argv[2]))
    elif len(sys.argv) == 2:
        testGraphs(int(sys.argv[1]))
    else:
        testGraphs()