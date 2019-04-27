#
#    File: plots.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/19
#
#    Functionality: helper function for plotting graphs
#
#    Instructions: intended use is to import this file as a module and to
#                  use the functions provided as needed
#

############ IMPORTS #########
import numpy as np
import math
import matplotlib.pyplot as plt                                                 # for drawing graphs


############ GLOBAL CONSTANTS ############

marks = ["o", "s", "^", "d", "*", "4"]

############ GRAPHICAL FUNCTIONS ############


def setupGraph():
    """ initial setup """
    outFig = plt.figure(figsize = (8, 8))                                       # define output figure
    tPlt = outFig.add_subplot(211)                                              # add sub plot to figure
    cPlt = outFig.add_subplot(212)                                              # add sub plot to figure

    outFig.show()                                                               # show figure
    outFig.canvas.draw()                                                        # first render

    return outFig, tPlt, cPlt


def updateGraph(resTime, resCount, outFig, tPlt, cPlt, labels):
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


def curve_func(x, a, b, c):
    """ trying to draw this curve to fit data """

    return a * np.exp(b * x) + c


def dataToPlot(data, plot, labels):
    """ given a dictionary of data and a plt adds the data and a best fit line """

    i = 0

    for resDic in data:
        if resDic != {}:                                                        # check for empty
            keys = sorted(list(resDic.keys()))                                  # get sorted list of keys
            vals = [resDic[key][0] for key in keys]                             # extract Y axis
            vals = [math.log(v,2) if v != 0 else 0 for v in vals]               # log it

            plot.scatter(keys, vals, label=labels[i], marker=marks[i])          # draw points

            try:
                xFit = np.linspace(keys[0], keys[-1], 100)                      # these are our x points
                p = np.poly1d(np.polyfit(keys, vals, 1))
                plot.plot(xFit, p(xFit))                                        # plot our expected line
                i += 1

            except Exception:
                pass

    return True                                                                 # return finished
