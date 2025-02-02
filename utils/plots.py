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



############ GRAPHICAL FUNCTIONS #########

def curve_func(x, a, b, c):
    """ trying to draw this curve to fit data """

    return a * np.exp(b * x) + c


def dataToPlot(data, plot):
    """ given a dictionary of data and a plt adds the data and a best fit line """

    for resDic in data:
        if resDic != {}:                                                        # check for empty
            keys = sorted(list(resDic.keys()))                                  # get sorted list of keys
            vals = [resDic[key][0] for key in keys]                             # extract Y axis
            vals = [math.log(v,2) if v != 0 else 0 for v in vals]               # log it

            plot.scatter(keys, vals)                                            # draw points

            try:
                xFit = np.linspace(keys[0], keys[-1], 100)                      # these are our x points
                p = np.poly1d(np.polyfit(keys, vals, 1))
                plot.plot(xFit, p(xFit))                                        # plot our expected line

            except Exception:
                pass

    return True                                                                 # return finished
