#
#    File: plots.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 06/02/18
#
#    Functionality: helper function for plotting graphs
#
#    Instructions: intended use is to import this file as a module and to
#                  use the functions provided as needed
#

############ IMPORTS #########
import numpy as np
import matplotlib.pyplot as plt                                                 # for drawing graphs
from scipy.optimize import curve_fit                                            # for curve


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

            plot.scatter(keys, vals)                                            # draw points

            try:
                xFit = np.linspace(keys[0], keys[-1], 100)                      # these are our x points
                opt = curve_fit(curve_func, keys, vals,                         # get curve
                                     (4e-06, 1.7e-01, -4.6e-05))[0]             # good guess
                yFit = curve_func(xFit, *opt)                                   # these are y points

                plot.plot(xFit, yFit)                                           # plot our expected curve

            except Exception:
                pass

    return True                                                                 # return finished
