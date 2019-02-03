#
#    File: curves.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.1
#    Date: 01/02/18
#
#    Functionality: defines curves and points for ECC
#
#    Instructions: intended use is to import this file as a module and to
#                  use the two defined classes
#

############ IMPORTS #########

import secrets
import math
from cypari import pari

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    import sys
    sys.path.append('../')

from utils import generate_prime
from utils import helper


############ POINT CLASS #########

class Point:
    """ stores a point on a particular curve
        and defines point equality, addition and multiplication """

    def __init__(self, x, y, curve):
        self.x = x                                                      # set point at x
        self.y = y                                                      # set point at y
        self.curve = curve                                              # set curve point belongs to
        self.inf = False                                                # this point isn't at infinity


    ############ SETTERS #########

    def setX(self, x):
        """ sets value for x """
        self.x = x

    def setY(self, y):
        """ sets value for y """
        self.y = y

    def setInf(self, inf):
        """ sets value for infinity """
        self.inf = inf

    def setCurve(self, curve):
        """ sets the curve the points are defined over """
        self.curve = curve


    ############ COMPUTATION FUNCTIONS #########

    def __eq__(self, point):
        """ given a second point returns if equal or not """

        if self.inf or point.inf:                                       # if one of the points is infinity
            return self.inf == point.inf                                # return if both are infinity
        else:
            return (self.x == point.x and                               # else check points are equal
                self.y == point.y)


    def __add__(self, point):
        """ given a second point returns the addition of the two """

        # sanity check
        if self.curve.fp != point.curve.fp:
            print ("Points must be defined over the same field")
            return 0

        # checks if either are infinity
        if self.inf:
            return point

        if point.inf:
            return self

        deltaX = (point.x - self.x) % self.curve.fp                     # diff x coords
        deltaY = (point.y - self.y) % self.curve.fp                     # diff y coords

        # if x have same coord
        if point.x == self.x:
            if point.y == self.y:                                       # point doubling case
                grad = ((3 * self.x * self.x + self.curve.a)            # 3x^2 + a
                    * helper.modInverse(2 * self.y, self.curve.fp))           
            else:                                                       # self.y == - point.y
                return self.curve.pointAtInf()                          # return point at infinity
        else:                                                           # standard case
            grad = deltaY * helper.modInverse(deltaX, self.curve.fp)    # compute gradient

        grad = grad % self.curve.fp                                     # ensure it is over the field 
        x3 = (grad * grad - self.x - point.x) % self.curve.fp           # compute new x coord
        y3 = (- self.y - grad*(x3 - self.x)) % self.curve.fp            # compute new y coord

        return Point(x3, y3, self.curve)                                # return a new point with updated coords


    def __mult__(self, k):
        """ defines multiplication via repeated squares """

        # sanity check
        if self.inf or k == 0:
            return self.curve.pointAtInf()                              # return point at infinity

        # repeated squares algo


    def __str__(self):
        """ defines how it should be printed """
        return "(" + str(self.x) + ", " + str(self.y) + ")" 
        

############ CURVE CLASS #########

class Curve:
    """ defines a curve in standard form y^2 = x^3 + ax + b
        (Weierstrass form) """


    def __init__(self, a = 0, b = 0, fp = 0, verbose = True):
        self.a = a                                                      # set x coefficent
        self.b = b                                                      # set constant
        self.fp = fp                                                    # set prime field
        self.G = None                                                   # generator value
        self.ord = 0                                                    # order of G over curve
        self.verbose = verbose                                          # additional output
        self.E = None                                                   # pari version of curve
        self.initPari()                                                 # initialise pari curve
        

    ############ SETTERS #########

    def setA(self, a):
        """ sets value for a """
        self.a = a

    def setB(self, b):
        """ sets value for b """
        self.b = b

    def setFp(self, fp):
        """ sets value for fp """
        self.fp = fp

    def setG(self, G):
        """ sets generator value """
        self.G = G


    ############ COMPUTATION FUNCTIONS #########


    def valid(self):
        """ checks the graph is valid over the real numbers """

        # delta =-16 * (4a^3 + 27b^2)
        self.discriminant = -16 * (4*self.a*self.a*self.a + 27 * self.b*self.b)
        return self.discriminant != 0


    def initPari(self):
        """ initialises the pari version of the curve for fast implementation """
        
    def pointAtInf(self):
        """ defines the point at infinity for the curve """

        inf = Point(0, 0, self)
        inf.setInf(True)
        return inf
        
        
    def onCurve(self, point):
        """ checks that a given point is on curve """

        # check point thinks of itself as a member of the curve
        if point.curve != self:
            return False

        # infinity point is on curve
        if point.inf == True:
            return True

        # check it satisfies equation
        leftHS = (point.y * point.y) % self.fp
        rightHS = (point.x*point.x*point.x + self.a*point.x + self.b) % self.fp

        return leftHS == rightHS                                        # check equation is satisfied


    def order(self, point):
        """ gives the order of a point on the curve """

        # check point is on curve first
        # and pari curve exists 
        if not self.onCurve(point) or self.E == None:
            return 0
        
        P = "[" + str(point.x) + "," + str(point.y) + "]"               # string representation of point
        oderP = pari(self.E).ellorder(P)                                # use Pari to calculate order
        
        return orderP


    def getG(self):
        """ returns a generator point, since we are working over a prime field
            all finite points are complete generators (except infinity) by
            Lagrange's theorem """

        # if exists return it
        if self.G != None:
            return self.G

        # else generate it

        # get an arbitrary point
        y = 0.5
        while y != int(y):                                              # loop till y is a natural number
            x = secrets.randbelow(10)                                   # arbitrary point
            y2 = x * x * x + self.a * x + self.b
            y = math.sqrt(y2)                                           # calculate y
            print (x, y)

        self.G = Point(x, y, self)  
        return self.G                                                   # return new point


    def __str__(self):
        """ string representation of the Curve """

        eq = "y^2 = x^3"

        if self.a:
            eq += " + " + str(self.a) + "x"

        if self.b:
            eq += " + " + str(self.b)

        return eq


############ GENERATOR FUNCTIONS #########

def generateCurve(self):
    """ tries random a and b coefficients, untill a curve of a prime number
        order > Fp/4 is produced """

    self.G = None                                                   # clear any previous generators
    self.ord = 0                                                    # clear any previous order
    self.a = secrets.randbelow(10)                                  # generate random coefficient
    self.b = secrets.randbelow(10)                                  # generate random coefficient

    if not self.valid():                                            # if not valid
        return self.generateCurve()                                 # try again

    G = self.getG()                                                 # get generator point
    order = self.order(G)                                           # get order of curve

    if order < fp/4:                                                # if order is too small
        return self.generateCurve()                                 # try again

    if not generate_prime.isPrime(ord):                             # if order isn't prime
        return self.generateCurve()                                 # try again

    return True                                                     # else we have a good curve
        
C = Curve(6, 6, 971)
P = Point(419, 770, C)
Q = P + P
print(Q)
