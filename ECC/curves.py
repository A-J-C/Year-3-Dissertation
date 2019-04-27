#
#    File: curves.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.1
#    Date: 06/02/19
#
#    Functionality: defines curves and points for ECC
#
#    Instructions: intended use is to import this file as a module and to
#                  use the two defined classes
#
#    Notes: makes use of a python wrapper for the maths language PARI/GP
#           https://pari.math.u-bordeaux.fr/
#           This implements the SEA algorithm amongst others to speed up
#           finding the order of a point on the curve
#           this algorithm is vital for my curve generation to work on large
#           key sizes. So I have used it minimally in my code as implementing
#           the SEA algorithm effectively would be an entire project in itself
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

# allows me to run this file directly, i.e. not wrapped up in the package
if not __package__:
    sys.path.append('../')

from cypari import pari
from utils import helper

############ EXTRA FUNCTIONS #########

def secondCurve(curve, degree):
    """ creates a second curve over an extended field """

    p = pow(curve.fp, degree)

    field = pari("a = ffgen(" + str(p) + ", 'a)")

    curve2str = "["+str(curve.a)+","+str(curve.b)+"]" +", " + str(field)

    curve2 = pari("E2 = ellinit(" + curve2str + ")")

    c = Curve()
    c.setE(curve2)

    return c.getR(), c


def cyclicLog(G, Q, o):
    """ answers the log problem of G = Q^k over a cyclic field of order o """

    # might not work
    try:
        return pari('fflog(' + G + ',' + Q + ',' + o + ')')
    except:
        return 0


def isPrime(p):
    """ uses pari to test for primes (easier to use than my own implementation) """

    if p != int(p):
        return False

    return pari("isprime(" + str(int(p)) + ")")

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

        if point is None:
            return False
        elif self.inf or point.inf:                                     # if one of the points is infinity
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


    def __sub__(self, point):
        """ given a second point returns the subtracton of the two """
        return self + point.inverted()                                  # simply add the inverted point


    def __mul__(self, k):
        """ defines multiplication via repeated squares """

        # sanity check
        if self.inf or k % self.curve.order(self) == 0:
            return self.curve.pointAtInf()                              # return point at infinity

        # repeated squares algorith
        Q = self.curve.pointAtInf()                                     # copy to Q
        G = self

        while k > 0:                                                    # continue while k is greater than 0

            if k % 2 == 1:                                              # if k is odd
                k -= 1
                Q = G + Q                                               # add a single G to Q
            else:
                k //= 2
                G += G                                                  # double G

        return Q


    def __str__(self):
        """ defines how it should be printed """

        if self.inf:
            return "Inf"
        else:
            return "(" + str(self.x) + ", " + str(self.y) + ")"


    def inverted(self):
        """ returns the inverted point """

        if self.inf:
            return self                                                 # simple case of base point
        else:
            return Point(self.x, (-self.y) % self.curve.fp, self.curve) # invert over field


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
        self.discriminant = 0                                           # discriminant of curve
        self.card = 0                                                   # cardinality of the curve
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

    def setE(self, E):
        """ sets pari curve """
        self.E = E


    ############ COMPUTATION FUNCTIONS #########

    def __eq__(self, curve):
        """ defines curve equality """
        if curve is None:
            return False
        else:
            return (self.a == curve.a and
                    self.b == curve.b and
                    self.fp == curve.fp)


    def valid(self):
        """ checks the graph is valid over the real numbers
            and has actual points on it """

        # delta =-16 * (4a^3 + 27b^2)
        self.discriminant = -16 * (4*self.a*self.a*self.a + 27 * self.b*self.b)

        try:
            orderOfCurve = pari(self.E).ellcard()                       # try to get order
        except:
            return False                                                # if there's an exception the curve has no integer points

        return self.discriminant != 0


    def initPari(self):
        """ initialises the pari version of the curve for fast implementation """

        curve = "["+str(self.a)+","+str(self.b)+"]"+" , "+str(self.fp)  # get string rep of curve
        self.E = pari('ellinit(' + curve + ')')                         # create pari version of curve

        try:
            self.card = pari(self.E).ellcard()                              # get cardinality
        except:
            pass


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
        if point.inf:
            return True

        # check it satisfies equation
        leftHS = (point.y * point.y) % self.fp
        rightHS = (point.x*point.x*point.x + self.a*point.x + self.b) % self.fp

        return leftHS == rightHS                                        # check equation is satisfied


    def order(self, point):
        """ gives the order of a point on the curve """

        # check point is on curve first
        # and pari curve exists
        if not self.onCurve(point) or self.E is None:
            return 0

        P = "[" + str(point.x) + "," + str(point.y) + "]"               # string representation of point

        # finds order using Schoof-Elkies-Atkin algorithm
        orderP = pari(self.E).ellorder(P)                               # use Pari to calculate order

        return int(orderP)


    def getG(self):
        """ returns a generator point using Pari """

        # if exists return it
        if self.G is not None:
            return self.G

        # else generate it

        pG = pari(self.E).ellgenerators()[0]                            # get first generator using pari
        pG = str(pG)                                                    # get string representation
        Gx = int(pG.split(",")[0].split("(")[1])                        # extract x coord
        Gy = int(pG.split(",")[2].split("(")[1])                        # extract y coord

        G = Point(Gx, Gy, self)                                         # create as Point class
        self.G = G                                                      # store result

        self.ord = self.order(G)                                        # store order

        return G                                                        # return point


    def getR(self):
        """ returns a new generator point if one exists"""

        generators = pari(self.E).ellgenerators()                       # get all generators

        # find G
        if self.G is not None:
            G = self.G

        # else generate it
        else:
            pG = str(generators[0])
            if pG.startswith("[Mod"):
                Gx = int(pG.split(",")[0].split("(")[1])                # extract x coord
                Gy = int(pG.split(",")[2].split("(")[1])                # extract y coord
            else:
                Gx, Gy = pG.split(",")


        for gen in generators:
            pR = str(gen)                                               # get string representation

            if pR.startswith("[Mod"):
                Rx = int(pR.split(",")[0].split("(")[1])                # extract x coord
                Ry = int(pR.split(",")[2].split("(")[1])                # extract y coord
            else:
                Rx, Ry = str(pR).split(",")

            if Rx != Gx and Ry != Gy:                                   # if not the same as G
                return pR                                               # return result

        return False                                                    # return point


    def group(self):
        """ returns ellgroup """

        return str(pari(self.E).ellgroup()[0])


    def weil(self, G, P, m):
        """ uses pari to compute the weil paring of a point on the curve
            to a new prime extension field """

        P = "[" + str(P.x) + "," + str(P.y) + "]"                       # string representation of point
        wP = pari("ellweilpairing(" + str(self.E) + ", "
                  + str(G) + "," + P + "," + str(m) +")")

        return str(wP)


    def __str__(self):
        """ string representation of the Curve """

        eq = "y^2 = x^3"

        if self.a:
            eq += " + " + str(self.a) + "x"

        if self.b:
            eq += " + " + str(self.b)

        eq += " % " + str(self.fp)

        return eq
