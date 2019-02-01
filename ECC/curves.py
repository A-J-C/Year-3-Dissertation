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


############ POINT CLASS #########

class Point:
    """ stores a point on a particular curve
        and defines point equality, addition and multiplication """

    def __init__(self, x, y, curve):
        self.x = x                                                  # set point at x
        self.y = y                                                  # set point at y
        self.curve = curve                                          # set curve point belongs to
        self.inf = False                                            # this point isn't at infinity


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

        if self.inf or point.inf:                                   # if one of the points is infinity
            return self.inf == point.inf                            # return if both are infinity
        else:
            return self.x == point.x and                            # else check points are equal
                self.y == point.y


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

        deltaX = (point.x - self.x) % self.curve.fp                 # diff x coords
        deltaY = (point.y - self.y) % fp                            # diff y coords

        # if x have same coord
        if point.x == self.x:
            if point.y == self.y:                                   # point doubling case
                grad = ((3 * self.x * self.x +                      # 3.x^2
                    2 * self.curve.a * self.x) /                    # 2.a.x
                    (2 * self.y)) % self.curve.fp                   # 2.y
            else:                                                   # self.y == - point.y
                return self.curve.pointAtInf()                      # return point at infinity
        else:                                                       # standard case
            grad = (deltaY / deltaX) % self.curve.fp                # compute gradient

        x3 = (grad * grad - self.x - point.x) % self.curve.fp       # compute new x coord
        y3 = (- self.y - grad*(x3 - self.x)) % self.curve.fp        # compute new y coord

        return Point(x3, y3, self.curve)                            # return a new point with updated coords


    def __mult__(self, k):
        """ defines multiplication via repeated squares """

        # sanity check
        if self.inf or k == 0:
            return self.curve.pointAtInf()                          # return point at infinity

        # repeated squares algo

############ CURVE CLASS #########

class Curve:
    """ defines a curve in standard form y^2 = x^3 + ax + b
        (Weierstrass form) """


    def __init__(self, a, b, fp):
        self.a = a                                                  # set x coefficent
        self.b = b                                                  # set constant
        self.fp = fp                                                # set prime field


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


    ############ COMPUTATION FUNCTIONS #########

    def valid(self):
        """ checks the graph is valid over the real numbers """

        # delta =-16 * (4a^3 + 27b^2)
        self.discriminant = -16 * (4*self.a*self.a*self.a + 27 * self.b*self.b)
        return self.discriminant != 0


    def onCurve(self, point):
        """ checks that a given point is on curve """

        # check point thinks of itself as a member of the curve
        if point.curve != self:
            return False

        # infinity point is on curve
        if point.inf == True:
            return True

        # check it satisfies equation
        leftHS = point.y * point.y
        rightHS = point.x*point.x*point.x + self.a*point.x + self.b

        return leftHS == rightHS                                    # check equation is satisfied


    def order(self, point):
        """ gives the order of a point on the curve """

        # check point is on curve first
        if not self.onCurve(point):
            return 0

        # replace with this at some point https://en.wikipedia.org/wiki/Schoof%27s_algorithm
        Q = point
        orderP = 1
        #Add P to Q repeatedly until obtaining the identity (point at infinity).
        while not Q.is_infinite():
            Q = Q + point
            orderP += 1
        return orderP
