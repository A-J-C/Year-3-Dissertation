#
#    File: screts.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 1.0
#    Date: 12/02/19
#
#    Functionality: replaces secrets module from Python 3.6
#
#    Instructions: intended use is to import this file as a module and to
#                  use the functions provided as needed
#

############ IMPORTS #########
import random


############ FUNCTIONS #########

def randbelow(n):
    """ returns a random integer below n """

    return random.randint(0, n -1)

def randbits(k):
    """ returns an integer with k random bits """

    bits = ["0" if random.random() <= 0.5 else "1" for _ in range(k)]

    return int("".join(bits), 2)

class SystemRandom:
    """ to replecate secrets.SystemRandom() """

    def randrange(self, x, y):
        """ returns a random integer in range [x, y) """
        return random.SystemRandom().randrange(x, y)
