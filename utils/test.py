# we load the first million primes from memory

import pickle
from bisect import bisect_left
import math

with open("millionPrimes.pkl", "rb") as f:
    primes = pickle.load(f)

def quadRes(p, n):
    """ returns True if n is a quadratic residue mod p """

    lamb = 1
    alpha = (n - 1) // 2
    p = p % n

    while alpha != 0:
        if alpha % 2:
            alpha -= 1
            lamb = (lamb * p) % n
        else:
            p = (p ** 2) % n
            alpha = alpha // 2

    return lamb

for x in range(3, 55):

    multiplier =  x// 2
    bound = min(x * 20 * multiplier, primes[-1])
    bound = bisect_left(primes, bound)

    # get subset of all possible prime factors which are B-smooth
    primesSub = primes[:bound]

    # filter list as we are only interested in square conguences
    residPrimes = list(filter(lambda p: quadRes(2**x-1, p) == 1, primesSub))

    phi = len(residPrimes)

    for p in residPrimes:
        phi *= math.log(2**x-1)/math.log(p)
    
    print(phi)
