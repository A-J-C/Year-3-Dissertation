#
#    File: run_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.1
#    Date: 26/02/19
#
#    Functionality: utilises other programs to generate and subsequently break RSA
#                   keys using a variety of algorithms, while collecting diagnostics
#                   to compare and check the results of each of these algorithms
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 run_RSA.py -h (to see possible flags)
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

import argparse
from RSA import *


############ FUNCTIONS #########

def runSolver(keys, solver, name, verbose):
    """ runs a check on the solver, given the correct keys """

    if verbose:
        print("="*10, name, "="*10)

    solver.solve()                                                              # factor n

    if verbose:
        if solver.d == keys.d:                                                  # check for correctness
            print("Success!")
        else:
            print("Fail!")

    return {"res": (solver.d == keys.d),                                        # return result as dict
            "time": solver.time,
            "count": solver.count}


############ MASTER PROGRAM #########

def run(k = 10, brute = True, ferm = True, pRho = True, knj = True, pMinus = True, verbose = True):
    """ creates a k-bit RSA key, cracks it with several algorithms, and generates
        statistics to compare their performance """

    ############ KEY GENERATION #########
    if verbose:
        print("\n" + "="*10, "GENERATING", "="*10)

    keys = generate_RSA.KeyGen(k, verbose)                                      # create new instance

    sanity = keys.generateKeys()                                                # get key and primes

    if not sanity:
        if verbose:
            print ("Please fix input and try again")
        return False

    ############ BRUTE FORCE ATTACK #########
    bf_res = {}
    if brute:
        bf = brute_force.BFSolver(keys.n, keys.e, verbose)                      # create new instance with public key info
        bf_res = runSolver(keys, bf, "BRUTE FORCE", verbose)                    # check solver

    ############ FERMAT'S FACTORISATION METHOD #########
    fer_res = {}
    if ferm:
        fer = fermats.FFSolver(keys.n, keys.e, verbose)                         # create new instance with public key info
        fer_res = runSolver(keys, fer, "FERMAT'S METHOD", verbose)              # check solver

    ############ POLLARD'S RHO ATTACK #########
    rho_res = {}
    if pRho:
        rho = pollard_rho.RhoSolver(keys.n, keys.e, verbose)                    # create new instance with public key info
        rho_res = runSolver(keys, rho, "POLLARD'S RHO", verbose)                # check solver

    ############ KNJ FACTORISATION #########
    knj_res = {}
    if knj:
        knjSol = knj_factorisation.KNJSolver(keys.n, keys.e, verbose)           # create new instance with public key info
        knj_res = runSolver(keys, knjSol, "KNJ FACTORISATION", verbose)         # check solver

    ############ POLLARD'S P - 1 ATTACK #########
    minus_res = {}
    if pMinus:
        polMin = pollard_p_minus_1.PSolver(keys.n, keys.e, verbose)             # create new instance with public key info
        minus_res = runSolver(keys, polMin, "POLLARD'S P-1", verbose)           # check solver

    return bf_res, fer_res, rho_res, knj_res, minus_res


def test(k = 10):
    """ tries to find failure point """

    res = {}
    res['res'] = True

    # loop till fail
    while res['res']:
        res = run(k, False, True, False, False, False, verbose = True)[1]


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="turns output off", action="store_true")
    parser.add_argument("-k", "--bitsize", help="bitlength of public key", action="store", type=int, default=10)
    parser.add_argument("-bf", "--bruteforce", help="turns bruteforce decryption on", action="store_true")
    parser.add_argument("-ff", "--fermats", help="turns fermats decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")
    parser.add_argument("-knj", "--KNJ_factorisation", help="turns KNJ_factorisation decryption on", action="store_true")
    parser.add_argument("-pp", "--pollard_p_minus_1", help="turns pollard_p_minus_1 decryption on", action="store_true")
    parser.add_argument("-t", "--test", help="runs failure test", action="store_true")

    args = parser.parse_args()

    if args.test:
        test(args.bitsize)

    elif len(sys.argv) == 1:
        # default run
        run()
    elif args.all:
        run(args.bitsize, True, True, True, True, True, not args.verbose)
    else:
        run(args.bitsize, args.bruteforce, args.fermats, args.pollard_rho, args.KNJ_factorisation, args.pollard_p_minus_1, not args.verbose)
