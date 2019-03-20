#
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.0
#    Date: 06/02/19
#
#    Functionality: utilises other programs to generate and subsequently break ECC
#                   keys using a variety of algorithms, while collecting diagnostics
#                   to compare and check the results of each of these algorithms
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 run_ECC.py -h (to see possible flags)
#

############ IMPORTS #########

# needed for pydocs to correctly find everything
import sys
sys.path.append('Programming/')

import argparse
from ECC import *


############ FUNCTIONS #########

def runSolver(keys, solver, name, verbose):
    """ runs a check on the solver, given the correct keys """

    if verbose:
        print("="*10, name, "="*10)

    solver.solve()                                                              # Elliptic Curve discrete log problem

    if verbose:
        if solver.k == keys.k:                                                  # check for correctness
            print("Success!")
        else:
            print("Fail!")

    return {"res": (solver.k == keys.k),                                        # return result as dict
            "time": solver.time,
            "count": solver.count}


############ MASTER PROGRAM #########

def run(k = 10, brute = True, babyStep = True, rho = True,
        lamb = True, poHel = True, verbose = True):
    """ creates a k-bit ECC key, cracks it with several algorithms, and generates
        statistics to compare their performance """

    ############ KEY GENERATION #########
    if verbose:
        print("\n" + "="*10, "GENERATING", "="*10)

    keys = generate_ECC.KeyGen(k, verbose)                                      # create new instance
    keys.generateCurve()                                                        # find a good curve

    sanity = keys.generateKeys()                                                # get key and primes

    if not sanity:
        if verbose:
            print("Please fix input and try again")
        return False

    ############ BRUTE FORCE ATTACK #########
    bf_res = {}
    if brute:
        bf = brute_force.BFSolver(keys.curve, keys.Q, keys.G, verbose)          # create new instance with public key info
        bf_res = runSolver(keys, bf, "BRUTE FORCE", verbose)                    # check solver

    ############ BABYSTEP-GIANTSTEP ATTACK #########
    bsgs_res = {}
    if babyStep:
        bg = baby_step.BGSolver(keys.curve, keys.Q, keys.G, verbose)            # create new instance with public key info
        bsgs_res = runSolver(keys, bg, "BABYSTEP_GIANTSTEP", verbose)           # check solver

    ############ POLLARD'S RHO ATTACK #########
    rho_res = {}
    if rho:
        rhoS = pollard_rho.PRSolver(keys.curve, keys.Q, keys.G, verbose)        # create new instance with public key info
        rho_res = runSolver(keys, rhoS, "POLLARD'S RHO", verbose)               # check solver

    ############ POLLARD'S RHO ATTACK #########
    lambda_res = {}
    if lamb:
        lambSol = pollard_lambda.PLSolver(keys.curve, keys.Q, keys.G, verbose)  # create new instance with public key info
        lambda_res = runSolver(keys, lambSol, "POLLARD'S LAMBDA", verbose)      # check solver

    ############ POHLIG HELLMAN ATTACK #########
    poh_res = {}
    if poHel:
        pohSol = pohlig_hellman.PHSolver(keys.curve, keys.Q, keys.G, verbose)   # create new instance with public key info
        poh_res = runSolver(keys, pohSol, "POHLIG HELLMAN", verbose)            # check solver

    return bf_res, bsgs_res, rho_res, lambda_res, poh_res


def test(k = 10):
    """ tries to find failure point """

    res = {}
    res['res'] = True

    # loop till fail
    while res['res']:
        res = run(k, False, False, False, False, True, verbose = True)[-1]


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="turns output off", action="store_true")
    parser.add_argument("-k", "--bitsize", help="bitlength of public key", action="store", type=int, default=10)
    parser.add_argument("-bf", "--bruteforce", help="turns bruteforce decryption on", action="store_true")
    parser.add_argument("-bs", "--baby_step", help="turns baby_step-giant_step decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")
    parser.add_argument("-pl", "--pollard_lambda", help="turns pollard_lambda decryption on", action="store_true")
    parser.add_argument("-ph", "--pohlig_hellman", help="turns pohlig_hellman decryption on", action="store_true")
    parser.add_argument("-a", "--all", help="turns all on", action="store_true")
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
        run(args.bitsize, args.bruteforce, args.baby_step, args.pollard_rho, args.pollard_lambda, args.pohlig_hellman, not args.verbose)
