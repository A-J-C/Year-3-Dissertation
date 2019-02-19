#
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.0
#    Date: 06/02/18
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

def run(k = 10, brute = True, babyStep = True, rho=True, verbose = True):
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

    return bf_res, bsgs_res, rho_res


def tests(k = 10, iter = 10000, algo = "bf", csvFile = "res.csv"):
    """ run tests to generate statistics """

    with open(csvFile, "w+") as file:
        out = "keySize,"
        out += algo + "_success," + algo + "_time," + algo + "_count,"
        file.write(out + "\n")

        bf = (algo == "bf")
        bsgs = (algo == "bsgs")
        rho = (algo == "rho")

        algorithms = ["bf", "bsbgs", "rho"]

        for _ in range(iter):
            res = run(k, bf, bsgs, rho, True)
            out = str(k) + ","
            r = res[algorithms.index(algo)]

            out += (str(r["res"]) + "," + str(r["time"]) +
                    "," + str(r["count"]) + ",")
            file.write(out + "\n")
            file.flush()


############ COMMAND LINE INTERFACE #########

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="turns output off", action="store_true")
    parser.add_argument("-k", "--bitsize", help="bitlength of public key", action="store", type=int, default=10)
    parser.add_argument("-bf", "--bruteforce", help="turns bruteforce decryption on", action="store_true")
    parser.add_argument("-bs", "--baby_step", help="turns baby_step-giant_step decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")
    parser.add_argument("-a", "--all", help="turns all on", action="store_true")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        # default run
        run()
    elif args.all:
        run(args.bitsize, True, True, True, not args.verbose)
    else:
        run(args.bitsize, args.bruteforce, args.baby_step, args.pollard_rho, not args.verbose)
