#
#    File: run_RSA.py
#    Author: Alexander Craig
#    Project: An Analysis of the Security of RSA & Elliptic Curve Cryptography
#    Supervisor: Maximilien Gadouleau
#    Version: 2.0
#    Date: 06/02/18
#
#    Functionality: utilises other programs to generate and subsequently break RSA
#                   keys using a variety of algorithms, while collecting diagnostics
#                   to compare and check the results of each of these algorithms
#
#    Instructions: used to run all other files to be run from the command line:
#
#    CLI: python3 run_RSA.py [bitLength] [bruteForce] [fermat] [pollard'sRho]
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

def run(k = 10, brute = True, ferm = True, pRho = True, verbose = True):
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

    return bf_res, fer_res, rho_res


def tests(k = 10, iter = 10000, algo = "bf", csvFile = "res.csv"):
    """ run tests to generate statistics """

    with open(csvFile, "w+") as file:
        out = "keySize,"
        out += algo + "_success," + algo + "_time," + algo + "_count,"
        file.write(out + "\n")

        bf = (algo == "bf")
        rho = (algo == "rho")

        for _ in range(iter):
            res = run(k, bf, rho, True)
            out = str(k) + ","
            r = res[0] if algo == "bf" else res[1]

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
    parser.add_argument("-ff", "--fermats", help="turns fermats decryption on", action="store_true")
    parser.add_argument("-pr", "--pollard_rho", help="turns pollard_rho decryption on", action="store_true")
    parser.add_argument("-a", "--all", help="turns all on", action="store_true")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        # default run
        run()
    elif args.all:
        run(args.bitsize, True, True, True, not args.verbose)
    else:
        run(args.bitsize, args.bruteforce, args.fermats, args.pollard_rho, not args.verbose)
