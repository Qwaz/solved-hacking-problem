#!/usr/bin/env python3
from __future__ import print_function
import contextlib
import subprocess
import argparse
import hashlib
import socket
import struct
import signal
import sys
import os

# inspired by C3CTF's POW

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1

def do_solve(args):
    print('Solving challenge: "{}", n: {}'.format(args.prefix, args.strength))

    solution = solve_pow(args.prefix, args.strength)
    print('Solution: {} -> {}'.format(solution, pow_hash(args.prefix, solution)))

def do_connect(args):
    print("Connecting...")
    s = socket.create_connection((args.host, args.port))
    print("Reading...")
    powtext = s.recv(1024)
    print("Analyzing...")
    prefix = next(line for line in powtext.decode('ascii').split("\n") if line.startswith("Challenge:")).split()[1]
    strength = int(next(line for line in powtext.decode('ascii').split("\n") if line.startswith("n:")).split()[1])

    solution = solve_pow(prefix, strength)
    solution_text = b"%d\n" % solution
    print(f"Submitting {solution_text} (hashes to {pow_hash(prefix, solution)}) to satisfy {prefix}, {strength}.")
    s.send(solution_text)

    if args.tty:
        p = subprocess.Popen(["socat", f"fd:{s.fileno()}", f"file:{os.ttyname(sys.stdout.fileno())},raw,echo=0,icrnl=1"], pass_fds=[s.fileno()])
    else:
        p = subprocess.Popen(["socat", "-", f"fd:{s.fileno()}"], pass_fds=[s.fileno()])
    while True:
        try:
            p.wait()
            break
        except KeyboardInterrupt:
            p.send_signal(signal.SIGINT)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help="sub-command help", dest="sub-command")

    parser_solve = subparsers.add_parser("solve", help="solves a pow")
    parser_solve.set_defaults(func=do_solve)
    parser_solve.add_argument("strength", type=int, help="the number of zeroes at the end")
    parser_solve.add_argument("prefix", help="the prefix of the hash")

    parser_solve = subparsers.add_parser("connect", help="solves a pow and interacts")
    parser_solve.set_defaults(func=do_connect)
    parser_solve.add_argument("-t", "--tty", action="store_true", help="pass through your TTY (enables Ctrl-C and friends)")
    parser_solve.add_argument("host", help="the number of zeroes at the end")
    parser_solve.add_argument("port", type=int, help="the prefix of the hash")

    _args = parser.parse_args()
    _args.func(_args)

