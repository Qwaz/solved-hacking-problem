#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

g++ *.cc --std=c++17 -O3 -I../PEGTL/include -o compiler
