#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

rm *.o
g++ -O3 -fno-inline -g semaphore.cc shared.cc signals.cc thread.cc --std=c++17 -O0 -g -z execstack -fno-stack-protector -c
ld -r *.o -o threading.obj
rm *.o
mv threading.obj threading.o
