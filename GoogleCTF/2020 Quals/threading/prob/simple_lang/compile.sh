#!/bin/bash

set -e -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

"${DIR}/compiler/compiler" "${1}" /tmp/tmp.cc
clang++ -O3 -g --std=c++17 -Werror=return-type -g /tmp/tmp.cc "${DIR}/../threading/threading.o" -I"${DIR}/runtime" -lpthread -z execstack -fno-stack-protector -o "${2}"

