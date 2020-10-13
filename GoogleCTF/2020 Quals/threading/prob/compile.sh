#!/bin/bash

set -e -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

"${DIR}/simple_lang/compile.sh" "${1}" "${2}"
