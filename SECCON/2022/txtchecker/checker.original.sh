#!/bin/bash

read -p "Input a file path: " filepath
file $filepath 2>/dev/null | grep -q "ASCII text" 2>/dev/null

# TODO: print the result the above command.
#   $? == 0 -> It's a text file.
#   $? != 0 -> It's not a text file.
exit 0
