#!/bin/bash

# https://www.pair.com/support/kb/paircloud-diff-and-patch/
diff -ruN original 'patched/localhost%3a4567' | tee game.patch
