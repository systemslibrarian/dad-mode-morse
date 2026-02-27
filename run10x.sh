#!/bin/bash
cd /workspaces/dad-mode-morse
for i in 1 2 3 4 5 6 7 8 9 10; do
  printf "\n=== Run $i/10 ===\n"
  node test_crypto.mjs 2>&1 | tail -1
  python3 test_decode.py 2>&1 | tail -1
done
