#!/bin/bash
# run10x_output.sh - Run all test suites 10 times, save output to file
# Tests: AES-256-GCM encryption, Morse encoding, Ed25519 signing, WAV decode

cd /workspaces/dad-mode-morse
OUTPUT_FILE="/workspaces/dad-mode-morse/test_results.txt"

exec > "$OUTPUT_FILE" 2>&1

echo "=============================================="
echo "Dad Mode Morse - Full Test Suite (10x)"
echo "=============================================="
echo "Tests: Encryption (32 tests) + WAV Decode (16 tests)"
echo "Includes: AES-256-GCM, Argon2id, Signal Key, Ed25519 signing"
echo "Started: $(date)"
echo ""

CRYPTO_PASS=0
CRYPTO_FAIL=0
DECODE_PASS=0
DECODE_FAIL=0

for i in 1 2 3 4 5 6 7 8 9 10; do
  printf "\n=== Run $i/10 ===\n"
  
  # Run crypto tests
  echo "--- Encryption tests ---"
  if node test_crypto.mjs 2>&1; then
    ((CRYPTO_PASS++))
  else
    ((CRYPTO_FAIL++))
    echo "   FAILED: Crypto tests on run $i"
  fi
  
  # Run decode tests
  echo "--- WAV decode tests ---"
  if python3 test_decode.py 2>&1; then
    ((DECODE_PASS++))
  else
    ((DECODE_FAIL++))
    echo "   FAILED: Decode tests on run $i"
  fi
done

echo ""
echo "=============================================="
echo "SUMMARY"
echo "=============================================="
echo "Crypto tests:  $CRYPTO_PASS/10 passed, $CRYPTO_FAIL failed"
echo "Decode tests:  $DECODE_PASS/10 passed, $DECODE_FAIL failed"
echo "Finished: $(date)"
echo ""

if [ $CRYPTO_FAIL -eq 0 ] && [ $DECODE_FAIL -eq 0 ]; then
  echo "ALL 10 RUNS PASSED - All capabilities verified!"
else
  echo "SOME RUNS FAILED"
fi

echo ""
echo "DONE"
