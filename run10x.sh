#!/bin/bash
# run10x.sh - Run all test suites 10 times to verify consistency
# Tests: AES-256-GCM encryption, Morse encoding, Ed25519 signing, WAV decode

cd /workspaces/dad-mode-morse

echo "=============================================="
echo "Dad Mode Morse - Full Test Suite (10x)"
echo "=============================================="
echo "Tests: Encryption (32 tests) + WAV Decode (16 tests)"
echo "Includes: AES-256-GCM, Argon2id, Signal Key, Ed25519 signing"
echo ""

CRYPTO_PASS=0
CRYPTO_FAIL=0
DECODE_PASS=0
DECODE_FAIL=0

for i in 1 2 3 4 5 6 7 8 9 10; do
  printf "\n=== Run $i/10 ===\n"
  
  # Run crypto tests (capture output, show summary)
  echo "🔐 Encryption tests..."
  CRYPTO_OUT=$(node test_crypto.mjs 2>&1) && CRYPTO_RC=0 || CRYPTO_RC=$?
  echo "$CRYPTO_OUT" | tail -5
  if [ $CRYPTO_RC -eq 0 ]; then
    ((CRYPTO_PASS++))
  else
    ((CRYPTO_FAIL++))
    echo "   ❌ Crypto tests failed on run $i"
  fi
  
  # Run decode tests (capture output, show summary)
  echo "📡 WAV decode tests..."
  DECODE_OUT=$(python3 test_decode.py 2>&1) && DECODE_RC=0 || DECODE_RC=$?
  echo "$DECODE_OUT" | tail -3
  if [ $DECODE_RC -eq 0 ]; then
    ((DECODE_PASS++))
  else
    ((DECODE_FAIL++))
    echo "   ❌ Decode tests failed on run $i"
  fi
done

echo ""
echo "=============================================="
echo "SUMMARY"
echo "=============================================="
echo "Crypto tests:  $CRYPTO_PASS/10 passed, $CRYPTO_FAIL failed"
echo "Decode tests:  $DECODE_PASS/10 passed, $DECODE_FAIL failed"
echo ""

if [ $CRYPTO_FAIL -eq 0 ] && [ $DECODE_FAIL -eq 0 ]; then
  echo "✅ ALL 10 RUNS PASSED - All capabilities verified!"
  exit 0
else
  echo "❌ SOME RUNS FAILED"
  exit 1
fi
