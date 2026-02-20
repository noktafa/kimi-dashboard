#!/bin/bash
# Quick integration test for the kimi ecosystem

set -e

echo "=== Kimi Ecosystem Integration Test ==="
echo

# Check CLIs exist
echo "Checking CLIs..."
which kimi-audit >/dev/null 2>&1 || { echo "kimi-audit not found"; exit 1; }
which kimi-admin >/dev/null 2>&1 || { echo "kimi-admin not found"; exit 1; }
which kimi-converge >/dev/null 2>&1 || { echo "kimi-converge not found"; exit 1; }
echo "✓ All CLIs installed"
echo

# Test security auditor
echo "Testing kimi-security-auditor..."
kimi-audit --help >/dev/null 2>&1
echo "✓ kimi-audit --help works"
echo

# Test sysadmin-ai
echo "Testing kimi-sysadmin-ai..."
kimi-admin --help >/dev/null 2>&1
echo "✓ kimi-admin --help works"

# Test safety filters
echo "Testing safety filters..."
RESULT=$(kimi-admin check "rm -rf /" 2>&1 || true)
if echo "$RESULT" | grep -q "BLOCKED"; then
    echo "✓ rm -rf / correctly blocked"
else
    echo "✗ rm -rf / NOT blocked (safety issue!)"
    exit 1
fi

echo

# Test convergence loop
echo "Testing kimi-convergence-loop..."
kimi-converge --help >/dev/null 2>&1
echo "✓ kimi-converge --help works"
echo

echo "=== All Integration Tests Passed ==="
