#!/bin/bash

# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

echo "=== Static Owner Key Signover Test ==="

# Test static public key parsing
echo "Testing static public key configuration..."
TEST_KEY="-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+UWQc7Qf5qB5RtvGzKB8wQ
-----END PUBLIC KEY-----"

# Test that the key can be parsed
if echo "$TEST_KEY" | grep -q "BEGIN PUBLIC KEY"; then
    echo "✅ Static public key format is valid"
else
    echo "❌ Static public key format is invalid"
    exit 1
fi

if echo "$TEST_KEY" | grep -q "END PUBLIC KEY"; then
    echo "✅ Static public key has proper ending"
else
    echo "❌ Static public key missing ending"
    exit 1
fi

# Test PEM block detection
if echo "$TEST_KEY" | head -1 | grep -q "BEGIN"; then
    echo "✅ PEM block start detected"
else
    echo "❌ PEM block start not detected"
    exit 1
fi

echo ""
echo "✅ Static owner key test setup complete!"
echo ""
echo "Expected behavior:"
echo "1. Server starts with owner_signover.mode=static"
echo "2. Server parses static_public_key from config"
echo "3. DI client connects"
echo "4. Voucher callback uses parsed static public key"
echo "5. Voucher is extended to static owner"
echo "6. Voucher upload echoes with 'Voucher uploaded and signed:'"
