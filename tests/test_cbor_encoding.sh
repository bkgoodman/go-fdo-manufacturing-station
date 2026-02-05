#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Test script for CBOR encoding fixes in rendezvous information
# Tests IP address, port, and protocol encoding

set -e

echo "=== CBOR Encoding Test ==="

# Test configuration with proper CBOR encoding
TEST_CONFIG="/tmp/cbor_test.cfg"
cat > "$TEST_CONFIG" << 'EOF'
# Basic configuration
debug: true

# Server settings
server:
  addr: "localhost:9999"
  ext_addr: "localhost:9999"
  use_tls: false
  insecure_tls: false

# Database settings
database:
  path: "test_cbor.db"
  password: ""

# Manufacturing settings
manufacturing:
  device_ca_key_type: "ec384"
  owner_key_type: "ec384"
  generate_certificates: true
  first_time_init: false

# Rendezvous configuration for CBOR testing
rendezvous:
  entries:
    - host: "127.0.0.1"
      port: 8080
      scheme: "http"
    - host: "192.168.1.100"
      port: 443
      scheme: "https"

# Voucher Management Configuration
voucher_management:
  persist_to_db: false
  voucher_signing:
    mode: "internal"
    first_time_init: true
  owner_signover:
    mode: "static"
    static_public_key: ""
EOF

echo "✅ Created CBOR test configuration"

# Test 1: IP Address Encoding (should be byte array with 0x50 prefix)
echo ""
echo "Test 1: IP Address Encoding"
echo "Expected: 0x50 + raw IP bytes [127, 0, 0, 1]"
echo "Should NOT be ASCII string '127.0.0.1'"

# Test 2: Port Encoding (should be CBOR integer)
echo ""
echo "Test 2: Port Encoding"
echo "Expected: CBOR integer 8080 = [0x19, 0x1F, 0x90]"
echo "Should NOT be ASCII string '8080'"

# Test 3: Protocol Encoding (should be CBOR unsigned integer)
echo ""
echo "Test 3: Protocol Encoding"
echo "Expected: HTTP = CBOR unsigned integer 1 = [0x01]"
echo "Expected: HTTPS = CBOR unsigned integer 2 = [0x02]"
echo "Should NOT be ASCII string '3' (which would be signed integer -20)"

# Test 4: Port Variable (should be RVDevPort not RVOwnerPort)
echo ""
echo "Test 4: Port Variable"
echo "Expected: RVDevPort (3) for devices"
echo "Should NOT be RVOwnerPort (4) for owners"

echo ""
echo "✅ CBOR encoding test setup complete!"
echo ""
echo "Expected behavior:"
echo "1. Server starts with proper rendezvous configuration"
echo "2. DI client connects"
echo "3. RvInfo callback returns properly encoded data"
echo "4. Client can successfully parse rendezvous URLs"
echo "5. No 'unsupported type' or 'invalid memory address' errors"

echo ""
echo "To run full test:"
echo "1. Start server: ./fdo-manufacturing-station -config $TEST_CONFIG"
echo "2. Run client: cd go-fdo && go run ./examples/cmd/client -di http://localhost:9999 -di-key ec384"
echo "3. Check for CBOR encoding debug messages in server logs"
