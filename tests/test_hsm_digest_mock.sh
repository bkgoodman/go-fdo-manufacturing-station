#!/bin/bash
# SPDX-FileCopyrightText: (C) 2026 Dell Technologies
# SPDX-License-Identifier: Apache 2.0
# Author: Brad Goodman

# Mock HSM Handler for Digest Signing
# Simulates HSM that signs a digest (binary blob) and returns signature

set -euo pipefail

# Function to output JSON error
error_exit() {
    local message="$1"
    echo "{\"signature\":\"\",\"request_id\":\"\",\"hsm_info\":{},\"error\":\"$message\"}"
    exit 1
}

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] MOCK-HSM-DIGEST: $*" >&2
}

# If no arguments provided, create a test request and run self-test
if [ $# -lt 1 ]; then
    # Create a test request file
    TEST_REQUEST="/tmp/test_hsm_digest_request.json"
    cat > "$TEST_REQUEST" << 'EOF'
{
  "digest": "dGVzdCBkaWdlc3QgZGF0YQ==",
  "request_id": "test-req-123",
  "signing_options": {
    "hash": "SHA256",
    "key_type": "ECDSA-P384"
  }
}
EOF
    REQUEST_FILE="$TEST_REQUEST"
    REQUESTID="test-req-123"
    STATION="test-station"
else
    REQUEST_FILE=$1
    REQUESTID=${2:-"unknown"}
    STATION=${3:-"unknown"}
fi

# Validate request file
if [ ! -f "$REQUEST_FILE" ]; then
    error_exit "Request file not found: $REQUEST_FILE"
fi

# Extract required fields using Python
eval "$(python3 -c "
import json
import sys
try:
    with open('$REQUEST_FILE', 'r') as f:
        data = json.load(f)
    digest = data.get('digest', '')
    request_id = data.get('request_id', '')
    signing_options = data.get('signing_options', {})
    hash_alg = signing_options.get('hash', 'SHA256')
    key_type = signing_options.get('key_type', 'ECDSA-P384')
    print(f'digest_base64=\"{digest}\"')
    print(f'request_id=\"{request_id}\"')
    print(f'hash_alg=\"{hash_alg}\"')
    print(f'key_type=\"{key_type}\"')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
")" || error_exit "Failed to parse JSON"

if [ -z "$digest_base64" ] || [ -z "$request_id" ]; then
    error_exit "Missing required fields in request"
fi

# Log request details
log "Processing digest signing request: $request_id"
log "Station: $STATION"
log "Hash algorithm: $hash_alg"
log "Key type: $key_type"

# Decode digest
log "Decoding digest from base64"
echo "$digest_base64" | base64 -d > /tmp/digest.bin || error_exit "Failed to decode digest"

# Validate digest (simple check)
if [ ! -s /tmp/digest.bin ]; then
    error_exit "Decoded digest is empty"
fi

# Log digest info
digest_size=$(wc -c < /tmp/digest.bin)
log "Digest size: $digest_size bytes"

# MOCK HSM SIGNING - Create a fake DER-encoded ECDSA signature
log "MOCK HSM: Simulating digest signing..."
signing_start=$(date +%s.%N)

# Deterministically derive r/s values from digest and metadata, then emit ASN.1 DER
signature_base64=$(python3 - <<'EOF'
import base64, hashlib, sys, pathlib

digest = pathlib.Path('/tmp/digest.bin').read_bytes()
curve_order = int('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973', 16)

def derive(tag: bytes) -> int:
	return int.from_bytes(hashlib.sha512(digest + tag).digest(), 'big') % curve_order or 1

def der_int(value: int) -> bytes:
	data = value.to_bytes(48, 'big').lstrip(b'\x00') or b'\x00'
	if data[0] & 0x80:
		data = b'\x00' + data
	return bytes((0x02, len(data))) + data

r = derive(b'R')
s = derive(b'S')
seq = der_int(r) + der_int(s)
der = bytes((0x30, len(seq))) + seq
print(base64.b64encode(der).decode('ascii'))
EOF
)

signing_end=$(date +%s.%N)
signing_duration=$(echo "$signing_end - $signing_start" | bc -l)

log "MOCK HSM: 'Signing' completed in ${signing_duration}s"
log "MOCK HSM: Generated fake DER ECDSA signature for testing"

# Create response
response=$(cat <<EOF
{
  "signature": "$signature_base64",
  "request_id": "$request_id",
  "hsm_info": {
    "hsm_id": "mock-hsm-digest-01",
    "signing_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "key_id": "mock-key-digest-12345",
    "signing_duration_ms": $(echo "$signing_duration * 1000" | bc -l),
    "hash_algorithm": "$hash_alg",
    "key_type": "$key_type",
    "note": "Mock HSM - fake signature for digest signing testing"
  },
  "error": ""
}
EOF
)

# Cleanup
rm -f /tmp/digest.bin

log "MOCK HSM: Digest signing request completed: $request_id"

# Output response (must be last thing to stdout)
echo "$response"
