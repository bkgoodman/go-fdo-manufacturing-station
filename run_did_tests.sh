#!/bin/bash

# Simple test runner for DID integration tests

echo "🧪 Running DID Integration Tests"
echo "================================"

# Change to the go-fdo-di directory
cd "$(dirname "$0")"

# Run the DID tests
echo "Running DID resolution tests..."
go test -v -run TestDIDIntegration

echo ""
echo "📋 Test Results:"
echo "- Mock did:key resolution: Tests mock implementation"
echo "- did:file resolution: Tests file-based DID documents"
echo "- Error handling: Tests 404 and malformed DIDs"

echo ""
echo "📁 Example DID Documents:"
echo "- examples/did_owner.json: Owner DID with FDO extension"
echo "- examples/did_manufacturer.json: Manufacturer DID with FDO extension"
echo "- examples/did_no_fdo.json: DID without FDO extension"

echo ""
echo "🔧 Usage Examples:"
echo "did:file:did_owner.json -> resolves to examples/did_owner.json"
echo "did:key:test-12345 -> resolves to mock generated key"
