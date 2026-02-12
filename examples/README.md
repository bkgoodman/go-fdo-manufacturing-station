# DID Integration Examples

This directory contains example DID documents and configurations for testing the DID integration feature.

## Files

### DID Documents
- `did_owner.json` - Owner DID with FDO extension and voucherRecipientURL
- `did_manufacturer.json` - Manufacturer DID with FDO extension
- `did_no_fdo.json` - DID without FDO extension (for testing)

### Configuration Files
- `config_did_file.yaml` - Configuration using `did:file:did_owner.json`
- `config_did_example.yaml` - Configuration using `did:web:example.com:owner`

## Usage

### Testing with did:file
The `did:file:` method is a custom test-only method that resolves DID documents from files in this directory.

Example DID URIs:
- `did:file:did_owner.json` → resolves to `examples/did_owner.json`
- `did:file:did_manufacturer.json` → resolves to `examples/did_manufacturer.json`
- `did:file:did_no_fdo.json` → resolves to `examples/did_no_fdo.json`

### Running Tests
```bash
# Run DID integration tests
./run_did_tests.sh

# Or run directly with go test
go test -v -run TestDIDIntegration
```

### Using Example Configuration
```bash
# Start manufacturing station with DID configuration
./go-fdo-manufacturing-station -config examples/config_did_file.yaml
```

## DID Document Structure

Each DID document follows this structure:
```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:localhost:8080:owner",
  "verificationMethod": [
    {
      "id": "#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:localhost:8080:owner",
      "publicKeyJwk": {
        "crv": "P-256",
        "kty": "EC",
        "x": "...",
        "y": "..."
      }
    }
  ],
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://example.com/vouchers/owner"
  }
}
```

## Test Scenarios

### ✅ Working Tests
1. **Mock did:key** - Generates test keys without multicodec parsing
2. **did:file resolution** - Reads DID documents from files
3. **FDO extension parsing** - Extracts voucherRecipientURL
4. **Error handling** - 404 errors, malformed DIDs

### 📋 TODO Tests
1. **Real did:key** - Actual multicodec parsing
2. **did:web HTTPS** - Real network resolution
3. **Caching behavior** - Cache hit/miss, TTL, refresh
4. **End-to-end voucher flow** - DID → voucher extension → upload
5. **Performance tests** - Cache performance under load

## Notes

- The `did:file:` method is test-only and always looks in the `examples/` directory
- JWK values in example documents are mock values for testing
- Real DID documents would contain actual public key coordinates
- The FDO extension is optional and contains voucher transmission URLs
