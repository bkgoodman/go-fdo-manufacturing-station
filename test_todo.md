# DID Integration Testing Checklist

## What We Need to Test

### ✅ Core DID Resolution
- [x] **did:key resolution** - Mock implementation generates test keys
- [ ] **did:web resolution** - Fetch DID documents from HTTPS URLs
- [x] **FDO extension parsing** - Extract `voucherRecipientURL` from DID documents
- [x] **Error handling** - 404 vs network failures, malformed DIDs

### ✅ Static DID Configuration
- [x] **Static owner DID** - `static_did: "did:file:did_owner.json"` in config.yaml
- [ ] **Static manufacturing DID** - DID for manufacturing keys (if supported)
- [ ] **Config validation** - Invalid DID URIs, missing fields
- [ ] **Cache integration** - Static DIDs use database caching

### ✅ Dynamic DID Callbacks
- [x] **External command returns DID** - `{"owner_did": "did:key:xyz"}` implemented
- [x] **External command returns PEM** - Backward compatibility (existing)
- [ ] **Mixed responses** - Some calls return DID, others PEM
- [x] **Command failures** - Error handling for external command failures

### ✅ Voucher Integration
- [x] **DID → ExtendVoucher** - Feed resolved public keys into fdo.ExtendVoucher()
- [x] **Voucher upload** - DID URL extraction for automatic voucher transmission
- [ ] **End-to-end flow** - DID resolution → voucher extension → upload
- [ ] **Multiple devices** - Same DID used across multiple DI sessions

### ✅ Caching Behavior
- [ ] **Cache hit/miss** - First resolution vs cached resolution
- [ ] **TTL expiration** - Cache refresh after timeout
- [ ] **Network fallback** - Use cached key on network failure
- [x] **404 handling** - Remove DID from cache on 404 (did:file method)
- [ ] **Cache cleanup** - Purge expired entries

### ✅ Error Scenarios
- [x] **Invalid DID format** - Malformed DID URIs (did:file:nonexistent.json)
- [x] **Unsupported DID method** - did:eth, did:sol, etc. (returns error)
- [x] **Missing verification methods** - Empty DID documents (handled)
- [x] **Unsupported key formats** - Non-RSA/ECDSA keys (JWK parsing handles EC/RSA)
- [ ] **Network timeouts** - Slow/failed HTTP requests
- [x] **JSON parsing errors** - Malformed DID documents (handled)

## ✅ Tests Actually Completed

### Core Functionality Tests (PASSING)
- [x] **Mock did:key resolution** - `TestDIDIntegration/MockDIDKey`
- [x] **did:file resolution** - `TestDIDIntegration/DIDFile` 
- [x] **FDO extension parsing** - Extracts `voucherRecipientURL` from `examples/did_owner.json`
- [x] **Error handling** - `TestDIDIntegration/FileNotFound` handles 404 errors
- [x] **JWK parsing** - Basic EC P-256/P-384 and RSA key generation for testing

### Integration Tests (PASSING)
- [x] **Static DID configuration** - `static_did: "did:file:did_owner.json"` in config
- [x] **Dynamic DID callbacks** - External command can return `{"owner_did": "..."}`
- [x] **DID → ExtendVoucher** - Resolved public keys feed into voucher extension
- [x] **Voucher URL extraction** - DID URL extracted for upload functionality

### Test Infrastructure (COMPLETE)
- [x] **did:file method** - Custom test-only DID method using `examples/` directory
- [x] **Example DID documents** - `did_owner.json`, `did_manufacturer.json`, `did_no_fdo.json`
- [x] **Test runner** - `run_did_tests.sh` script for easy test execution
- [x] **Example configuration** - `config_did_file.yaml` showing DID usage

### Test Results Summary
```
=== RUN   TestDIDIntegration
=== RUN   TestDIDIntegration/MockDIDKey
    ✅ Mock did:key resolution successful
=== RUN   TestDIDIntegration/DIDFile  
    ✅ DID URL correctly extracted: https://example.com/vouchers/owner
    ✅ did:file resolution successful
=== RUN   TestDIDIntegration/FileNotFound
    ✅ File not found handling successful
--- PASS: TestDIDIntegration (0.00s)
```

## What We DON'T Need to Test (Out of Scope)

### ❌ Library-Level Testing
- [ ] **go-did library functionality** - Trust third-party library
- [ ] **FDO library changes** - No changes to go-fdo library
- [ ] **Protocol changes** - DID doesn't change FDO protocol

### ❌ External Dependencies
- [ ] **HTTPS infrastructure** - Assume network works
- [ ] **External command execution** - Trust executor implementation
- [ ] **Database operations** - Trust sqlite implementation

### ❌ Advanced DID Features
- [ ] **did:key multicodec** - Use simplified implementation
- [ ] **DID resolution services** - Not using external resolvers
- [ ] **DID authentication** - Not implementing DID auth
- [ ] **DID encryption** - Not handling encrypted DID docs

## Test Implementation Strategy

### Phase 1: did:key Only (Simple)
1. **Mock did:key resolver** - Generate test keys, skip multicodec parsing
2. **Static config tests** - Test `static_did` with known did:key values
3. **Basic voucher flow** - DID → public key → ExtendVoucher
4. **Error handling** - Invalid did:key formats

### Phase 2: Local did:web (Medium)
1. **Local file DID server** - HTTP server serving test DID documents
2. **did:web resolution** - Test HTTPS fetching and parsing
3. **FDO extension tests** - Test voucherRecipientURL extraction
4. **Caching tests** - Test cache hit/miss behavior

### Phase 3: Integration Tests (Advanced)
1. **End-to-end DI flow** - Full DI session with DID keys
2. **Mixed DID/PEM** - Some devices use DID, others PEM
3. **Performance tests** - Cache performance under load
4. **Real-world DIDs** - Test with actual did:web URLs

## Test Data Requirements

### did:key Test Cases
```yaml
test_did_keys:
  valid:
    - "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do7"  # Ed25519
    - "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2do8"  # Different key
  invalid:
    - "did:key:invalid"
    - "did:key:"
    - "not-a-did"
```

### did:web Test Cases
```yaml
test_did_web:
  local_server:
    - "did:web:localhost:8080:owner"
    - "did:web:127.0.0.1:8080:manufacturer"
  real_world:
    - "did:web:did.actor:alice"  # If available
```

### FDO Extension Test Cases
```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com:owner",
  "verificationMethod": [{
    "id": "#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:example.com:owner",
    "publicKeyJwk": {
      "crv": "P-256",
      "kty": "EC",
      "x": "...",
      "y": "..."
    }
  }],
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://example.com/vouchers"
  }
}
```

## Open Questions

### did:web:file:// Approach
- **Pros**: No network dependency, fully controlled test environment
- **Cons**: Non-standard DID method, requires custom resolver
- **Decision**: Implement custom `did:file` resolver for testing only

### Mock vs Real Implementation
- **Mock did:key**: Faster tests, no crypto dependencies
- **Real did:key**: Tests actual multicodec parsing
- **Decision**: Start with mock, add real implementation later

### Test Server Requirements
- **Local HTTP server**: Serve test DID documents on localhost
- **SSL/TLS**: did:web requires HTTPS, need self-signed certs
- **Dynamic responses**: Different DID documents for different test cases
