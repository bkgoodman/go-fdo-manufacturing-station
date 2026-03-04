# FDOKeyAuth Push Authentication

This document describes the FDOKeyAuth authentication support for voucher push operations.

## Overview

FDOKeyAuth is a cryptographic challenge-response protocol that allows push clients to authenticate to push receivers using key-based authentication instead of static bearer tokens. This provides stronger security and better key management for voucher distribution.

## Configuration

### Basic Configuration

Add the following to your `voucher_management.push_service` configuration:

```yaml
voucher_management:
  push_service:
    enabled: true
    url: "http://receiver.example.com/vouchers"
    auth_method: "both"  # "static" | "fdokeyauth" | "both"
    supplier_key_type: "ec384"  # Key type for FDOKeyAuth
    supplier_key_file: ""  # Optional: PEM file with supplier key
    auth_token: ""  # Static token (fallback)
```

### Configuration Options

- **`auth_method`**: Authentication method selection
  - `"static"`: Use static bearer token only (legacy)
  - `"fdokeyauth"`: Use FDOKeyAuth only (fails if unavailable)
  - `"both"`: Try FDOKeyAuth first, fall back to static token (default)

- **`supplier_key_type`**: Key type for FDOKeyAuth (e.g., "ec384", "rsa2048")
  - Default: "ec384"
  - Used when loading manufacturer key from database

- **`supplier_key_file`**: Path to PEM-encoded supplier private key
  - If empty, uses manufacturer key from database
  - Supports RSA and ECDSA keys in PKCS#1, PKCS#8, or SEC1 format

- **`auth_token`**: Static bearer token for fallback authentication
  - Used if FDOKeyAuth fails or is disabled
  - Empty string disables static token fallback

## How It Works

### Authentication Flow

1. **FDOKeyAuth Enabled** (`auth_method` = "fdokeyauth" or "both"):
   - Client retrieves supplier key (from file or database)
   - Client performs FDOKeyAuth handshake with server
   - Server validates client's key and issues session token
   - Client uses session token for push operations

2. **Static Token Fallback** (when FDOKeyAuth fails or disabled):
   - Client uses configured static bearer token
   - No cryptographic authentication
   - Simpler but less secure

### Supplier Key Sources

The client automatically tries supplier keys in this order:

1. **Dedicated Supplier Key File** (`supplier_key_file`)
   - If configured and file exists, uses this key
   - Allows separate supplier identity from manufacturer

2. **Manufacturer Key from Database** (default)
   - If no supplier key file, uses manufacturer key
   - Requires active database session
   - Key type controlled by `supplier_key_type`

## Usage Examples

### Example 1: FDOKeyAuth with Manufacturer Key (Default)

```yaml
voucher_management:
  push_service:
    enabled: true
    url: "http://receiver.example.com/vouchers"
    auth_method: "both"
    supplier_key_type: "ec384"
    supplier_key_file: ""  # Use manufacturer key
```

### Example 2: FDOKeyAuth with Dedicated Supplier Key

```yaml
voucher_management:
  push_service:
    enabled: true
    url: "http://receiver.example.com/vouchers"
    auth_method: "fdokeyauth"
    supplier_key_type: "ec384"
    supplier_key_file: "/etc/fdo/supplier-key.pem"
```

### Example 3: Fallback to Static Token

```yaml
voucher_management:
  push_service:
    enabled: true
    url: "http://receiver.example.com/vouchers"
    auth_method: "both"
    supplier_key_type: "ec384"
    supplier_key_file: ""
    auth_token: "static-bearer-token-here"
```

## Server-Side Setup

To accept FDOKeyAuth push requests, configure the push receiver with FDOKeyAuth support:

```go
import "github.com/fido-device-onboard/go-fdo/transfer"

// Create FDOKeyAuth server for push endpoint
pushAuthServer := &transfer.FDOKeyAuthServer{
    ServerKey: serverPrivateKey,
    Sessions:  transfer.NewSessionStore(60*time.Second, 1000),
    LookupKey: func(callerKey protocol.PublicKey) (int, error) {
        // Verify caller key belongs to trusted supplier
        if isTrustedSupplier(callerKey) {
            return 0, nil
        }
        return -1, nil
    },
    IssueToken: func(callerKey protocol.PublicKey) (string, time.Time, error) {
        return generateSessionToken(callerKey)
    },
}

// Register on push endpoint
pushAuthServer.RegisterHandlers(mux, "/api/v1/vouchers")

// Also register push receiver
pushReceiver := &transfer.HTTPPushReceiver{
    Store: voucherStore,
    Authenticate: func(r *http.Request) bool {
        // Validate session token from FDOKeyAuth
        token := extractBearerToken(r)
        return isValidSessionToken(token)
    },
}
mux.Handle("POST /api/v1/vouchers", pushReceiver)
```

## Error Handling

### FDOKeyAuth Failures

If FDOKeyAuth authentication fails:

- **`auth_method: "fdokeyauth"`**: Push fails with error
- **`auth_method: "both"`**: Falls back to static token
- **`auth_method: "static"`**: Uses static token (FDOKeyAuth not attempted)

### Missing Supplier Key

If no supplier key is available:

- **With `supplier_key_file`**: Error if file not found or invalid
- **Without `supplier_key_file`**: Uses manufacturer key from database
- **No database session**: Falls back to static token (if available)

## Logging

The push client logs authentication decisions at DEBUG level:

```
time=... level=DEBUG msg="using FDOKeyAuth token for push" url=...
time=... level=DEBUG msg="using static bearer token for push" url=...
time=... level=DEBUG msg="FDOKeyAuth failed, falling back to static token" error=...
time=... level=DEBUG msg="FDOKeyAuth push authentication successful" token_length=...
```

## Security Considerations

### Key Management

- **Supplier Keys**: Should be stored securely (e.g., HSM, encrypted file)
- **Manufacturer Keys**: Automatically managed by database
- **Session Tokens**: Short-lived, issued per authentication

### Best Practices

1. Use FDOKeyAuth for production deployments
2. Keep supplier keys separate from manufacturer keys when possible
3. Implement proper key rotation policies
4. Monitor authentication logs for failures
5. Use HTTPS for all push operations
6. Validate server certificates in production

## Migration from Static Tokens

To migrate from static tokens to FDOKeyAuth:

1. **Phase 1**: Enable `auth_method: "both"` to support both methods
2. **Phase 2**: Configure supplier keys and test FDOKeyAuth
3. **Phase 3**: Monitor logs to confirm FDOKeyAuth is being used
4. **Phase 4**: Switch to `auth_method: "fdokeyauth"` when ready

## Troubleshooting

### FDOKeyAuth Fails with "supplier key not configured"

- Check `supplier_key_file` path is correct
- Verify database session is active
- Check `supplier_key_type` matches available keys

### Server Rejects Token

- Verify server has matching supplier key
- Check session token hasn't expired
- Ensure FDOKeyAuth endpoints are registered on server

### Static Token Fallback Not Working

- Verify `auth_token` is configured
- Check `auth_method` is not "fdokeyauth" only
- Ensure receiver accepts bearer tokens

## References

- [FDOKeyAuth Protocol](../go-fdo/transfer/README.md)
- [Voucher Push Configuration](../README.md)
- [FDO Specification](https://fidoalliance.org/fido-device-onboard/)
