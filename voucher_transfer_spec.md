# FDO Voucher Transfer Protocol Specification

This document defines the standard protocol for transferring FDO (FIDO Device Onboarding) vouchers between manufacturing systems and owner systems via HTTP.

## Problem Statement and Scope

### The Challenge
FDO vouchers need to be securely transferred from manufacturing systems (where devices are provisioned) to owner systems (where devices will be onboarded). Today, this transfer is handled through proprietary, implementation-specific mechanisms that create:

- **Integration Complexity**: Each manufacturer-owner pair requires custom integration work
- **Security Inconsistencies**: Varying security models across implementations
- **Scalability Issues**: No standard approach for high-volume or complex deployments
- **Operational Overhead**: Lack of common monitoring, error handling, and debugging approaches

### Use Cases and Requirements

#### Real-World Deployment Scenarios

**Cloud Service Push Model**
- **Scenario**: Manufacturer devices are purchased and immediately need to send vouchers to cloud-based owner services
- **Requirements**: Real-time delivery, high availability, global accessibility
- **Challenges**: Network connectivity, service availability, security at scale

**On-Premises Pull Model**
- **Scenario**: Owner systems are in isolated networks (air-gapped, local data centers) without inbound internet access
- **Requirements**: Secure outbound connections, batch processing, offline operation support
- **Challenges**: Network restrictions, manual data transfer, synchronization

**Batch Transfer Requirements**
- **Push Batching**: Manufacturing sites may go offline; need to queue vouchers and batch upload when connectivity restored
- **Pull Batching**: Owner systems may need to retrieve large volumes of vouchers efficiently during maintenance windows
- **Requirements**: Efficient batching, resume capabilities, progress tracking

**Reconciliation and Recovery**
- **Scenario**: System failures, data corruption, or disaster recovery requiring voucher re-synchronization
- **Requirements**: Pull-based recovery, duplicate detection, audit trail maintenance
- **Use Case**: "Give me all vouchers since last checkpoint" for system restoration

**Pagination Requirements**
- **Pull Pagination**: Essential for large datasets - "return first 100 vouchers, then next 100"
- **Push Pagination**: Less common but needed for bulk uploads or rate-limited environments
- **Requirements**: Opaque continuation tokens, efficient state management, timeout handling

#### Security and Operational Implications

**Security Cannot Be Optional**
- **Problem**: We cannot open voucher endpoints to the internet without authentication and authorization
- **Risk**: Unauthorized voucher submission, DDoS attacks, data harvesting, manufacturer impersonation
- **Requirement**: All voucher transfers must be authenticated and authorized regardless of push/pull model

**Voucher-Only Security is Insufficient**
- **Problem**: Relying solely on voucher signature validation puts heavy computational burden on recipients
- **DDoS Risk**: Attackers can flood systems with invalid vouchers, forcing expensive cryptographic operations
- **Resource Impact**: High CPU/memory usage, processing bottlenecks, late rejection of invalid requests

**WAF and Edge Security Integration**
- **Requirement**: Security credentials should be usable by Web Application Firewalls and edge security systems
- **Benefits**: Early rejection of invalid requests, DDoS protection, reduced load on application servers
- **Implementation**: Tokens and credentials that can be validated at network edge

#### Security Approaches

**Explicit Permission Models**
- **Token-Based Authorization**: JWT tokens with scopes, quotas, time limits, device restrictions
- **Certificate-Based Authentication**: mTLS with manufacturer certificates, CAs, short-lived certs
- **API Keys**: Simple bearer tokens for basic scenarios
- **Purchase-Tied Permissions**: Tokens generated during purchase process, tied to orders/customers

**Implicit Trust Models**
- **Voucher Signature Validation**: Cryptographic verification of manufacturer signatures
- **Shared Key Systems**: Using same keys that sign vouchers for authentication
- **DID-Based Trust**: Resolving manufacturer identities through DID documents
- **Reputation Systems**: Trust based on historical manufacturer behavior

**Hybrid Security Strategies**
- **Layered Defense**: Multiple security mechanisms (token + signature + business validation)
- **Risk-Based Authentication**: Different security levels based on voucher value, manufacturer reputation
- **Adaptive Security**: Dynamic security requirements based on threat intelligence

### Protocol Goals
This specification establishes a standardized method for secure voucher transfer that addresses:

1. **Interoperability**: Common API that any FDO-compliant system can implement
2. **Security**: Multiple security models supporting different trust and risk requirements
3. **Flexibility**: Support for both push (manufacturer-initiated) and pull (owner-initiated) transfer models
4. **Scalability**: Approaches for high-volume deployments with proper DDoS protection
5. **Operational Excellence**: Standardized monitoring, error handling, and troubleshooting

### Transfer Models

#### Push Model (Manufacturer-Initiated)
**When to Use**: Real-time voucher delivery as soon as devices are manufactured

**Flow**:
1. Manufacturing system generates voucher during device provisioning
2. Manufacturing system immediately transfers voucher to owner system
3. Owner system validates and processes the voucher
4. Device can be onboarded immediately upon receipt

**Benefits**:
- Minimal latency - vouchers available immediately
- Simple manufacturer workflow
- Real-time status of device provisioning

**Challenges**:
- Owner system must be always available to receive vouchers
- Security considerations for accepting unsolicited voucher submissions
- Potential DDoS exposure on owner infrastructure

#### Pull Model (Owner-Initiated)
**When to Use**: Batch processing, compliance requirements, or when owner controls timing

**Flow**:
1. Manufacturing system generates and stores vouchers
2. Owner system polls or subscribes to voucher availability
3. Owner system retrieves vouchers when ready to process
4. Owner system controls processing timing and throughput

**Benefits**:
- Owner controls processing timing and resources
- Better for batch processing and compliance workflows
- Reduced DDoS exposure on owner systems
- Supports reconciliation and audit requirements

**Challenges**:
- Increased latency in device availability
- More complex polling/subscription infrastructure
- Storage requirements on manufacturing side

#### Hybrid Approaches
**When to Use**: Combining benefits of both models

**Examples**:
- **Push with Pull Fallback**: Primary push delivery with pull capability for missed vouchers
- **Pull with Notifications**: Pull model with webhook notifications when vouchers are ready
- **Conditional Transfer**: Push for high-priority devices, pull for bulk processing

## Overview

The FDO Voucher Transfer Protocol defines standardized HTTP APIs, message formats, security requirements, and operational procedures for both push and pull voucher transfer models. The protocol is designed to support:

- **Multiple Security Models**: From simple token-based auth to zero-trust voucher validation
- **Flexible Deployment**: Cloud, on-premises, and hybrid environments
- **Scalable Operations**: High-volume transfers with proper rate limiting and monitoring
- **Business Integration**: Purchase process integration and order-based validation
- **Compliance Support**: Audit trails, data retention, and geographic restrictions

## Protocol Definition

### HTTP API Specification

#### POST /api/vouchers

**Purpose**: Submit a new voucher to the recipient system

**Content-Type**: `multipart/form-data`

**Request Parameters**:

- `voucher` (file, required): The `.fdoov` voucher file
- `serial` (string, optional): Device serial number for routing/validation
- `model` (string, optional): Device model identifier
- `manufacturer` (string, optional): Manufacturing system identifier
- `timestamp` (string, optional): Voucher generation timestamp (ISO 8601)

**Request Headers**:

- `Content-Type`: `multipart/form-data; boundary=...`
- `X-FDO-Version`: FDO protocol version (e.g., "1.0")
- `X-FDO-Client-ID`: Client identifier for tracking
- `Authorization`: Bearer token or API key (optional, for authentication)

**Response Codes**:

- `200 OK`: Voucher accepted and processed
- `202 Accepted`: Voucher accepted for async processing
- `400 Bad Request`: Invalid voucher format or missing required data
- `401 Unauthorized`: Authentication required/failed
- `403 Forbidden`: Not authorized to submit vouchers
- `409 Conflict`: Duplicate voucher for same device
- `413 Payload Too Large`: Voucher file exceeds size limits
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server processing error
- `503 Service Unavailable`: Temporarily unable to process

**Response Format**:

```json
{
  "status": "accepted|processed|error|pending",
  "voucher_id": "uuid-string",
  "message": "Human-readable status message",
  "timestamp": "2024-01-01T12:00:00Z",
  "details": {
    "device_serial": "ABC123",
    "processing_time_ms": 150,
    "retry_after_seconds": 60
  }
}
```

#### Alternative: PUT /api/vouchers/{serial}

**Purpose**: Submit or update voucher for specific device

**Content-Type**: `application/octet-stream` (raw voucher file)

**URL Parameters**:

- `serial` (string, required): Device serial number

**Request Headers**:

- `Content-Type`: `application/octet-stream`
- `X-FDO-Version`: FDO protocol version
- `X-FDO-Model`: Device model identifier
- `X-FDO-Manufacturer`: Manufacturing system identifier
- `X-FDO-Timestamp`: Voucher generation timestamp
- `Authorization`: Authentication header

**Response**: Same format as POST endpoint

#### GET /api/vouchers/{serial}/status

**Purpose**: Check processing status of submitted voucher

**Response Format**:

```json
{
  "voucher_id": "uuid-string",
  "status": "pending|processing|completed|failed",
  "submitted_at": "2024-01-01T12:00:00Z",
  "processed_at": "2024-01-01T12:01:30Z",
  "error_message": null,
  "retry_count": 0
}
```

## Message Formats

### Voucher File Format

#### File Extension: `.fdoov`

The voucher file is a binary-encoded FDO voucher following the FDO specification format. The file contains:

1. **Device Information**: Serial number, model, GUID
2. **Manufacturer Signature**: Cryptographic signature of device data
3. **Owner Public Key**: Recipient's public key for encryption
4. **Device Attestation**: Device-specific attestation data
5. **Timestamps**: Generation and expiration timestamps
6. **Metadata**: Additional device and manufacturing metadata

#### MIME Type

**Standard**: `application/x-fdo-voucher`

**Alternative**: `application/octet-stream` (generic binary)

#### File Size Limits

- **Maximum size**: 10 MB per voucher
- **Recommended size**: < 1 MB for optimal performance
- **Compression**: Vouchers may be compressed using gzip

### DID Integration with Security Requirements

#### DID Document Security Extensions

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "verificationMethod": [...],
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://owner.example.com/api/vouchers",
    "supportedFormats": ["application/x-fdo-voucher"],
    "authentication": ["bearer", "mtls"],
    "maxVoucherSize": "10MB",
    "rateLimitPerMinute": 60,
    "securityRequirements": {
      "required": ["signature", "token"],
      "optional": ["business_validation"],
      "token_endpoint": "https://owner.example.com/api/tokens",
      "trusted_manufacturers": ["did:web:mfg1.com", "did:web:mfg2.com"]
    }
  }
}
```

#### Purchase Process Integration

**Token Generation During Purchase**:
1. Customer purchases devices through ordering system
2. Ordering system generates manufacturer-specific JWT tokens
3. Tokens include purchase order details, device counts, expiration
4. Tokens provided to manufacturer along with DID information
5. Manufacturer uses tokens for voucher submission

**Purchase-Tied Token Format**:
```json
{
  "iss": "https://ordering.example.com",
  "sub": "manufacturer-123",
  "aud": "https://owner.example.com/api/vouchers",
  "exp": 1640995200,
  "iat": 1640908800,
  "purchase_order": "PO-12345",
  "customer_id": "cust-abc123",
  "device_counts": {
    "model-a": 100,
    "model-b": 50
  },
  "allowed_serial_prefix": ["ABC", "DEF"],
  "manufacturer_id": "mfg-abc123"
}
```

### Voucher Sequestering

#### Overview
Voucher sequestering holds submitted vouchers in quarantine until additional validation or manual approval is completed.

#### Sequestering Process
1. **Quarantine Reception**: Voucher accepted but held in quarantine
2. **Additional Validation**: Business logic, order verification, manual review
3. **Approval Process**: Automatic or manual approval based on risk rules
4. **Release or Reject**: Approved vouchers released to processing, rejected vouchers deleted

#### Sequestering Configuration
```yaml
sequestering:
  enabled: true
  quarantine_duration: "24h"
  auto_approval_rules:
    - trusted_manufacturer: true
    - order_verified: true
    - device_count_under: 100
  manual_review_triggers:
    - first_time_manufacturer: true
    - high_value_order: true
    - unusual_device_pattern: true
    - geographic_anomaly: true
```

#### Risk-Based Sequestering
| Risk Level | Auto-Approval | Manual Review | Quarantine Time |
|------------|---------------|---------------|----------------|
| **Low** | Yes | No | 1 hour |
| **Medium** | Conditional | Yes | 4 hours |
| **High** | No | Required | 24 hours |
| **Critical** | No | Executive | 72 hours |

## DID Integration

### DID-Enhanced Transfer

When using DID-based recipient identification, the transfer process includes:

1. **DID Resolution**: Issuer resolves recipient's DID URI
2. **URL Extraction**: Extract `voucherRecipientURL` from DID document
3. **Direct Upload**: POST voucher directly to extracted URL
4. **Fallback**: Use alternative endpoint if DID URL unavailable

### DID Document Extension

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "verificationMethod": [...],
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://owner.example.com/api/vouchers",
    "supportedFormats": ["application/x-fdo-voucher"],
    "authentication": ["bearer", "mtls"],
    "maxVoucherSize": "10MB",
    "rateLimitPerMinute": 60
  }
}
```

## Transfer Protocol Comparison

### Callback-Based Approach
**Pros**:
- Maximum flexibility for owner systems
- Supports any protocol or authentication method
- Easy integration with existing systems

**Cons**:
- Owner must implement and host callback endpoint
- No standardization across implementations
- Limited error feedback to manufacturing station

### First-Class HTTP Service
**Pros**:
- Standardized protocol and error handling
- Built-in retry and monitoring capabilities
- Clear contract between manufacturing and owner
- Better observability and debugging

**Cons**:
- Less flexibility for custom integrations
- Requires owner to implement specific endpoint
- Additional implementation complexity

## Security Framework

### Threat Model Analysis

**Primary Threats**:
- **Unauthorized Voucher Submission**: Malicious actors sending fraudulent vouchers
- **Voucher Injection**: Attackers submitting vouchers for devices they don't own
- **Denial of Service**: Overwhelming recipient systems with invalid vouchers
- **Data Harvesting**: Using voucher endpoints to discover device information
- **Manufacturer Impersonation**: Fake manufacturers submitting counterfeit vouchers

### Security Models

#### Model 1: Token-Based Authorization

**Overview**: Recipient issues scoped tokens to authorized manufacturers

**DDoS Advantages**:
- **Fast Rejection**: Token validation at edge/WAF before reaching application
- **Third-Party WAF Support**: Tokens can be validated by CDN/WAF providers
- **Rate Limiting**: Token-based rate limiting per manufacturer
- **Resource Efficiency**: Minimal processing for invalid requests

**Token Types**:
- **One-Time Use Tokens**: Single voucher submission, auto-expire after use
- **Time-Limited Tokens**: Valid for specified duration (e.g., 24 hours, 30 days)
- **Quota-Limited Tokens**: Maximum number of vouchers allowed
- **Device-Specific Tokens**: Valid only for specific device serial numbers/models
- **Manufacturer-Specific Tokens**: Tied to specific manufacturer identifier
- **Purchase-Tied Tokens**: Generated during purchase process, tied to order/customer

**Token Format** (JWT recommended):
```json
{
  "iss": "https://recipient.example.com",
  "sub": "manufacturer-123",
  "aud": "https://recipient.example.com/api/vouchers",
  "exp": 1640995200,
  "iat": 1640908800,
  "scope": "voucher:submit",
  "limits": {
    "max_vouchers": 100,
    "allowed_models": ["model-a", "model-b"],
    "allowed_serials": ["prefix-*"],
    "device_specific": false
  },
  "manufacturer_id": "mfg-abc123"
}
```

**Validation Process**:
1. Client includes `Authorization: Bearer <token>` header
2. Server validates JWT signature and claims
3. Server enforces token limits and scope
4. Token is marked as used (for one-time tokens) or quota decremented

#### Model 2: Manufacturer Key Enrollment (mTLS)

**Overview**: Recipient enrolls manufacturer certificates for mutual TLS authentication

**DDoS Considerations**:
- **Medium Resource Usage**: TLS handshake requires CPU but less than voucher parsing
- **Connection Filtering**: Invalid certificates rejected at TLS layer
- **Rate Limiting**: Connection-based rate limiting possible
- **WAF Limitations**: mTLS validation typically requires termination at application

**JWT vs mTLS Credentials**:

| Aspect | JWT Tokens | mTLS Certificates |
|--------|------------|-------------------|
| **Validation Speed** | Very Fast (signature verification) | Medium (TLS handshake) |
| **WAF Support** | Excellent (can validate at edge) | Limited (requires TLS termination) |
| **Revocation** | Immediate (token blacklist) | Delayed (CRL/OCSP) |
| **Scope Flexibility** | High (claims-based) | Low (certificate-based) |
| **Key Rotation** | Easy (new tokens) | Complex (certificate reissuance) |
| **Third-Party Integration** | Excellent | Poor |

**Enrollment Process**:
1. Manufacturer provides public key or CA certificate to recipient
2. Recipient adds certificate to trusted manufacturer store
3. Manufacturer configures client with corresponding private key
4. All voucher submissions require mTLS handshake

**Certificate Types**:
- **Individual Manufacturer Cert**: Direct certificate for specific manufacturer
- **Manufacturer CA Cert**: Root CA that can issue manufacturer certificates
- **Short-Lived Certs**: Certificates with short validity (hours/days)
- **Device-Specific Certs**: Certificates tied to specific device batches

**Configuration Example**:
```yaml
trusted_manufacturers:
  - id: "mfg-abc123"
    name: "Acme Manufacturing"
    certificate: |
      -----BEGIN CERTIFICATE-----
      MIICljCCAX4CCQCK...
      -----END CERTIFICATE-----
    ca_chain: false
    allowed_models: ["*"]
    cert_fingerprint: "SHA256:abcd1234..."
  - id: "mfg-def456"  
    name: "Beta Corp"
    ca_certificate: |
      -----BEGIN CERTIFICATE-----
      MIICljCCAX4CCQCK...
      -----END CERTIFICATE-----
    ca_chain: true
    allowed_models: ["model-x", "model-y"]
```

#### Model 3: Voucher Signature Validation

**Overview**: Recipient validates voucher signatures against trusted manufacturer keys

**DDoS Implications**:
- **High Resource Usage**: Requires voucher parsing and cryptographic verification
- **Processing Bottleneck**: Must parse entire voucher before rejection
- **Memory Pressure**: Large voucher files consume memory
- **CPU Intensive**: Signature verification is computationally expensive
- **Late Rejection**: Invalid vouchers only rejected after full processing

**Use Cases**:
- **Zero-Trust Environments**: No prior relationship with manufacturer
- **High-Security**: Cryptographic verification required
- **Audit Requirements**: Need to verify voucher authenticity
- **Fallback**: When tokens/certificates unavailable

**Signature Validation Process**:
1. Extract manufacturer signature from voucher
2. Lookup manufacturer public key from trusted store
3. Verify cryptographic signature of voucher data
4. Reject vouchers with invalid or untrusted signatures

**Key Management**:
- **Static Key List**: Pre-configured manufacturer public keys
- **Dynamic Key Resolution**: Fetch keys from manufacturer DID documents
- **Key Rotation**: Support for key rollover and multiple active keys
- **Key Revocation**: Mechanism to revoke compromised keys

**Validation Flow**:
```yaml
signature_validation:
  required: true
  trusted_keys:
    - manufacturer_id: "mfg-abc123"
      public_key: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhki...
        -----END PUBLIC KEY-----
      valid_from: "2024-01-01T00:00:00Z"
      valid_until: "2025-01-01T00:00:00Z"
    - manufacturer_id: "mfg-def456"
      did_url: "did:web:manufacturer.com:keys"
      cache_ttl: "1h"
  
  reject_unsigned: true
  allow_key_rotation: true
  revocation_check: true
```

#### Model 4: Business Logic Validation

**Overview**: Application-level validation based on business rules and order data

**DDoS Impact**:
- **Very High Resource Usage**: Database lookups, API calls, complex validation
- **External Dependencies**: Relies on CRM, order systems, device registries
- **Processing Time**: Can take seconds per voucher
- **Cascading Failures**: External service issues affect voucher processing

**Use Cases**:
- **Purchase Integration**: Validate against purchase orders
- **Customer Verification**: Ensure vouchers for registered customers
- **Device Registration**: Pre-registered device validation
- **Compliance**: Regulatory and business rule enforcement

**Validation Types**:
- **Order Number Validation**: Voucher must reference valid purchase order
- **Device Registration**: Device must be pre-registered in recipient system
- **Customer Validation**: Voucher must be for registered customer
- **Geographic Restrictions**: Device location/shipping validation
- **Quantity Limits**: Enforce order quantities and limits

**Integration Points**:
```yaml
business_validation:
  order_validation:
    enabled: true
    service_url: "https://internal.example.com/orders/validate"
    required_fields: ["order_number", "customer_id"]
    
  device_registration:
    enabled: true
    database: "device_registry"
    check_fields: ["serial", "model", "customer_id"]
    
  customer_validation:
    enabled: true
    crm_service: "https://crm.example.com/api/customers"
    required_status: "active"
```

### Composite Security Models

#### Recommended: Defense-in-Depth Approach

**Layer 1: Transport Security** (Required)
- HTTPS with TLS 1.2+
- Certificate validation
- HSTS headers

**Layer 2: Authentication** (Choose one or more)
- Token-based authorization (Model 1)
- mTLS with manufacturer certificates (Model 2)

**Layer 3: Voucher Integrity** (Required)
- Signature validation (Model 3)
- Manufacturer key verification

**Layer 4: Business Logic** (Optional but recommended)
- Order validation (Model 4)
- Device registration checks

#### Security Matrix

| Security Level | Authentication | Signature | Business Logic | DDoS Resistance | Resource Usage | Use Case |
|---------------|----------------|-----------|----------------|----------------|---------------|----------|
| **Basic** | None | Required | Optional | Low | High | Testing/Development |
| **Token-Only** | JWT Token | Optional | Optional | High | Low | High-volume deployments |
| **Standard** | Token or mTLS | Required | Recommended | Medium | Medium | Production deployments |
| **High** | Token + mTLS | Required | Required | High | Medium | High-value deployments |
| **Maximum** | Token + mTLS | Required + Key Rotation | Required + Audit | Very High | High | Critical infrastructure |
| **Voucher-Based** | None | Required + Deep Validation | Required + Sequestering | Low | Very High | Zero-trust environments |

### Security Implementation Examples

#### Token-Only Configuration
```yaml
security:
  authentication:
    type: "token"
    jwt_validation:
      issuer: "https://recipient.example.com"
      audience: "https://recipient.example.com/api/vouchers"
      public_key_url: "https://recipient.example.com/.well-known/jwks.json"
  
  signature_validation:
    required: true
    trusted_manufacturers: ["mfg-abc123", "mfg-def456"]
```

#### mTLS + Signature Configuration
```yaml
security:
  authentication:
    type: "mtls"
    trusted_certificates:
      - manufacturer_id: "mfg-abc123"
        certificate_file: "/certs/mfg-abc123.pem"
        ca_chain: false
  
  signature_validation:
    required: true
    trusted_manufacturers: ["mfg-abc123", "mfg-def456"]
    
  business_validation:
    order_validation: true
    device_registration: true
```

#### Full Defense-in-Depth
```yaml
security:
  authentication:
    - type: "token"
      jwt_validation: {...}
    - type: "mtls" 
      trusted_certificates: {...}
  
  signature_validation:
    required: true
    key_rotation: true
    revocation_check: true
    
  business_validation:
    order_validation: true
    device_registration: true
    customer_validation: true
    geographic_validation: true
    
  rate_limiting:
    per_manufacturer: "100/hour"
    per_ip: "1000/hour"
    burst_limit: 10
```

### Security Headers and Response Data

#### Security Headers
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

#### Error Response Security
```json
{
  "error": "authentication_failed",
  "message": "Invalid or expired token",
  "error_code": "AUTH_001",
  "timestamp": "2024-01-01T12:00:00Z",
  "request_id": "req-abc123"
  // Note: Don't reveal internal details or system information
}
```

### Security Monitoring and Alerting

#### Security Events to Monitor
- Authentication failures by manufacturer
- Invalid signature attempts
- Token usage anomalies
- Unusual geographic patterns
- Rate limit violations
- Certificate expiration warnings

#### Alert Thresholds
- >10 authentication failures/hour per manufacturer
- >5 invalid signature attempts/hour
- Token usage >90% of quota
- Certificate expiring in <30 days
- Unrecognized IP addresses

## Protocol Requirements

### Security Requirements

#### Authentication Methods

1. **API Key/Bearer Token**: Simple token-based auth
2. **mTLS**: Mutual TLS for certificate-based auth
3. **JWT**: Signed tokens with claims
4. **HMAC**: Request signing with shared secret
5. **OAuth 2.0**: Standard authorization framework

#### Transport Security

- **HTTPS Required**: All voucher transfers must use TLS 1.2+
- **Certificate Validation**: Proper certificate chain validation
- **Certificate Pinning**: Optional for high-security deployments
- **HSTS**: HTTP Strict Transport Security enabled

#### Voucher Integrity

- **Cryptographic Signature**: Vouchers are signed by issuer
- **Tamper Detection**: Any modification invalidates signature
- **Replay Protection**: Timestamps and nonces in voucher data
- **Checksum Verification**: Optional file integrity verification

## Operational Procedures

### Error Handling and Retry Logic

#### Retry Strategy

1. **Exponential Backoff**: 1s, 2s, 4s, 8s, 16s, 32s
2. **Maximum Attempts**: 5 retries by default (configurable)
3. **Jitter**: Random delay ±25% to prevent thundering herd
4. **Dead Letter Queue**: Failed transfers stored for manual review
5. **Circuit Breaker**: Temporarily stop sending to failing endpoints

#### Error Categories

1. **Transient Errors**: Retry recommended
   - Network timeouts
   - HTTP 5xx server errors
   - Rate limiting (429) with Retry-After header
   - Temporary service unavailability (503)

2. **Permanent Errors**: No retry
   - HTTP 4xx client errors (except 429)
   - Invalid voucher format (400)
   - Authentication failures (401/403)
   - Duplicate vouchers (409)

3. **Configuration Errors**: Manual intervention required
   - Invalid recipient URLs
   - Missing authentication credentials
   - DID resolution failures
   - Certificate validation errors

### Monitoring and Observability

#### Metrics to Track

1. **Transfer Success Rate**: Percentage of successful voucher uploads
2. **Transfer Latency**: Time from voucher generation to recipient acceptance
3. **Retry Count**: Number of retries per transfer
4. **Error Rates**: Breakdown by error type
5. **Queue Depth**: Number of pending transfers
6. **Throughput**: Vouchers processed per minute/hour
7. **Endpoint Health**: Availability and response times

#### Logging Requirements

1. **Transfer Events**: Start, success, failure, retry
2. **Error Details**: Full error messages and stack traces
3. **Performance Metrics**: Transfer times and sizes
4. **Security Events**: Authentication failures, suspicious activity
5. **Audit Trail**: Complete transfer history for compliance

#### Alerting

- Success rate drops below 95%
- Transfer latency exceeds 5 minutes
- Error rate exceeds 5%
- Authentication failure rate exceeds 1%
- Queue depth exceeds 1000 vouchers

## Implementation Guidelines

### Client Implementation Requirements

#### HTTP Client Configuration

```yaml
voucher_transfer:
  endpoint: "https://recipient.example.com/api/vouchers"
  auth_method: "bearer"
  auth_token: "${API_TOKEN}"
  timeout: "30s"
  retry_attempts: 5
  retry_backoff: "exponential"
  max_voucher_size: "10MB"
  user_agent: "FDO-Transfer-Client/1.0"
```

#### DID Support

```yaml
did_resolution:
  enabled: true
  cache_ttl: "1h"
  timeout: "10s"
  fallback_endpoint: "https://default-recipient.example.com/api/vouchers"
```

### Server Implementation Requirements

#### API Endpoint Configuration

```yaml
voucher_api:
  base_path: "/api/vouchers"
  max_file_size: "10MB"
  rate_limit: "60/minute"
  supported_auth: ["bearer", "mtls", "jwt"]
  processing_timeout: "5m"
  async_processing: true
```

#### Storage and Processing

```yaml
voucher_storage:
  type: "s3" | "local" | "database"
  retention_period: "30d"
  encryption: "aes256"
  backup_enabled: true

processing:
  workers: 10
  queue_size: 1000
  dead_letter_queue: "failed_vouchers"
```

## Voucher Retrieval (Pull Model)

### Overview
While push-based voucher transfer is the primary model, some use cases require recipients to pull vouchers from manufacturers or centralized voucher repositories.

### Pull API Specification

#### GET /api/vouchers

**Purpose**: Retrieve vouchers for a specific customer or manufacturer

**Query Parameters**:
- `customer_id` (string, required): Customer identifier
- `manufacturer_id` (string, optional): Filter by manufacturer
- `since` (timestamp, optional): Get vouchers since this time (ISO 8601)
- `until` (timestamp, optional): Get vouchers until this time
- `status` (string, optional): Filter by status (pending, processed, all)
- `limit` (integer, optional): Maximum vouchers to return (default: 100)
- `continuation` (string, optional): Opaque continuation token for pagination

**Authentication**: Same security models as push (token, mTLS, etc.)

**Response Format**:
```json
{
  "vouchers": [
    {
      "voucher_id": "uuid-1",
      "serial": "ABC123",
      "model": "model-a",
      "manufacturer_id": "mfg-abc123",
      "status": "pending",
      "created_at": "2024-01-01T12:00:00Z",
      "download_url": "https://mfg.example.com/api/vouchers/uuid-1/download",
      "size_bytes": 1024,
      "checksum": "sha256:abcd1234..."
    }
  ],
  "continuation": "opaque-token-123",
  "has_more": true,
  "total_count": 1500
}
```

#### GET /api/vouchers/{voucher_id}/download

**Purpose**: Download the actual voucher file

**Response**: Raw `.fdoov` file with appropriate headers:
```http
Content-Type: application/x-fdo-voucher
Content-Disposition: attachment; filename="ABC123.fdoov"
Content-Length: 1024
X-FDO-Voucher-ID: uuid-1
X-FDO-Checksum: sha256:abcd1234...
```

### Pagination Strategies

#### Continuation Token Pagination
**Recommended for large datasets**

- **Opaque Tokens**: Server-generated, client passes back unchanged
- **Stateless**: No server-side session state required
- **Efficient**: Can skip to any point in dataset
- **Expiry**: Tokens can expire for security

**Continuation Token Format** (server implementation detail):
```json
{
  "position": "timestamp:serial",
  "checksum": "verify-integrity",
  "expires": "2024-01-01T13:00:00Z",
  "customer_filter": "cust-123"
}
```

#### Offset-Based Pagination
**Simple but limited**

- **Query Parameters**: `offset=0&limit=100`
- **Limitations**: Inefficient for large datasets, data consistency issues
- **Use Case**: Small datasets, simple implementations

#### Cursor-Based Pagination
**Balance of complexity and functionality**

- **Cursor**: Based on timestamp or voucher ID
- **Efficiency**: Better than offset for large datasets
- **Consistency**: Handles new data during pagination

### Long-Polling and Streaming

#### Long-Polling Endpoint
**GET /api/vouchers/subscribe**

**Query Parameters**:
- `customer_id` (string, required)
- `timeout` (integer, optional): Max wait time (default: 30 seconds)
- `since` (timestamp, optional): Only return vouchers since this time

**Response**: Returns immediately if vouchers available, waits up to timeout if none

#### Server-Sent Events
**GET /api/vouchers/stream**

**Response**: SSE stream of voucher availability notifications
```http
Content-Type: text/event-stream
Cache-Control: no-cache

retry: 5000
event: voucher_available
data: {"voucher_id": "uuid-1", "serial": "ABC123"}

event: voucher_available
data: {"voucher_id": "uuid-2", "serial": "DEF456"}
```

### Pull Model Security Considerations

#### Authentication and Authorization
- **Same Security Models**: Token, mTLS, signature validation
- **Customer Scoping**: Only return vouchers for authenticated customer
- **Rate Limiting**: Prevent excessive polling
- **Data Minimization**: Only return necessary metadata

#### Data Privacy and Compliance
- **Access Logging**: Log all voucher access attempts
- **Data Retention**: Clear policies for voucher storage
- **Audit Trail**: Complete history of voucher downloads
- **Geographic Restrictions**: Comply with data residency requirements

#### Performance and Scalability
- **Caching**: Cache voucher metadata, not files
- **CDN Integration**: Use CDN for voucher file downloads
- **Database Optimization**: Efficient queries for large datasets
- **Bandwidth Management**: Throttle large downloads

### Pull vs Push Comparison

| Aspect | Push Model | Pull Model |
|--------|------------|------------|
| **Initiation** | Manufacturer pushes | Recipient pulls |
| **Latency** | Immediate | Polling interval |
| **Resource Usage** | High on recipient | High on manufacturer |
| **Complexity** | Simple retry logic | Pagination, polling |
| **Firewall Issues** | Outbound from mfg | Inbound to recipient |
| **Audit Trail** | Automatic | Requires logging |
| **Scalability** | Recipient-limited | Manufacturer-limited |
| **Use Cases** | Real-time delivery | Batch processing, compliance |

### Hybrid Approaches

#### Push with Pull Fallback
1. **Primary Push**: Manufacturer pushes vouchers immediately
2. **Pull Fallback**: Recipient can pull missed vouchers
3. **Reconciliation**: Periodic sync to ensure completeness

#### Pull with Push Notifications
1. **Webhook Notification**: Manufacturer notifies of voucher availability
2. **Pull Download**: Recipient pulls voucher when ready
3. **Queue Management**: Recipient controls processing timing

## Protocol Evolution

### Versioning Strategy

- **Semantic Versioning**: MAJOR.MINOR.PATCH format
- **Backward Compatibility**: Minor versions maintain compatibility
- **Deprecation Policy**: 12-month deprecation notice for major changes
- **Feature Flags**: Optional features can be enabled/disabled

### Future Enhancements

1. **Batch Transfer**: Submit multiple vouchers in single request
2. **Streaming Transfer**: Large voucher file streaming
3. **WebSocket Support**: Real-time transfer status updates
4. **GraphQL API**: Alternative query interface
5. **Event-Driven Architecture**: Message queue integration

## Compliance and Standards

### Regulatory Requirements

- **Data Protection**: GDPR/CCPA compliance for personal data
- **Audit Requirements**: Complete audit trail for all transfers
- **Data Retention**: Configurable retention policies
- **Export Controls**: Compliance with export regulations

### Industry Standards

- **FDO Specification**: Alignment with FIDO Device Onboarding standard
- **HTTP Standards**: RFC 7230-7235 compliance
- **TLS Standards**: RFC 5246/8446 compliance
- **JSON Standards**: RFC 8259 compliance

## Conclusion

This specification provides a comprehensive, standards-based protocol for FDO voucher transfer that ensures security, reliability, and interoperability between manufacturing systems and owner systems. The protocol supports both simple implementations and advanced enterprise deployments while maintaining backward compatibility and enabling future enhancements.
