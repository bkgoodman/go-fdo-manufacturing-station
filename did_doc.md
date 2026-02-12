# Formalized DID Context

## Required Context Document

For <https://fidoalliance.org/ns/did/v1>, you'd need to host this JSON-LD context:

```json
{
  "@context": {
    "fido-device-onboarding": {
      "@id": "https://fidoalliance.org/ns/did/v1#fido-device-onboarding",
      "@type": "@json"
    },
    "voucherRecipientURL": "https://fidoalliance.org/ns/did/v1#voucherRecipientURL"
  }
}
```

## What This Does

1. ``fido-device-onboarding``: Defines your extension term as a JSON object
1. ``voucherRecipientURL``: Defines the URL property within that object
1. ``@id`` URLs: Provide unique identifiers for each term
1. ``@type": "@json"``: Tells JSON-LD processors this contains structured JSON data

## Hosting Requirements

1. **HTTPS required** - Must be served over HTTPS
1. **CORS headers** - Should allow cross-origin requests
1. **Content-Type**: `application/ld+json`
1. **Must be publicly accessible** - DID resolvers need to fetch it

## Alternative (Simpler) Approach

Since this is for a specific ecosystem, you could use the "out-of-band agreement" approach and skip the custom context entirely:

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://myvms.com/importvouchers"
  }
}
```

## Both Approaches Use Same DID Document Structure

Your DID document would be identical in both cases:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://fidoalliance.org/ns/did/v1"
  ],
  "id": "did:web:example.com:owner",
  "verificationMethod": [...],
  "fido-device-onboarding": {
    "voucherRecipientURL": "https://myvms.com/importvouchers"
  }
}
```

## The Difference is Context Availability

### Without Published Context (Current State)

- ✅ Works: FDO ecosystem implementations can parse it
- ❌ Limitation: Generic JSON-LD processors might drop fido-device-onboarding as "undefined term"
- ❌ Interoperability: Outside FDO ecosystem, it's "out-of-band agreement only"

### With Published Context (Formal Approach)

- ✅ Works: FDO ecosystem implementations can parse it
- ✅ Interoperability: Any JSON-LD processor can understand it
- ✅ Standards Compliant: Follows W3C DID Specification Registries recommendation
- ✅ Future Proof: Other ecosystems can adopt your extension

## The Key Insight

You can implement NOW with the simple approach, then publish the context later to make it formally correct.

The DID document structure doesn't change - only whether the context URL resolves to a real JSON-LD definition.
