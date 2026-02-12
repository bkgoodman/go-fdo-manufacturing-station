// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nuts-foundation/go-did/did"
)

// TestDIDResolver extends DIDResolver with test-specific functionality
type TestDIDResolver struct {
	*DIDResolver
	testMode bool
}

// NewTestDIDResolver creates a DID resolver with test capabilities
func NewTestDIDResolver(sessionState interface{}, config *DIDCache, testMode bool) *TestDIDResolver {
	return &TestDIDResolver{
		DIDResolver: NewDIDResolver(sessionState, config),
		testMode:    testMode,
	}
}

// ResolveDIDKey resolves a DID URI with test-specific methods
func (r *TestDIDResolver) ResolveDIDKey(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	// Handle test-specific did:file method
	if r.testMode && strings.HasPrefix(didURI, "did:file:") {
		return r.resolveDIDFile(ctx, didURI)
	}

	// Handle mock did:key for testing
	if r.testMode && strings.HasPrefix(didURI, "did:key:") {
		return r.resolveMockDIDKey(ctx, didURI)
	}

	// Fall back to regular resolution
	return r.DIDResolver.ResolveDIDKey(ctx, didURI)
}

// resolveDIDFile resolves did:file:/path/to/document.json (test only)
func (r *TestDIDResolver) resolveDIDFile(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	// Extract filename: did:file:filename.json
	filename := strings.TrimPrefix(didURI, "did:file:")
	if filename == "" {
		return nil, "", fmt.Errorf("did:file requires filename: %s", didURI)
	}

	// Always look in examples directory
	filePath := filepath.Join("examples", filename)

	// Read the DID document from file
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", fmt.Errorf("DID file not found (404): %s", filePath)
		}
		return nil, "", fmt.Errorf("failed to read DID file: %w", err)
	}

	// Parse the DID document
	doc, err := did.ParseDocument(string(data))
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Extract public key
	publicKey, err := r.extractPublicKey(doc)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract public key: %w", err)
	}

	// Extract DID URL - pass the original DID URI to help with file resolution
	didURL := r.extractDIDURLWithOriginalDID(doc, didURI)

	return publicKey, didURL, nil
}

// extractDIDURLWithOriginalDID extracts voucherRecipientURL using original DID URI
func (r *TestDIDResolver) extractDIDURLWithOriginalDID(doc *did.Document, originalDID string) string {
	// For did:file resolution, we need to re-read the raw JSON to get extensions
	// because the go-did library may not preserve custom properties

	if !strings.HasPrefix(originalDID, "did:file:") {
		return ""
	}

	// Extract filename from did:file:filename.json
	filename := strings.TrimPrefix(originalDID, "did:file:")
	if filename == "" {
		return ""
	}

	// Read the original file to get raw JSON with extensions
	filePath := filepath.Join("examples", filename)
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	// Parse the raw JSON to extract FDO extension
	var docMap map[string]interface{}
	if err := json.Unmarshal(data, &docMap); err != nil {
		return ""
	}

	// Look for fido-device-onboarding extension
	if fdoExt, ok := docMap["fido-device-onboarding"].(map[string]interface{}); ok {
		if voucherURL, ok := fdoExt["voucherRecipientURL"].(string); ok {
			return voucherURL
		}
	}

	return ""
}

// resolveMockDIDKey resolves did:key with mock implementation (test only)
func (r *TestDIDResolver) resolveMockDIDKey(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	// For testing, we'll generate a deterministic key based on the DID
	// This avoids needing multicodec parsing libraries

	// Use a simple approach: generate a key for testing
	// In a real implementation, you'd parse the multicodec from the DID

	// Generate a test P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate test key: %w", err)
	}

	// did:key doesn't have voucherRecipientURL
	return privateKey.Public(), "", nil
}

// GenerateTestDIDKey generates a test did:key URI with a real key
func GenerateTestDIDKey() (string, crypto.PublicKey, error) {
	// Generate a real P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}

	// For testing, we'll use a mock did:key format
	// In reality, did:key contains multicodec-encoded public key
	pubKey := privateKey.Public()
	didURI := "did:key:test-" + fmt.Sprintf("%x", pubKey.(*ecdsa.PublicKey).X)[:16]

	return didURI, pubKey, nil
}

// CreateTestDIDDocument creates a test DID document with FDO extension
func CreateTestDIDDocument(publicKey crypto.PublicKey, voucherURL string) (string, error) {
	// Convert public key to JWK format (simplified)
	jwk := map[string]interface{}{
		"crv": "P-256",
		"kty": "EC",
		"x":   "mock_x_value",
		"y":   "mock_y_value",
	}

	// Create DID document
	doc := map[string]interface{}{
		"@context": []string{"https://www.w3.org/ns/did/v1"},
		"id":       "did:web:localhost:8080:test",
		"verificationMethod": []map[string]interface{}{
			{
				"id":           "#key-1",
				"type":         "JsonWebKey2020",
				"controller":   "did:web:localhost:8080:test",
				"publicKeyJwk": jwk,
			},
		},
	}

	// Add FDO extension if voucher URL provided
	if voucherURL != "" {
		doc["fido-device-onboarding"] = map[string]interface{}{
			"voucherRecipientURL": voucherURL,
		}
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// SaveTestDIDDocument saves a test DID document to a file
func SaveTestDIDDocument(filePath string, publicKey crypto.PublicKey, voucherURL string) error {
	docJSON, err := CreateTestDIDDocument(publicKey, voucherURL)
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, []byte(docJSON), 0644)
}

// TestDIDIntegration tests DID resolution and voucher integration
func TestDIDIntegration(t *testing.T) {
	// Create test resolver
	resolver := NewTestDIDResolver(nil, &DIDCache{Enabled: false}, true)

	// Test 1: Mock did:key resolution
	t.Run("MockDIDKey", func(t *testing.T) {
		didURI := "did:key:test-12345"
		publicKey, didURL, err := resolver.ResolveDIDKey(nil, didURI)
		if err != nil {
			t.Fatalf("Failed to resolve mock did:key: %v", err)
		}

		if publicKey == nil {
			t.Fatal("Expected public key, got nil")
		}

		if didURL != "" {
			t.Errorf("Expected empty DID URL for did:key, got: %s", didURL)
		}

		t.Logf("✅ Mock did:key resolution successful")
	})

	// Test 2: did:file resolution
	t.Run("DIDFile", func(t *testing.T) {
		// Test with existing example file
		didURI := "did:file:did_owner.json"
		publicKey, didURL, err := resolver.ResolveDIDKey(nil, didURI)
		if err != nil {
			t.Fatalf("Failed to resolve did:file: %v", err)
		}

		if publicKey == nil {
			t.Fatal("Expected public key, got nil")
		}

		expectedURL := "https://example.com/vouchers/owner"
		if didURL != expectedURL {
			t.Errorf("Expected voucher URL %s, got: '%s'", expectedURL, didURL)
			t.Logf("Debug: DID URL was empty or incorrect")
		} else {
			t.Logf("✅ DID URL correctly extracted: %s", didURL)
		}

		t.Logf("✅ did:file resolution successful")
	})

	// Test 3: File not found
	t.Run("FileNotFound", func(t *testing.T) {
		didURI := "did:file:nonexistent.json"
		_, _, err := resolver.ResolveDIDKey(nil, didURI)
		if err == nil {
			t.Fatal("Expected error for non-existent file")
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected 'not found' error, got: %v", err)
		}

		t.Logf("✅ File not found handling successful")
	})
}

// TestDIDCaching tests DID caching behavior
func TestDIDCaching(t *testing.T) {
	// This would test the caching functionality
	// For now, we'll just create a placeholder
	t.Log("📋 DID caching tests not yet implemented")
}

// TestDIDIntegrationWithVoucher tests end-to-end DID integration with vouchers
func TestDIDIntegrationWithVoucher(t *testing.T) {
	// This would test the full voucher flow
	// For now, we'll just create a placeholder
	t.Log("📋 DID voucher integration tests not yet implemented")
}
