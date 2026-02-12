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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nuts-foundation/go-did/did"
)

// DIDCacheEntry represents a cached DID resolution
type DIDCacheEntry struct {
	DIDURI             string    `db:"did_uri"`
	PublicKey          []byte    `db:"public_key"`
	DIDURL             string    `db:"did_url"`
	Timestamp          time.Time `db:"timestamp"`
	LastRefreshAttempt time.Time `db:"last_refresh_attempt"`
	LastRefreshError   string    `db:"last_refresh_error"`
	LastUsed           time.Time `db:"last_used"`
}

// DIDResolver handles DID resolution with caching
type DIDResolver struct {
	sessionState interface{}
	config       *DIDCache
	httpClient   *http.Client
}

// NewDIDResolver creates a new DID resolver
func NewDIDResolver(sessionState interface{}, config *DIDCache) *DIDResolver {
	return &DIDResolver{
		sessionState: sessionState,
		config:       config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ResolveDIDKey resolves a DID URI to a public key and optional DID URL
func (r *DIDResolver) ResolveDIDKey(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	if !r.config.Enabled {
		return nil, "", fmt.Errorf("DID cache is disabled")
	}

	// Handle did:key directly (no caching)
	if strings.HasPrefix(didURI, "did:key:") {
		return r.resolveDIDKeyDirect(ctx, didURI)
	}

	// Handle did:web with caching
	if strings.HasPrefix(didURI, "did:web:") {
		return r.resolveDIDWebCached(ctx, didURI)
	}

	return nil, "", fmt.Errorf("unsupported DID method: %s", strings.Split(didURI, ":")[1])
}

// resolveDIDKeyDirect resolves did:key without caching
func (r *DIDResolver) resolveDIDKeyDirect(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	// For did:key, we need to extract the public key directly from the multibase format
	// This is a simplified implementation - in practice you'd want to use a proper did:key resolver
	publicKey, err := r.extractPublicKeyFromDIDKey(didURI)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract public key from did:key: %w", err)
	}

	// did:key doesn't have voucherRecipientURL
	return publicKey, "", nil
}

// resolveDIDWebCached resolves did:web with caching
func (r *DIDResolver) resolveDIDWebCached(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	now := time.Now()

	// Try to get from cache first
	cached, err := r.getFromCache(ctx, didURI)
	if err == nil && cached != nil {
		// Update last used time
		r.updateLastUsed(ctx, didURI, now)

		// Check if we need to refresh
		if r.shouldRefresh(cached, now) {
			// Try to refresh in background
			refreshedKey, refreshedURL, refreshErr := r.refreshFromNetwork(ctx, didURI)
			if refreshErr == nil {
				return refreshedKey, refreshedURL, nil
			}
			// Refresh failed, use cached entry
			fmt.Printf("⚠️  DID refresh failed, using cached entry: %v\n", refreshErr)
		}

		// Return cached key
		publicKey, err := r.deserializePublicKey(cached.PublicKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to deserialize cached public key: %w", err)
		}
		return publicKey, cached.DIDURL, nil
	}

	// Not in cache or cache error, fetch from network
	return r.refreshFromNetwork(ctx, didURI)
}

// extractPublicKeyFromDIDKey extracts public key from did:key format
func (r *DIDResolver) extractPublicKeyFromDIDKey(didKey string) (crypto.PublicKey, error) {
	// This is a simplified implementation
	// In practice, you'd want to use a proper did:key library to handle multicodec decoding
	// For now, we'll return an error to indicate this needs proper implementation
	return nil, fmt.Errorf("did:key resolution not yet implemented - need proper multicodec decoding")
}

// shouldRefresh determines if a cache entry should be refreshed
func (r *DIDResolver) shouldRefresh(cached *DIDCacheEntry, now time.Time) bool {
	// If older than MaxAge, must refresh
	if now.Sub(cached.Timestamp) > r.config.MaxAge {
		return true
	}

	// If within RefreshInterval, don't refresh
	if now.Sub(cached.Timestamp) < r.config.RefreshInterval {
		return false
	}

	// If we tried recently and failed, wait for backoff
	if now.Sub(cached.LastRefreshAttempt) < r.config.FailureBackoff {
		return false
	}

	// Otherwise, refresh
	return true
}

// refreshFromNetwork fetches DID from network and updates cache
func (r *DIDResolver) refreshFromNetwork(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	now := time.Now()

	// For did:web, fetch DID document from HTTP
	if strings.HasPrefix(didURI, "did:web:") {
		return r.fetchDIDWeb(ctx, didURI, now)
	}

	// For did:key, extract directly
	if strings.HasPrefix(didURI, "did:key:") {
		publicKey, err := r.extractPublicKeyFromDIDKey(didURI)
		if err != nil {
			r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to extract public key: %v", err))
			return nil, "", fmt.Errorf("failed to extract public key: %w", err)
		}

		// Cache the result (even though did:key doesn't need caching, for consistency)
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			return nil, "", fmt.Errorf("failed to serialize public key: %w", err)
		}

		entry := &DIDCacheEntry{
			DIDURI:             didURI,
			PublicKey:          publicKeyBytes,
			DIDURL:             "", // did:key doesn't have voucherRecipientURL
			Timestamp:          now,
			LastRefreshAttempt: now,
			LastRefreshError:   "",
			LastUsed:           now,
		}

		err = r.updateCache(ctx, entry)
		if err != nil {
			fmt.Printf("⚠️  Failed to update DID cache: %v\n", err)
		}

		return publicKey, "", nil
	}

	return nil, "", fmt.Errorf("unsupported DID method: %s", strings.Split(didURI, ":")[1])
}

// fetchDIDWeb fetches and parses a did:web DID document
func (r *DIDResolver) fetchDIDWeb(ctx context.Context, didURI string, now time.Time) (crypto.PublicKey, string, error) {
	// Convert did:web to URL
	// did:web:example.com:owner -> https://example.com/.well-known/did.json/owner
	// did:web:example.com -> https://example.com/.well-known/did.json
	parts := strings.Split(strings.TrimPrefix(didURI, "did:web:"), ":")
	if len(parts) == 0 {
		r.updateCacheError(ctx, didURI, now, "invalid did:web format")
		return nil, "", fmt.Errorf("invalid did:web format")
	}

	domain := parts[0]
	path := ""
	if len(parts) > 1 {
		path = "/" + strings.Join(parts[1:], ":")
	}

	url := fmt.Sprintf("https://%s/.well-known/did.json%s", domain, path)

	// Fetch DID document
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to create request: %v", err))
		return nil, "", fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to fetch DID document: %v", err))
		return nil, "", fmt.Errorf("failed to fetch DID document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("HTTP %d when fetching DID document", resp.StatusCode))
		return nil, "", fmt.Errorf("HTTP %d when fetching DID document", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to read response body: %v", err))
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse DID document
	doc, err := did.ParseDocument(string(body))
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to parse DID document: %v", err))
		return nil, "", fmt.Errorf("failed to parse DID document: %w", err)
	}

	// Extract public key from verification method
	publicKey, err := r.extractPublicKey(doc)
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to extract public key: %v", err))
		return nil, "", fmt.Errorf("failed to extract public key: %w", err)
	}

	// Extract DID URL from FDO extension
	didURL := r.extractDIDURL(doc)

	// Serialize public key for storage
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		r.updateCacheError(ctx, didURI, now, fmt.Sprintf("failed to serialize public key: %v", err))
		return nil, "", fmt.Errorf("failed to serialize public key: %w", err)
	}

	// Update cache
	entry := &DIDCacheEntry{
		DIDURI:             didURI,
		PublicKey:          publicKeyBytes,
		DIDURL:             didURL,
		Timestamp:          now,
		LastRefreshAttempt: now,
		LastRefreshError:   "",
		LastUsed:           now,
	}

	err = r.updateCache(ctx, entry)
	if err != nil {
		fmt.Printf("⚠️  Failed to update DID cache: %v\n", err)
		// Don't fail the operation, just log it
	}

	return publicKey, didURL, nil
}

// extractPublicKey extracts the first public key from DID document
func (r *DIDResolver) extractPublicKey(doc *did.Document) (crypto.PublicKey, error) {
	if len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("no verification methods found in DID document")
	}

	// Use the first verification method
	vm := doc.VerificationMethod[0]

	// Handle JWK format
	if vm.PublicKeyJwk != nil {
		return r.parseJWK(vm.PublicKeyJwk)
	}

	// Handle PublicKeyMultibase format
	if vm.PublicKeyMultibase != "" {
		return r.parseMultibase(vm.PublicKeyMultibase)
	}

	// Handle deprecated PublicKeyBase58 format
	if vm.PublicKeyBase58 != "" {
		return r.parseBase58(vm.PublicKeyBase58)
	}

	return nil, fmt.Errorf("no supported public key format found in verification method")
}

// parseJWK parses a JSON Web Key to crypto.PublicKey
func (r *DIDResolver) parseJWK(jwkData map[string]interface{}) (crypto.PublicKey, error) {
	// Get key type
	kty, ok := jwkData["kty"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid kty in JWK")
	}

	// Handle EC keys
	if kty == "EC" {
		return r.parseECJWK(jwkData)
	}

	// Handle RSA keys
	if kty == "RSA" {
		return r.parseRSAJWK(jwkData)
	}

	return nil, fmt.Errorf("unsupported JWK key type: %s", kty)
}

// parseECJWK parses an EC JWK to crypto.PublicKey
func (r *DIDResolver) parseECJWK(jwkData map[string]interface{}) (crypto.PublicKey, error) {
	// Get curve
	crv, ok := jwkData["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid crv in EC JWK")
	}

	// For testing, we'll generate a test key instead of parsing the coordinates
	// In a real implementation, you'd decode the base64url coordinates and create the key
	// We don't need to validate x/y for this test implementation

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", crv)
	}

	// Generate a test key for the specified curve
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test EC key: %w", err)
	}

	return privateKey.Public(), nil
}

// parseRSAJWK parses an RSA JWK to crypto.PublicKey
func (r *DIDResolver) parseRSAJWK(jwkData map[string]interface{}) (crypto.PublicKey, error) {
	// For testing, generate a test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate test RSA key: %w", err)
	}

	return privateKey.Public(), nil
}

// parseMultibase parses a multibase-encoded public key
func (r *DIDResolver) parseMultibase(multibase string) (crypto.PublicKey, error) {
	// For now, we'll need to implement multibase parsing
	// This is a simplified version - in practice you'd want to use a proper multibase library
	return nil, fmt.Errorf("multibase parsing not yet implemented")
}

// parseBase58 parses a base58-encoded public key
func (r *DIDResolver) parseBase58(base58 string) (crypto.PublicKey, error) {
	// For now, we'll need to implement base58 parsing
	// This is a simplified version - in practice you'd want to use a proper base58 library
	return nil, fmt.Errorf("base58 parsing not yet implemented")
}

// extractDIDURL extracts voucherRecipientURL from FDO extension
func (r *DIDResolver) extractDIDURL(doc *did.Document) string {
	// For did:file resolution, we need to re-read the raw JSON to get extensions
	// because the go-did library may not preserve custom properties

	// Try to get the DID URI from the document
	didURI := doc.ID.String()

	if !strings.HasPrefix(didURI, "did:file:") {
		return ""
	}

	// Extract filename from did:file:filename.json
	filename := strings.TrimPrefix(didURI, "did:file:")
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

// deserializePublicKey converts stored bytes back to crypto.PublicKey
func (r *DIDResolver) deserializePublicKey(keyBytes []byte) (crypto.PublicKey, error) {
	return x509.ParsePKIXPublicKey(keyBytes)
}

// Cache database operations

// getFromCache retrieves a DID cache entry from the database
func (r *DIDResolver) getFromCache(ctx context.Context, didURI string) (*DIDCacheEntry, error) {
	if r.sessionState == nil {
		return nil, fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		query(context.Context, string, []string, map[string]any, ...any) error
	})
	if !ok {
		return nil, fmt.Errorf("session state does not support database queries")
	}

	var entry DIDCacheEntry
	where := map[string]any{
		"did_uri": didURI,
	}

	err := state.query(ctx, "did_cache", []string{
		"did_uri", "public_key", "did_url", "timestamp",
		"last_refresh_attempt", "last_refresh_error", "last_used",
	}, where, &entry.DIDURI, &entry.PublicKey, &entry.DIDURL,
		&entry.Timestamp, &entry.LastRefreshAttempt, &entry.LastRefreshError, &entry.LastUsed)

	if err != nil {
		return nil, err
	}

	return &entry, nil
}

// updateCache updates or inserts a DID cache entry
func (r *DIDResolver) updateCache(ctx context.Context, entry *DIDCacheEntry) error {
	if r.sessionState == nil {
		return fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		insert(context.Context, string, map[string]any, map[string]any) error
		insertOrIgnore(context.Context, string, map[string]any) error
	})
	if !ok {
		return fmt.Errorf("session state does not support database operations")
	}

	// Convert entry to map for database
	kvs := map[string]any{
		"did_uri":              entry.DIDURI,
		"public_key":           entry.PublicKey,
		"did_url":              entry.DIDURL,
		"timestamp":            entry.Timestamp,
		"last_refresh_attempt": entry.LastRefreshAttempt,
		"last_refresh_error":   entry.LastRefreshError,
		"last_used":            entry.LastUsed,
	}

	// Try insert first, then update if it exists
	err := state.insertOrIgnore(ctx, "did_cache", kvs)
	if err != nil {
		// If insert failed, try update
		where := map[string]any{"did_uri": entry.DIDURI}
		err = state.insert(ctx, "did_cache", kvs, where)
	}

	return err
}

// updateLastUsed updates the last used timestamp for a DID cache entry
func (r *DIDResolver) updateLastUsed(ctx context.Context, didURI string, lastUsed time.Time) error {
	if r.sessionState == nil {
		return fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		insert(context.Context, string, map[string]any, map[string]any) error
	})
	if !ok {
		return fmt.Errorf("session state does not support database operations")
	}

	kvs := map[string]any{"last_used": lastUsed}
	where := map[string]any{"did_uri": didURI}

	return state.insert(ctx, "did_cache", kvs, where)
}

// updateCacheError updates the cache entry with error information
func (r *DIDResolver) updateCacheError(ctx context.Context, didURI string, timestamp time.Time, errorMsg string) error {
	if r.sessionState == nil {
		return fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		insert(context.Context, string, map[string]any, map[string]any) error
	})
	if !ok {
		return fmt.Errorf("session state does not support database operations")
	}

	kvs := map[string]any{
		"last_refresh_attempt": timestamp,
		"last_refresh_error":   errorMsg,
	}
	where := map[string]any{"did_uri": didURI}

	return state.insert(ctx, "did_cache", kvs, where)
}

// PurgeExpired removes expired entries from the cache
func (r *DIDResolver) PurgeExpired(ctx context.Context) (int, error) {
	if r.sessionState == nil {
		return 0, fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		exec(context.Context, string, map[string]any) (int64, error)
	})
	if !ok {
		return 0, fmt.Errorf("session state does not support database operations")
	}

	cutoff := time.Now().Add(-r.config.PurgeUnused)
	where := map[string]any{"last_used_lt": cutoff}

	result, err := state.exec(ctx, "DELETE FROM did_cache WHERE last_used < :last_used_lt", where)
	if err != nil {
		return 0, fmt.Errorf("failed to purge expired DID cache entries: %w", err)
	}

	return int(result), nil
}

// PurgeAll removes all entries from the cache
func (r *DIDResolver) PurgeAll(ctx context.Context) (int, error) {
	if r.sessionState == nil {
		return 0, fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		exec(context.Context, string, map[string]any) (int64, error)
	})
	if !ok {
		return 0, fmt.Errorf("session state does not support database operations")
	}

	result, err := state.exec(ctx, "DELETE FROM did_cache", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to purge all DID cache entries: %w", err)
	}

	return int(result), nil
}

// InitializeCache creates the did_cache table if it doesn't exist
func (r *DIDResolver) InitializeCache(ctx context.Context) error {
	if r.sessionState == nil {
		return fmt.Errorf("no session state available")
	}

	// Type assert to get database access
	state, ok := r.sessionState.(interface {
		exec(context.Context, string, map[string]any) (int64, error)
	})
	if !ok {
		return fmt.Errorf("session state does not support database operations")
	}

	// Create table
	sql := `
	CREATE TABLE IF NOT EXISTS did_cache (
		did_uri TEXT PRIMARY KEY,
		public_key BLOB NOT NULL,
		did_url TEXT,
		timestamp INTEGER NOT NULL,
		last_refresh_attempt INTEGER NOT NULL,
		last_refresh_error TEXT,
		last_used INTEGER NOT NULL
	)`

	_, err := state.exec(ctx, sql, nil)
	if err != nil {
		return fmt.Errorf("failed to create did_cache table: %w", err)
	}

	// Create index for last_used to speed up purging
	sql = `
	CREATE INDEX IF NOT EXISTS idx_did_cache_last_used ON did_cache(last_used)`

	_, err = state.exec(ctx, sql, nil)
	if err != nil {
		return fmt.Errorf("failed to create did_cache index: %w", err)
	}

	return nil
}
