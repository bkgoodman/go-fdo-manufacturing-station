// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/did"
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

// DIDResolver handles DID resolution with optional SQLite caching.
// Resolution is delegated to the go-fdo library's did.Resolver which
// correctly handles did:web (JWK parsing, service endpoints) and
// did:key (multicodec + base58-btc, zero external deps).
type DIDResolver struct {
	resolver *did.Resolver
	config   *DIDCache
	db       *sql.DB
}

// NewDIDResolver creates a new DID resolver.
// If db is nil, caching is disabled (resolution still works).
func NewDIDResolver(db *sql.DB, config *DIDCache) *DIDResolver {
	return &DIDResolver{
		resolver: did.NewResolver(),
		config:   config,
		db:       db,
	}
}

// SetInsecureHTTP enables HTTP (instead of HTTPS) for did:web resolution.
// This is for local development/testing only.
func (r *DIDResolver) SetInsecureHTTP(insecure bool) {
	r.resolver.InsecureHTTP = insecure
}

// ResolveDIDKey resolves a DID URI to a public key and optional voucher recipient URL.
func (r *DIDResolver) ResolveDIDKey(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	if r.config != nil && !r.config.Enabled {
		return nil, "", fmt.Errorf("DID resolution is disabled")
	}

	// did:key is stateless — resolve directly, no caching needed
	if strings.HasPrefix(didURI, "did:key:") {
		result, err := r.resolver.Resolve(ctx, didURI)
		if err != nil {
			return nil, "", fmt.Errorf("failed to resolve %s: %w", didURI, err)
		}
		return result.PublicKey, result.VoucherRecipientURL, nil
	}

	// did:web — use cache if available
	if strings.HasPrefix(didURI, "did:web:") {
		return r.resolveWithCache(ctx, didURI)
	}

	return nil, "", fmt.Errorf("unsupported DID method in %q", didURI)
}

// resolveWithCache resolves a DID URI using cache-first strategy.
func (r *DIDResolver) resolveWithCache(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	now := time.Now()

	// Try cache first (if DB available)
	if r.db != nil {
		cached, err := r.getFromCache(ctx, didURI)
		if err == nil && cached != nil {
			r.updateLastUsed(ctx, didURI, now)

			if r.shouldRefresh(cached, now) {
				// Try to refresh; on failure, use cached entry
				key, url, refreshErr := r.resolveFromLibrary(ctx, didURI)
				if refreshErr == nil {
					r.cacheResult(ctx, didURI, key, url, now)
					return key, url, nil
				}
				slog.Warn("DID refresh failed, using cached entry", "did", didURI, "error", refreshErr)
			}

			publicKey, err := x509.ParsePKIXPublicKey(cached.PublicKey)
			if err != nil {
				return nil, "", fmt.Errorf("failed to deserialize cached public key: %w", err)
			}
			return publicKey, cached.DIDURL, nil
		}
	}

	// Cache miss or no DB — resolve from network
	key, url, err := r.resolveFromLibrary(ctx, didURI)
	if err != nil {
		if r.db != nil {
			r.updateCacheError(ctx, didURI, now, err.Error())
		}
		return nil, "", err
	}

	if r.db != nil {
		r.cacheResult(ctx, didURI, key, url, now)
	}
	return key, url, nil
}

// resolveFromLibrary delegates to the go-fdo library's did.Resolver.
func (r *DIDResolver) resolveFromLibrary(ctx context.Context, didURI string) (crypto.PublicKey, string, error) {
	result, err := r.resolver.Resolve(ctx, didURI)
	if err != nil {
		return nil, "", err
	}
	return result.PublicKey, result.VoucherRecipientURL, nil
}

// shouldRefresh determines if a cache entry should be refreshed.
func (r *DIDResolver) shouldRefresh(cached *DIDCacheEntry, now time.Time) bool {
	if r.config == nil {
		return true
	}
	if now.Sub(cached.Timestamp) > r.config.MaxAge {
		return true
	}
	if now.Sub(cached.Timestamp) < r.config.RefreshInterval {
		return false
	}
	if now.Sub(cached.LastRefreshAttempt) < r.config.FailureBackoff {
		return false
	}
	return true
}

// cacheResult serializes the public key and stores it in the cache.
func (r *DIDResolver) cacheResult(ctx context.Context, didURI string, key crypto.PublicKey, url string, now time.Time) {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		slog.Warn("failed to serialize public key for cache", "did", didURI, "error", err)
		return
	}
	entry := &DIDCacheEntry{
		DIDURI:             didURI,
		PublicKey:          keyBytes,
		DIDURL:             url,
		Timestamp:          now,
		LastRefreshAttempt: now,
		LastRefreshError:   "",
		LastUsed:           now,
	}
	if err := r.updateCache(ctx, entry); err != nil {
		slog.Warn("failed to update DID cache", "did", didURI, "error", err)
	}
}

// --- SQLite cache operations ---

func (r *DIDResolver) getFromCache(ctx context.Context, didURI string) (*DIDCacheEntry, error) {
	if r.db == nil {
		return nil, fmt.Errorf("no database available")
	}
	row := r.db.QueryRowContext(ctx,
		`SELECT did_uri, public_key, did_url, timestamp, last_refresh_attempt, last_refresh_error, last_used
		 FROM did_cache WHERE did_uri = ?`, didURI)

	var entry DIDCacheEntry
	err := row.Scan(&entry.DIDURI, &entry.PublicKey, &entry.DIDURL,
		&entry.Timestamp, &entry.LastRefreshAttempt, &entry.LastRefreshError, &entry.LastUsed)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

func (r *DIDResolver) updateCache(ctx context.Context, entry *DIDCacheEntry) error {
	if r.db == nil {
		return nil
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO did_cache (did_uri, public_key, did_url, timestamp, last_refresh_attempt, last_refresh_error, last_used)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(did_uri) DO UPDATE SET
		   public_key = excluded.public_key,
		   did_url = excluded.did_url,
		   timestamp = excluded.timestamp,
		   last_refresh_attempt = excluded.last_refresh_attempt,
		   last_refresh_error = excluded.last_refresh_error,
		   last_used = excluded.last_used`,
		entry.DIDURI, entry.PublicKey, entry.DIDURL,
		entry.Timestamp, entry.LastRefreshAttempt, entry.LastRefreshError, entry.LastUsed)
	return err
}

func (r *DIDResolver) updateLastUsed(ctx context.Context, didURI string, lastUsed time.Time) {
	if r.db == nil {
		return
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE did_cache SET last_used = ? WHERE did_uri = ?`, lastUsed, didURI)
	if err != nil {
		slog.Warn("failed to update DID cache last_used", "did", didURI, "error", err)
	}
}

func (r *DIDResolver) updateCacheError(ctx context.Context, didURI string, now time.Time, errorMsg string) {
	if r.db == nil {
		return
	}
	_, err := r.db.ExecContext(ctx,
		`UPDATE did_cache SET last_refresh_attempt = ?, last_refresh_error = ? WHERE did_uri = ?`,
		now, errorMsg, didURI)
	if err != nil {
		slog.Warn("failed to update DID cache error", "did", didURI, "error", err)
	}
}

// PurgeExpired removes entries not used within the configured PurgeUnused duration.
func (r *DIDResolver) PurgeExpired(ctx context.Context) (int, error) {
	if r.db == nil {
		return 0, fmt.Errorf("no database available")
	}
	cutoff := time.Now().Add(-r.config.PurgeUnused)
	result, err := r.db.ExecContext(ctx, `DELETE FROM did_cache WHERE last_used < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to purge expired DID cache entries: %w", err)
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// PurgeAll removes all entries from the cache.
func (r *DIDResolver) PurgeAll(ctx context.Context) (int, error) {
	if r.db == nil {
		return 0, fmt.Errorf("no database available")
	}
	result, err := r.db.ExecContext(ctx, `DELETE FROM did_cache`)
	if err != nil {
		return 0, fmt.Errorf("failed to purge all DID cache entries: %w", err)
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

// InitializeCache creates the did_cache table if it doesn't exist.
func (r *DIDResolver) InitializeCache(ctx context.Context) error {
	if r.db == nil {
		return fmt.Errorf("no database available")
	}

	_, err := r.db.ExecContext(ctx, `
	CREATE TABLE IF NOT EXISTS did_cache (
		did_uri TEXT PRIMARY KEY,
		public_key BLOB NOT NULL,
		did_url TEXT,
		timestamp INTEGER NOT NULL,
		last_refresh_attempt INTEGER NOT NULL,
		last_refresh_error TEXT,
		last_used INTEGER NOT NULL
	)`)
	if err != nil {
		return fmt.Errorf("failed to create did_cache table: %w", err)
	}

	_, err = r.db.ExecContext(ctx, `
	CREATE INDEX IF NOT EXISTS idx_did_cache_last_used ON did_cache(last_used)`)
	if err != nil {
		return fmt.Errorf("failed to create did_cache index: %w", err)
	}

	return nil
}
