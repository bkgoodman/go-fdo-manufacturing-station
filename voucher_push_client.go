// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"os"

	fdo "github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// VoucherPushClient wraps the library's transfer.HTTPPushSender,
// adapting its interface to the app's file-path-based push workflow.
type VoucherPushClient struct {
	sender       *transfer.HTTPPushSender
	config       *VoucherConfig
	sessionState interface{} // For accessing manufacturer keys
	authClients  map[string]*FDOKeyAuthPushClient
}

// NewVoucherPushClient constructs a push client with sensible defaults.
func NewVoucherPushClient(config *VoucherConfig, sessionState interface{}) *VoucherPushClient {
	return &VoucherPushClient{
		sender:       transfer.NewHTTPPushSender(),
		config:       config,
		sessionState: sessionState,
		authClients:  make(map[string]*FDOKeyAuthPushClient),
	}
}

// Push reads a voucher from filePath and uploads it to the destination URL.
func (c *VoucherPushClient) Push(ctx context.Context, dest *VoucherDestination, filePath, serial, model, guid string) error {
	if c == nil || c.sender == nil {
		return fmt.Errorf("push client not configured")
	}
	if dest == nil || dest.URL == "" {
		return fmt.Errorf("destination missing URL")
	}

	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read voucher file %s: %w", filePath, err)
	}

	// Voucher files are PEM-encoded; decode to get raw CBOR bytes
	raw := fileData
	if block, _ := pem.Decode(fileData); block != nil {
		raw = block.Bytes
	}

	var ov fdo.Voucher
	if err := cbor.Unmarshal(raw, &ov); err != nil {
		return fmt.Errorf("failed to decode voucher from %s: %w", filePath, err)
	}

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:         guid,
			SerialNumber: serial,
			ModelNumber:  model,
		},
		Voucher: &ov,
		Raw:     raw,
	}

	// Get authentication token (FDOKeyAuth or static)
	token, err := c.getAuthToken(ctx, dest)
	if err != nil {
		return fmt.Errorf("failed to get authentication token: %w", err)
	}

	pushDest := transfer.PushDestination{
		URL:   dest.URL,
		Token: token,
	}

	return c.sender.Push(ctx, pushDest, data)
}

// getAuthToken retrieves an authentication token using FDOKeyAuth or static token.
func (c *VoucherPushClient) getAuthToken(ctx context.Context, dest *VoucherDestination) (string, error) {
	if c.config == nil {
		return "", fmt.Errorf("push client config not configured")
	}

	authMethod := c.config.PushService.AuthMethod
	if authMethod == "" {
		authMethod = "both"
	}

	// Try FDOKeyAuth if enabled
	if authMethod == "fdokeyauth" || authMethod == "both" {
		token, err := c.authenticateWithFDOKeyAuth(ctx, dest.URL)
		if err == nil {
			slog.Debug("using FDOKeyAuth token for push", "url", dest.URL)
			return token, nil
		}
		if authMethod == "fdokeyauth" {
			return "", fmt.Errorf("FDOKeyAuth required but failed: %w", err)
		}
		slog.Debug("FDOKeyAuth failed, falling back to static token", "error", err)
	}

	// Fall back to static token
	if dest.Token != "" {
		slog.Debug("using static bearer token for push", "url", dest.URL)
		return dest.Token, nil
	}

	return "", fmt.Errorf("no authentication method available (no FDOKeyAuth and no static token)")
}

// authenticateWithFDOKeyAuth performs FDOKeyAuth authentication for push.
func (c *VoucherPushClient) authenticateWithFDOKeyAuth(ctx context.Context, destURL string) (string, error) {
	if c.config == nil || c.sessionState == nil {
		return "", fmt.Errorf("FDOKeyAuth not configured")
	}

	// Get or create auth client for this URL
	authClient, exists := c.authClients[destURL]
	if !exists {
		// Get supplier key
		supplierKey, err := c.getSupplierKey(ctx)
		if err != nil {
			return "", fmt.Errorf("failed to get supplier key: %w", err)
		}

		// Parse destination URL to split scheme+host from path.
		// baseURL here is actually the full destination URL (e.g.
		// http://host:port/api/v1/vouchers), so we must separate
		// the base (scheme+host) from the path prefix to avoid
		// the path being doubled in FDOKeyAuth endpoint URLs.
		parsedURL, parseErr := url.Parse(destURL)
		if parseErr != nil {
			return "", fmt.Errorf("failed to parse destination URL %s: %w", destURL, parseErr)
		}
		schemeHost := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		pathPrefix := parsedURL.Path
		if pathPrefix == "" {
			pathPrefix = "/api/v1/vouchers"
		}

		authClient = NewFDOKeyAuthPushClient(supplierKey, schemeHost, pathPrefix)
		c.authClients[destURL] = authClient
	}

	return authClient.Authenticate(ctx)
}

// getSupplierKey retrieves the supplier key for FDOKeyAuth.
func (c *VoucherPushClient) getSupplierKey(ctx context.Context) (crypto.Signer, error) {
	// Try dedicated supplier key file first
	if c.config.PushService.SupplierKeyFile != "" {
		return loadPrivateKeyFromFile(c.config.PushService.SupplierKeyFile)
	}

	// Fall back to manufacturer key from session state
	if c.sessionState == nil {
		return nil, fmt.Errorf("no session state for manufacturer key")
	}

	// Try to get manufacturer key from session state
	type ManufacturerKeyProvider interface {
		ManufacturerKey(ctx context.Context, keyType protocol.KeyType, index int) (crypto.Signer, []*x509.Certificate, error)
	}

	if provider, ok := c.sessionState.(ManufacturerKeyProvider); ok {
		keyType := protocol.Secp384r1KeyType
		if c.config.PushService.SupplierKeyType != "" {
			kt, err := protocol.ParseKeyType(c.config.PushService.SupplierKeyType)
			if err != nil {
				slog.Warn("invalid supplier key type, using default", "type", c.config.PushService.SupplierKeyType)
			} else {
				keyType = kt
			}
		}

		key, _, err := provider.ManufacturerKey(ctx, keyType, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to get manufacturer key: %w", err)
		}
		return key, nil
	}

	return nil, fmt.Errorf("session state does not provide manufacturer key")
}

// loadPrivateKeyFromFile loads a private key from a PEM-encoded file.
func loadPrivateKeyFromFile(filename string) (crypto.Signer, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", filename, err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM from %s", filename)
	}

	var key crypto.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %w", filename, err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("key from %s does not implement crypto.Signer", filename)
	}

	return signer, nil
}
