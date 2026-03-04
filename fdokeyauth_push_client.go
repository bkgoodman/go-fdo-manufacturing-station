// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"

	"github.com/fido-device-onboard/go-fdo/protocol"
	"github.com/fido-device-onboard/go-fdo/transfer"
)

// FDOKeyAuthPushClient handles FDOKeyAuth authentication for push operations.
type FDOKeyAuthPushClient struct {
	supplierKey crypto.Signer
	baseURL     string
	pathPrefix  string
}

// NewFDOKeyAuthPushClient creates a new FDOKeyAuth push client.
func NewFDOKeyAuthPushClient(supplierKey crypto.Signer, baseURL, pathPrefix string) *FDOKeyAuthPushClient {
	if pathPrefix == "" {
		pathPrefix = "/api/v1/vouchers"
	}
	return &FDOKeyAuthPushClient{
		supplierKey: supplierKey,
		baseURL:     baseURL,
		pathPrefix:  pathPrefix,
	}
}

// Authenticate performs FDOKeyAuth handshake and returns a session token.
func (c *FDOKeyAuthPushClient) Authenticate(ctx context.Context) (string, error) {
	if c.supplierKey == nil {
		return "", fmt.Errorf("supplier key not configured")
	}

	authClient := &transfer.FDOKeyAuthClient{
		CallerKey:  c.supplierKey,
		BaseURL:    c.baseURL,
		PathPrefix: c.pathPrefix,
	}

	result, err := authClient.Authenticate()
	if err != nil {
		return "", fmt.Errorf("FDOKeyAuth authentication failed: %w", err)
	}

	slog.Debug("FDOKeyAuth push authentication successful", "token_length", len(result.SessionToken))
	return result.SessionToken, nil
}

// ConvertPublicKeyToProtocol converts a crypto.PublicKey to protocol.PublicKey.
func ConvertPublicKeyToProtocol(pubKey crypto.PublicKey) (*protocol.PublicKey, error) {
	keyType, err := protocol.KeyTypeFromPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to determine key type: %w", err)
	}

	protoKey, err := encodePublicKey(keyType, protocol.X509KeyEnc, pubKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encode public key: %w", err)
	}

	return protoKey, nil
}
