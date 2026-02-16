// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// VoucherSigningRequest represents a voucher signing request to external HSM
type VoucherSigningRequest struct {
	Voucher              string         `json:"voucher"`               // base64-encoded CBOR voucher
	OwnerKey             string         `json:"owner_key"`             // PEM-encoded public key
	RequestID            string         `json:"request_id"`            // Unique request identifier
	Timestamp            time.Time      `json:"timestamp"`             // Request timestamp
	ManufacturingStation string         `json:"manufacturing_station"` // Station identifier
	DeviceInfo           DeviceInfo     `json:"device_info"`           // Device details
	OVEExtraData         map[int][]byte `json:"ove_extra_data,omitempty"`
}

// DeviceInfo contains device details for logging/auditing
type DeviceInfo struct {
	SerialNo string `json:"serialno"`
	Model    string `json:"model"`
}

// VoucherSigningResponse represents the JSON response from external HSM
type VoucherSigningResponse struct {
	SignedVoucher string  `json:"signed_voucher"` // base64-encoded CBOR signed voucher
	RequestID     string  `json:"request_id"`     // Echoed request ID
	HSMInfo       HSMInfo `json:"hsm_info"`       // HSM signing details
	Error         string  `json:"error"`          // Error message if any
}

// HSMInfo contains HSM signing details
type HSMInfo struct {
	HSMID       string    `json:"hsm_id"`
	SigningTime time.Time `json:"signing_time"`
	KeyID       string    `json:"key_id"`
}

// VoucherSigningService handles voucher signing operations
type VoucherSigningService struct {
	config       *VoucherSigningConfig
	executor     *ExternalCommandExecutor
	stationID    string
	sessionState interface{} // For accessing manufacturer keys
}

// NewVoucherSigningService creates a new voucher signing service
func NewVoucherSigningService(config *VoucherSigningConfig, executor *ExternalCommandExecutor, stationID string) *VoucherSigningService {
	return &VoucherSigningService{
		config:    config,
		executor:  executor,
		stationID: stationID,
	}
}

// SetSessionState sets the session state for accessing manufacturer keys
func (s *VoucherSigningService) SetSessionState(sessionState interface{}) {
	s.sessionState = sessionState
}

// SignVoucher signs a voucher based on the configured mode
func (s *VoucherSigningService) SignVoucher(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, serial, model string, extraData map[int][]byte) (*fdo.Voucher, error) {
	switch s.config.Mode {
	case "internal":
		return s.signVoucherInternal(ctx, voucher, nextOwner, extraData)
	case "external":
		return s.signVoucherExternal(ctx, voucher, nextOwner, serial, model, extraData)
	case "hsm":
		return s.signVoucherHSM(ctx, voucher, nextOwner, serial, model, extraData)
	default:
		return nil, fmt.Errorf("unsupported voucher signing mode: %s", s.config.Mode)
	}
}

// signVoucherInternal signs voucher using internal owner key
// This uses the manufacturer key from the database to extend the voucher to the nextOwner
func (s *VoucherSigningService) signVoucherInternal(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, extraData map[int][]byte) (*fdo.Voucher, error) {
	fmt.Printf("🔧 Internal voucher signing - extending voucher to next owner\n")
	fmt.Printf("📋 OVEExtra data keys: %d\n", len(extraData))
	for key, value := range extraData {
		fmt.Printf("   Key %d: %d bytes\n", key, len(value))
	}

	// For internal mode, we need to get the manufacturer private key from the database
	// and use it to extend the voucher to the next owner
	manufacturerKey, err := s.getManufacturerKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get manufacturer key for internal signing: %w", err)
	}

	if manufacturerKey == nil {
		return nil, fmt.Errorf("no manufacturer key available for internal signing")
	}

	fmt.Printf("🔐 Using manufacturer key to extend voucher to next owner\n")

	// Use fdo.ExtendVoucher with the manufacturer key and next owner
	var extendedVoucher *fdo.Voucher

	// Type assert nextOwner to satisfy protocol.PublicKeyOrChain constraint
	switch key := nextOwner.(type) {
	case *ecdsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, manufacturerKey, key, extraData)
	case *rsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, manufacturerKey, key, extraData)
	case []*x509.Certificate:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, manufacturerKey, key, extraData)
	default:
		return nil, fmt.Errorf("unsupported nextOwner key type: %T", nextOwner)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to extend voucher with internal signing: %w", err)
	}

	fmt.Printf("✅ Voucher extended successfully using internal manufacturer key\n")
	return extendedVoucher, nil
}

// getManufacturerKey retrieves the manufacturer private key from the session state
func (s *VoucherSigningService) getManufacturerKey(ctx context.Context) (crypto.Signer, error) {
	if s.sessionState == nil {
		return nil, fmt.Errorf("no session state available")
	}

	// Type assert to get the ManufacturerKey method
	// This uses the same interface as in main.go
	state, ok := s.sessionState.(interface {
		ManufacturerKey(ctx context.Context, keyType protocol.KeyType, rsaBits int) (crypto.Signer, []*x509.Certificate, error)
	})
	if !ok {
		return nil, fmt.Errorf("session state does not support ManufacturerKey method")
	}

	// Get ECDSA P-384 manufacturer key (same as used in main.go)
	manufacturerKey, _, err := state.ManufacturerKey(ctx, protocol.Secp384r1KeyType, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to get manufacturer key: %w", err)
	}

	return manufacturerKey, nil
}

// signVoucherExternal signs voucher using external service (legacy compatibility)
func (s *VoucherSigningService) signVoucherExternal(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, serial, model string, extraData map[int][]byte) (*fdo.Voucher, error) {
	// External mode is an alias for HSM mode - they do the same thing
	return s.signVoucherHSM(ctx, voucher, nextOwner, serial, model, extraData)
}

// signVoucherHSM signs voucher using external HSM service
func (s *VoucherSigningService) signVoucherHSM(ctx context.Context, voucher *fdo.Voucher, nextOwner crypto.PublicKey, serial, model string, extraData map[int][]byte) (*fdo.Voucher, error) {
	// For external HSM mode, we need to create an external signer that intercepts the crypto.Sign calls
	// The HSM will receive digest blobs and return signatures

	// TODO: Load the manufacturer private key for this station
	// For now, we'll create a placeholder key
	// In a real implementation, this would be loaded from secure storage or HSM

	fmt.Printf("🔧 External HSM voucher signing with OVEExtra data\n")
	fmt.Printf("📋 OVEExtra data keys: %d\n", len(extraData))
	for key, value := range extraData {
		fmt.Printf("   Key %d: %d bytes\n", key, len(value))
	}

	// Create external HSM signer
	// The external signer needs the manufacturer public key that matches the voucher header
	// This is the public key corresponding to the private key held by the HSM
	manufacturerPubKey := voucher.Header.Val.ManufacturerKey

	// Convert protocol.PublicKey to crypto.PublicKey for the external signer
	cryptoPubKey, convertErr := protocolPublicKeyToCrypto(&manufacturerPubKey)
	if convertErr != nil {
		return nil, fmt.Errorf("failed to convert manufacturer public key: %w", convertErr)
	}

	externalSigner := NewExternalHSMSigner(cryptoPubKey, s.executor, s.config, s.stationID)

	// Use fdo.ExtendVoucher with the external signer
	// The external signer will intercept crypto.Sign calls and delegate to HSM
	var extendedVoucher *fdo.Voucher
	var err error

	// Type assert nextOwner to satisfy protocol.PublicKeyOrChain constraint
	switch key := nextOwner.(type) {
	case *ecdsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	case *rsa.PublicKey:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	case []*x509.Certificate:
		extendedVoucher, err = fdo.ExtendVoucher(voucher, externalSigner, key, extraData)
	default:
		return nil, fmt.Errorf("unsupported nextOwner key type: %T", nextOwner)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to extend voucher with external HSM: %w", err)
	}

	fmt.Printf("✅ Voucher extended successfully using external HSM\n")
	return extendedVoucher, nil
}
