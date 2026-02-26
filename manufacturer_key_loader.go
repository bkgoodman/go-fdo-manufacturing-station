// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"crypto"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo/did"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

// LoadManufacturerPublicKey loads the manufacturer public key from a PEM file
func LoadManufacturerPublicKey(filename string) (protocol.PublicKey, error) {
	if filename == "" {
		return protocol.PublicKey{}, fmt.Errorf("manufacturer public key file not specified")
	}

	pemData, err := os.ReadFile(filename)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to read manufacturer public key file: %w", err)
	}

	pubKey, err := did.LoadPublicKeyPEM(pemData)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to parse public key from %s: %w", filename, err)
	}

	keyType, err := protocol.KeyTypeFromPublicKey(pubKey)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to determine key type: %w", err)
	}

	protoKey, err := encodePublicKey(keyType, protocol.X509KeyEnc, pubKey, nil)
	if err != nil {
		return protocol.PublicKey{}, fmt.Errorf("failed to encode protocol public key: %w", err)
	}

	fmt.Printf("Loaded manufacturer public key from %s\n", filename)
	return *protoKey, nil
}

// protocolPublicKeyToCrypto converts a protocol.PublicKey to crypto.PublicKey
func protocolPublicKeyToCrypto(protocolPubKey *protocol.PublicKey) (crypto.PublicKey, error) {
	return protocolPubKey.Public()
}
