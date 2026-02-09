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
	"encoding/pem"
	"fmt"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/custom"
)

// VoucherCallbackService handles voucher-related callbacks
type VoucherCallbackService struct {
	config                *VoucherConfig
	ownerKeyService       *OwnerKeyService
	voucherSigningService *VoucherSigningService
	voucherUploadService  *VoucherUploadService
	voucherDiskService    *VoucherDiskService
	oveExtraDataService   *OVEExtraDataService
	signingKey            crypto.Signer
}

// NewVoucherCallbackService creates a new voucher callback service
func NewVoucherCallbackService(
	config *VoucherConfig,
	ownerKeyService *OwnerKeyService,
	voucherSigningService *VoucherSigningService,
	voucherUploadService *VoucherUploadService,
	voucherDiskService *VoucherDiskService,
	oveExtraDataService *OVEExtraDataService,
	signingKey crypto.Signer,
) *VoucherCallbackService {
	return &VoucherCallbackService{
		config:                config,
		ownerKeyService:       ownerKeyService,
		voucherSigningService: voucherSigningService,
		voucherUploadService:  voucherUploadService,
		voucherDiskService:    voucherDiskService,
		oveExtraDataService:   oveExtraDataService,
		signingKey:            signingKey,
	}
}

// BeforeVoucherPersist is called before a voucher is persisted to storage
func (v *VoucherCallbackService) BeforeVoucherPersist(ctx context.Context, sessionState interface{}, ov *fdo.Voucher) (bool, error) {
	// Get device info from session state
	serial, model, _ := v.getDeviceInfo(ctx, sessionState, ov)

	fmt.Printf("🔍 DEBUG: BeforeVoucherPersist called!\n")
	fmt.Printf("🔍 DEBUG: SessionState type: %T\n", sessionState)
	fmt.Printf("🔍 DEBUG: Voucher GUID: %x\n", ov.Header.Val.GUID[:])
	fmt.Printf("🔍 DEBUG: Voucher DeviceInfo: %s\n", ov.Header.Val.DeviceInfo)

	// Attempt to get device info from session state
	fmt.Printf("🔍 DEBUG: Attempting to get device info from session state...\n")
	if deviceSelfInfoStore, ok := sessionState.(interface {
		DeviceSelfInfo(context.Context) (*custom.DeviceMfgInfo, error)
	}); ok {
		fmt.Printf("🔍 DEBUG: Session state supports DeviceSelfInfo interface\n")
		devInfo, err := deviceSelfInfoStore.DeviceSelfInfo(ctx)
		if err == nil {
			fmt.Printf("🔍 DEBUG: Got device info from session: serial=%s, deviceInfo=%s\n", devInfo.SerialNumber, devInfo.DeviceInfo)
			serial = devInfo.SerialNumber
			model = devInfo.DeviceInfo
		} else {
			fmt.Printf("🔍 DEBUG: Error getting device info from session: %v\n", err)
		}
	} else {
		fmt.Printf("🔍 DEBUG: Session state does NOT support DeviceSelfInfo interface\n")
	}

	// Use GUID as fallback for serial if we couldn't get it from session
	if serial == "" {
		serial = fmt.Sprintf("%x", ov.Header.Val.GUID[:])
	}
	if model == "" {
		model = ov.Header.Val.DeviceInfo
	}

	guidStr := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

	fmt.Printf("🔍 DEBUG: Final values - serial=%s, model=%s, guid=%s\n", serial, model, guidStr)
	fmt.Printf("🔍 DEBUG: VoucherSigning.Mode=%v, VoucherUpload.Enabled=%v, PersistToDB=%v\n",
		v.config.VoucherSigning.Mode, v.config.VoucherUpload.Enabled, v.config.PersistToDB)

	// 1. Get owner signover key first (who we're signing TO)
	var nextOwner crypto.PublicKey
	var err error

	// Owner signover logic - get the public key of the recipient we're signing over TO
	switch v.config.OwnerSignover.Mode {
	case "static":
		// Static mode: use configured public key for all devices
		if v.config.OwnerSignover.StaticPublicKey != "" {
			nextOwner, err = parseStaticPublicKey(v.config.OwnerSignover.StaticPublicKey)
			if err != nil {
				return false, fmt.Errorf("failed to parse static public key: %w", err)
			}
			fmt.Printf("🔧 DEBUG: Using static owner key for signover\n")
		} else {
			fmt.Printf("🔧 DEBUG: No static public key configured - no owner signover\n")
		}

	case "dynamic":
		// Dynamic mode: per-device/customer public keys via callback
		if v.config.OwnerSignover.ExternalCommand != "" {
			ownerKey, err := v.ownerKeyService.GetOwnerKey(ctx, serial, model)
			if err != nil {
				return false, fmt.Errorf("failed to get dynamic owner key: %w", err)
			}
			// Convert to crypto.PublicKey
			nextOwner = ownerKey.(crypto.PublicKey)
			fmt.Printf("🔧 DEBUG: Using dynamic owner key for signover\n")
		} else {
			return false, fmt.Errorf("dynamic mode enabled but no external command configured")
		}

	default:
		fmt.Printf("🔧 DEBUG: Unsupported owner signover mode: %s - no owner signover\n", v.config.OwnerSignover.Mode)
	}

	// 2. Voucher signing if configured
	if v.config.VoucherSigning.Mode != "" {

		// Get OVEExtra data if configured
		var extraData map[int][]byte
		if v.oveExtraDataService != nil {
			extraData, err = v.oveExtraDataService.GetOVEExtraData(ctx, serial, model)
			if err != nil {
				fmt.Printf("⚠️  Failed to get OVEExtra data: %v\n", err)
				// Continue without extra data
				extraData = nil
			}
		}

		// Set session state for voucher signing service to access manufacturer keys
		v.voucherSigningService.SetSessionState(sessionState)

		// Always call voucher signing - default mode is "internal" which lets go-fdo handle it
		fmt.Printf("🔐 DEBUG: About to call SignVoucher with mode=%s, nextOwner=%v\n", v.config.VoucherSigning.Mode, nextOwner != nil)
		signedVoucher, err := v.voucherSigningService.SignVoucher(ctx, ov, nextOwner, serial, model, extraData)
		if err != nil {
			return false, fmt.Errorf("voucher signing failed: %w", err)
		}
		*ov = *signedVoucher // Replace with signed version
	} else {
		// No voucher signing configured, but we still might have owner signover
		if nextOwner != nil {
			// We have an owner key but no voucher signing - extend voucher directly
			var extended *fdo.Voucher

			// Use type assertion with the specific types that satisfy the constraint
			switch key := nextOwner.(type) {
			case *rsa.PublicKey:
				extended, err = fdo.ExtendVoucher(ov, nil, key, nil)
				if err != nil {
					return false, fmt.Errorf("failed to extend voucher to owner: %w", err)
				}
			case *ecdsa.PublicKey:
				extended, err = fdo.ExtendVoucher(ov, nil, key, nil)
				if err != nil {
					return false, fmt.Errorf("failed to extend voucher to owner: %w", err)
				}
			case []*x509.Certificate:
				extended, err = fdo.ExtendVoucher(ov, nil, key, nil)
				if err != nil {
					return false, fmt.Errorf("failed to extend voucher to owner: %w", err)
				}
			default:
				return false, fmt.Errorf("unsupported owner key type: %T", nextOwner)
			}

			*ov = *extended // Replace with signed version
			fmt.Printf("✅ Voucher extended to owner using %s mode (no voucher signing)\n", v.config.OwnerSignover.Mode)
		}
	}

	// 2. Voucher upload if configured
	if v.config.VoucherUpload.Enabled {
		if err := v.voucherUploadService.UploadVoucher(ctx, serial, model, guidStr, ov); err != nil {
			return false, fmt.Errorf("voucher upload failed: %w", err)
		}
	}

	// 3. Save to disk if configured
	if v.config.SaveToDisk.Directory != "" {
		if err := v.voucherDiskService.SaveVoucherToDisk(ov, serial); err != nil {
			fmt.Printf("⚠️  Failed to save voucher to disk: %v\n", err)
			// Don't fail the entire operation for disk save errors
		}
	}

	// 4. Return persistence decision
	result := v.config.PersistToDB
	fmt.Printf("🔍 DEBUG: Returning persist=%v from BeforeVoucherPersist\n", result)
	return result, nil
}

// getDeviceInfo extracts serial, model, and guid information from the session state or voucher
func (v *VoucherCallbackService) getDeviceInfo(ctx context.Context, sessionState interface{}, ov *fdo.Voucher) (string, string, string) {
	var serial, model string

	if sessionState != nil {
		if provider, ok := sessionState.(interface {
			DeviceSelfInfo(context.Context) (*custom.DeviceMfgInfo, error)
		}); ok {
			if info, err := provider.DeviceSelfInfo(ctx); err == nil && info != nil {
				serial = info.SerialNumber
				model = info.DeviceInfo
			}
		}
	}

	if ov != nil {
		if serial == "" {
			serial = fmt.Sprintf("%x", ov.Header.Val.GUID[:])
		}
		if model == "" {
			model = ov.Header.Val.DeviceInfo
		}
	}

	guid := ""
	if ov != nil {
		guid = fmt.Sprintf("%x", ov.Header.Val.GUID[:])
	}

	return serial, model, guid
}

// parseStaticPublicKey parses a PEM-encoded public key string into a crypto.PublicKey
func parseStaticPublicKey(pemKey string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try to parse as different key types
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert.PublicKey, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("unsupported public key format")
}
