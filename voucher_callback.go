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
	"log/slog"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/custom"
	"github.com/fido-device-onboard/go-fdo/did"
)

// VoucherCallbackService handles voucher-related callbacks
type VoucherCallbackService struct {
	config                *VoucherConfig
	ownerKeyService       *OwnerKeyService
	voucherSigningService *VoucherSigningService
	voucherUploadService  *VoucherUploadService
	voucherDiskService    *VoucherDiskService
	voucherFileStore      *VoucherFileStore
	voucherPushService    *VoucherPushService
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
	voucherFileStore *VoucherFileStore,
	voucherPushService *VoucherPushService,
	oveExtraDataService *OVEExtraDataService,
	signingKey crypto.Signer,
) *VoucherCallbackService {
	return &VoucherCallbackService{
		config:                config,
		ownerKeyService:       ownerKeyService,
		voucherSigningService: voucherSigningService,
		voucherUploadService:  voucherUploadService,
		voucherDiskService:    voucherDiskService,
		voucherFileStore:      voucherFileStore,
		voucherPushService:    voucherPushService,
		oveExtraDataService:   oveExtraDataService,
		signingKey:            signingKey,
	}
}

// BeforeVoucherPersist is called before a voucher is persisted to storage
func (v *VoucherCallbackService) BeforeVoucherPersist(ctx context.Context, sessionState interface{}, ov *fdo.Voucher) (bool, error) {
	// Get device info from session state
	serial, model, _ := v.getDeviceInfo(ctx, sessionState, ov)

	slog.Debug("BeforeVoucherPersist called",
		"guid", fmt.Sprintf("%x", ov.Header.Val.GUID[:]),
		"device_info", ov.Header.Val.DeviceInfo)

	// Attempt to get device info from session state
	if deviceSelfInfoStore, ok := sessionState.(interface {
		DeviceSelfInfo(context.Context) (*custom.DeviceMfgInfo, error)
	}); ok {
		devInfo, err := deviceSelfInfoStore.DeviceSelfInfo(ctx)
		if err == nil {
			slog.Debug("got device info from session", "serial", devInfo.SerialNumber, "device_info", devInfo.DeviceInfo)
			serial = devInfo.SerialNumber
			model = devInfo.DeviceInfo
		} else {
			slog.Debug("error getting device info from session", "error", err)
		}
	}

	// Use GUID as fallback for serial if we couldn't get it from session
	if serial == "" {
		serial = fmt.Sprintf("%x", ov.Header.Val.GUID[:])
	}
	if model == "" {
		model = ov.Header.Val.DeviceInfo
	}

	guidStr := fmt.Sprintf("%x", ov.Header.Val.GUID[:])

	slog.Debug("voucher persist parameters",
		"serial", serial, "model", model, "guid", guidStr,
		"signing_mode", v.config.VoucherSigning.Mode,
		"upload_enabled", v.config.VoucherUpload.Enabled,
		"persist_to_db", v.config.PersistToDB)

	// Path to the voucher artifact saved for push transmission
	var voucherFilePath string

	// 1. Get owner signover key first (who we're signing TO)
	var nextOwner crypto.PublicKey
	var err error
	var didURL string // Store DID URL for upload

	// Owner signover logic - get the public key of the recipient we're signing over TO
	switch v.config.OwnerSignover.Mode {
	case "static":
		// Static mode: use configured public key or DID for all devices
		if v.config.OwnerSignover.StaticDID != "" {
			// Handle static DID
			slog.Debug("using static DID for signover", "did", v.config.OwnerSignover.StaticDID)
			// TODO: Implement DID resolution for static case
			slog.Warn("static DID resolution not yet implemented")
		} else if v.config.OwnerSignover.StaticPublicKey != "" {
			// Handle static PEM key (existing logic)
			nextOwner, err = parseStaticPublicKey(v.config.OwnerSignover.StaticPublicKey)
			if err != nil {
				return false, fmt.Errorf("failed to parse static public key: %w", err)
			}
			slog.Debug("using static owner key for signover")
		} else {
			slog.Debug("no static public key or DID configured - no owner signover")
		}

	case "dynamic":
		// Dynamic mode: per-device/customer public keys via callback
		if v.config.OwnerSignover.ExternalCommand != "" {
			ownerKeyResult, err := v.ownerKeyService.GetOwnerKey(ctx, serial, model)
			if err != nil {
				return false, fmt.Errorf("failed to get dynamic owner key: %w", err)
			}
			// Convert to crypto.PublicKey
			nextOwner = ownerKeyResult.PublicKey.(crypto.PublicKey)
			didURL = ownerKeyResult.DIDURL // Store DID URL for upload
			slog.Debug("using dynamic owner key for signover", "did_url", ownerKeyResult.DIDURL)
		} else {
			return false, fmt.Errorf("dynamic mode enabled but no external command configured")
		}

	default:
		slog.Debug("unsupported owner signover mode - no owner signover", "mode", v.config.OwnerSignover.Mode)
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
		slog.Debug("calling SignVoucher", "mode", v.config.VoucherSigning.Mode, "has_next_owner", nextOwner != nil)
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

	// Persist voucher to GUID-based file store now that signing is complete
	if v.voucherFileStore != nil {
		if path, err := v.voucherFileStore.SaveVoucher(ov); err != nil {
			fmt.Printf("⚠️  Failed to store voucher file for GUID %s: %v\n", guidStr, err)
		} else {
			voucherFilePath = path
			fmt.Printf("🗂️  Voucher stored at %s\n", path)
		}
	}

	// 2. Voucher upload if configured
	if v.config.VoucherUpload.Enabled {
		if err := v.voucherUploadService.UploadVoucher(ctx, serial, model, guidStr, ov, didURL); err != nil {
			return false, fmt.Errorf("voucher upload failed: %w", err)
		}
	}

	// 2b. Push via first-class service (metadata + HTTP push)
	if v.voucherPushService != nil && v.voucherPushService.Enabled() && voucherFilePath != "" {
		if err := v.voucherPushService.ProcessVoucher(ctx, serial, model, guidStr, voucherFilePath, didURL); err != nil {
			fmt.Printf("⚠️  Voucher push service failed: %v\n", err)
		}
	}

	// 3. Save to disk if configured
	if v.config.SaveToDisk.Directory != "" {
		if err := v.voucherDiskService.SaveVoucherToDisk(ov); err != nil {
			fmt.Printf("⚠️  Failed to save voucher to disk: %v\n", err)
			// Don't fail the entire operation for disk save errors
		}
	}

	// 4. Return persistence decision
	result := v.config.PersistToDB
	slog.Debug("BeforeVoucherPersist complete", "persist", result)
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
	return did.LoadPublicKeyPEM([]byte(pemKey))
}
