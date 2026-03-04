// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"time"
)

// VoucherSigningConfig contains configuration for voucher signing
type VoucherSigningConfig struct {
	Mode                      string        `yaml:"mode"`                         // "internal" | "external"
	OwnerKeyType              string        `yaml:"owner_key_type"`               // for internal mode
	FirstTimeInit             bool          `yaml:"first_time_init"`              // for internal mode
	ExternalCommand           string        `yaml:"external_command"`             // for external mode
	ExternalTimeout           time.Duration `yaml:"external_timeout"`             // for external mode
	ManufacturerPublicKeyFile string        `yaml:"manufacturer_public_key_file"` // PEM file with manufacturer public key
}

// OVEExtraDataConfig contains configuration for OVEExtra data
type OVEExtraDataConfig struct {
	Enabled         bool          `yaml:"enabled"`
	ExternalCommand string        `yaml:"external_command"` // script to call for extra data
	Timeout         time.Duration `yaml:"timeout"`
}

// DIDCache configuration for DID resolution caching
type DIDCache struct {
	Enabled         bool          `yaml:"enabled"`
	RefreshInterval time.Duration `yaml:"refresh_interval"` // Time between refresh attempts
	MaxAge          time.Duration `yaml:"max_age"`          // Force refresh if older than this
	FailureBackoff  time.Duration `yaml:"failure_backoff"`  // Backoff after failed refresh
	PurgeUnused     time.Duration `yaml:"purge_unused"`     // Delete if unused for this duration
	PurgeOnStartup  bool          `yaml:"purge_on_startup"` // Run purge cleanup on server start
}

// VoucherConfig contains configuration for voucher management
type VoucherConfig struct {
	PersistToDB bool `yaml:"persist_to_db"`

	// New voucher signing configuration
	VoucherSigning VoucherSigningConfig `yaml:"voucher_signing"`

	// OVEExtra data configuration
	OVEExtraData OVEExtraDataConfig `yaml:"ove_extra_data"`

	// Save vouchers to disk configuration
	SaveToDisk struct {
		Directory string `yaml:"directory"` // Directory to save vouchers (empty = disabled)
	} `yaml:"save_to_disk"`

	// Owner signover configuration
	OwnerSignover struct {
		Mode            string        `yaml:"mode"`              // "static" or "dynamic"
		StaticPublicKey string        `yaml:"static_public_key"` // PEM-encoded public key for static mode
		StaticDID       string        `yaml:"static_did"`        // DID URI for static mode
		ExternalCommand string        `yaml:"external_command"`  // Command for dynamic mode
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"owner_signover"`

	// DID cache configuration
	DIDCache DIDCache `yaml:"did_cache"`

	VoucherUpload struct {
		Enabled         bool          `yaml:"enabled"`
		ExternalCommand string        `yaml:"external_command"`
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"voucher_upload"`

	VoucherFiles struct {
		Directory string `yaml:"directory"`
	} `yaml:"voucher_files"`

	DestinationCallback struct {
		Enabled         bool          `yaml:"enabled"`
		ExternalCommand string        `yaml:"external_command"`
		Timeout         time.Duration `yaml:"timeout"`
	} `yaml:"destination_callback"`

	PushService struct {
		Enabled            bool          `yaml:"enabled"`
		URL                string        `yaml:"url"`
		AuthToken          string        `yaml:"auth_token"`
		AuthMethod         string        `yaml:"auth_method"`       // "static" | "fdokeyauth" | "both"
		SupplierKeyType    string        `yaml:"supplier_key_type"` // Key type for FDOKeyAuth (e.g., "ec384")
		SupplierKeyFile    string        `yaml:"supplier_key_file"` // PEM file with supplier private key
		Mode               string        `yaml:"mode"`              // "fallback" or "send_always"
		RetainFiles        bool          `yaml:"retain_files"`
		DeleteAfterSuccess bool          `yaml:"delete_after_success"`
		RetryInterval      time.Duration `yaml:"retry_interval"`
		MaxAttempts        int           `yaml:"max_attempts"`
	} `yaml:"push_service"`

	DIDPush struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"did_push"`

	RetryWorker struct {
		Enabled       bool          `yaml:"enabled"`
		RetryInterval time.Duration `yaml:"retry_interval"`
		MaxAttempts   int           `yaml:"max_attempts"`
	} `yaml:"retry_worker"`

	Retention struct {
		KeepIndefinitely bool          `yaml:"keep_indefinitely"`
		PurgeAfter       time.Duration `yaml:"purge_after"`
	} `yaml:"retention"`
}
