// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the manufacturing station configuration
type Config struct {
	// Basic configuration
	Debug bool `yaml:"debug"`

	// Server configuration
	Server struct {
		Addr        string `yaml:"addr"`
		ExtAddr     string `yaml:"ext_addr"`
		UseTLS      bool   `yaml:"use_tls"`
		InsecureTLS bool   `yaml:"insecure_tls"`
	} `yaml:"server"`

	// Database configuration
	Database struct {
		Path     string `yaml:"path"`
		Password string `yaml:"password"`
	} `yaml:"database"`

	// Manufacturing configuration
	Manufacturing struct {
		DeviceCAKeyType      string `yaml:"device_ca_key_type"`
		OwnerKeyType         string `yaml:"owner_key_type"`
		GenerateCertificates bool   `yaml:"generate_certificates"`
		FirstTimeInit        bool   `yaml:"first_time_init"`
	} `yaml:"manufacturing"`

	// Rendezvous configuration
	Rendezvous struct {
		Entries []RendezvousEntry `yaml:"entries"`
	} `yaml:"rendezvous"`

	// Voucher management configuration
	VoucherManagement VoucherConfig `yaml:"voucher_management"`
}

// RendezvousEntry represents a single rendezvous endpoint
type RendezvousEntry struct {
	Host   string `yaml:"host"`   // IP address or DNS name
	Port   int    `yaml:"port"`   // Port number
	Scheme string `yaml:"scheme"` // "http" or "https"
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Debug: false,
		Server: struct {
			Addr        string `yaml:"addr"`
			ExtAddr     string `yaml:"ext_addr"`
			UseTLS      bool   `yaml:"use_tls"`
			InsecureTLS bool   `yaml:"insecure_tls"`
		}{
			Addr:        "localhost:8080",
			ExtAddr:     "",
			UseTLS:      false,
			InsecureTLS: false,
		},
		Database: struct {
			Path     string `yaml:"path"`
			Password string `yaml:"password"`
		}{
			Path:     "manufacturing.db",
			Password: "",
		},
		Manufacturing: struct {
			DeviceCAKeyType      string `yaml:"device_ca_key_type"`
			OwnerKeyType         string `yaml:"owner_key_type"`
			GenerateCertificates bool   `yaml:"generate_certificates"`
			FirstTimeInit        bool   `yaml:"first_time_init"`
		}{
			DeviceCAKeyType:      "ec384",
			OwnerKeyType:         "ec384",
			GenerateCertificates: true,
			FirstTimeInit:        false,
		},
		Rendezvous: struct {
			Entries []RendezvousEntry `yaml:"entries"`
		}{
			Entries: []RendezvousEntry{},
		},
		VoucherManagement: VoucherConfig{
			PersistToDB: true,
			VoucherSigning: VoucherSigningConfig{
				Mode:            "internal",       // "internal" = default, "hsm" = external HSM
				OwnerKeyType:    "ec384",          // for internal mode
				FirstTimeInit:   true,             // for internal mode - create key on first boot
				ExternalCommand: "",               // for hsm mode
				ExternalTimeout: 30 * time.Second, // for hsm mode
			},
			OwnerSignover: struct {
				Mode            string        `yaml:"mode"`              // "static" or "dynamic"
				StaticPublicKey string        `yaml:"static_public_key"` // PEM-encoded public key for static mode
				StaticDID       string        `yaml:"static_did"`        // DID URI for static mode
				ExternalCommand string        `yaml:"external_command"`  // Command for dynamic mode
				Timeout         time.Duration `yaml:"timeout"`
			}{
				Mode:            "static", // Default to static mode
				StaticPublicKey: "",       // Empty means no owner signover
				StaticDID:       "",       // Empty means no DID signover
				ExternalCommand: "",
				Timeout:         10 * time.Second,
			},
			VoucherUpload: struct {
				Enabled         bool          `yaml:"enabled"`
				ExternalCommand string        `yaml:"external_command"`
				Timeout         time.Duration `yaml:"timeout"`
			}{
				Enabled:         false,
				ExternalCommand: "",
				Timeout:         30 * time.Second,
			},
			DIDCache: DIDCache{
				Enabled:         false,              // Disabled by default
				RefreshInterval: 1 * time.Hour,      // Check for updates every hour
				MaxAge:          24 * time.Hour,     // Force refresh if older than 24h
				FailureBackoff:  1 * time.Hour,      // Backoff after failed refresh
				PurgeUnused:     7 * 24 * time.Hour, // Delete if not used for 7 days
				PurgeOnStartup:  false,              // Don't purge on startup by default
			},
		},
	}
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(configPath string) (*Config, error) {
	config := DefaultConfig()

	if configPath == "" {
		configPath = "manufacturing.cfg"
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Config file doesn't exist, return defaults
			return config, nil
		}
		return nil, fmt.Errorf("error reading config file %q: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("error parsing config file %q: %w", configPath, err)
	}

	return config, nil
}

// SaveConfig saves the configuration to a YAML file
func SaveConfig(config *Config, configPath string) error {
	if configPath == "" {
		configPath = "config.yaml"
	}

	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("error marshaling config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("error writing config file %q: %w", configPath, err)
	}

	return nil
}
