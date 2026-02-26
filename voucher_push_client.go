// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/fido-device-onboard/go-fdo/transfer"
)

// VoucherPushClient wraps the library's transfer.HTTPPushSender,
// adapting its interface to the app's file-path-based push workflow.
type VoucherPushClient struct {
	sender *transfer.HTTPPushSender
}

// NewVoucherPushClient constructs a push client with sensible defaults.
func NewVoucherPushClient() *VoucherPushClient {
	return &VoucherPushClient{
		sender: transfer.NewHTTPPushSender(),
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

	raw, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read voucher file %s: %w", filePath, err)
	}

	data := &transfer.VoucherData{
		VoucherInfo: transfer.VoucherInfo{
			GUID:         guid,
			SerialNumber: serial,
			ModelNumber:  model,
		},
		Raw: raw,
	}

	pushDest := transfer.PushDestination{
		URL:   dest.URL,
		Token: dest.Token,
	}

	return c.sender.Push(ctx, pushDest, data)
}
