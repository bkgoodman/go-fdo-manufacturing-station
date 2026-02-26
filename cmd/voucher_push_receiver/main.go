// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo/transfer"
)

func main() {
	var (
		addr    = flag.String("addr", ":9090", "address to listen on")
		dir     = flag.String("dir", "/tmp/fdo_push_receiver", "directory to store received vouchers")
		token   = flag.String("token", "", "expected bearer token (optional)")
		logPath = flag.String("log", "/tmp/fdo_push_receiver.log", "log file path")
	)
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("failed to create receiver directory: %v", err)
	}

	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				log.Printf("failed to close log file: %v", err)
			}
		}()
		log.SetOutput(f)
	}

	store := &fileVoucherStore{dir: *dir}
	expectedToken := *token

	receiver := &transfer.HTTPPushReceiver{
		Store: store,
		Authenticate: func(r *http.Request) bool {
			if expectedToken == "" {
				return true
			}
			auth := r.Header.Get("Authorization")
			return strings.EqualFold(auth, "Bearer "+expectedToken)
		},
		OnReceive: func(_ context.Context, data *transfer.VoucherData, path string) {
			log.Printf("received voucher guid=%s serial=%s model=%s path=%s",
				data.GUID, data.SerialNumber, data.ModelNumber, path)
		},
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           receiver,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Printf("voucher push receiver listening on %s, dir=%s", *addr, *dir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("receiver server error: %v", err)
	}
}

// fileVoucherStore implements transfer.VoucherStore by writing vouchers to disk.
type fileVoucherStore struct {
	dir string
}

func (s *fileVoucherStore) Save(_ context.Context, data *transfer.VoucherData) (string, error) {
	voucherPath := filepath.Join(s.dir, data.GUID+".fdoov")
	if err := os.WriteFile(voucherPath, data.Raw, 0o644); err != nil {
		return "", fmt.Errorf("failed to write voucher: %w", err)
	}

	meta := map[string]string{
		"guid":        data.GUID,
		"serial":      data.SerialNumber,
		"model":       data.ModelNumber,
		"received_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	metaPath := filepath.Join(s.dir, data.GUID+".json")
	if err := os.WriteFile(metaPath, metaBytes, 0o644); err != nil {
		log.Printf("warning: failed to write metadata: %v", err)
	}

	return voucherPath, nil
}

func (s *fileVoucherStore) Load(_ context.Context, _ string) (*transfer.VoucherData, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *fileVoucherStore) GetVoucher(_ context.Context, _ []byte, _ string) (*transfer.VoucherData, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *fileVoucherStore) List(_ context.Context, _ []byte, _ transfer.ListFilter) (*transfer.VoucherListResponse, error) {
	return nil, fmt.Errorf("not implemented")
}

func (s *fileVoucherStore) Delete(_ context.Context, _ string) error {
	return fmt.Errorf("not implemented")
}
