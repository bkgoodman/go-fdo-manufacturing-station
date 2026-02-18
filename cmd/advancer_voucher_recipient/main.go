// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fido-device-onboard/go-fdo"
	"github.com/fido-device-onboard/go-fdo/cbor"
	"github.com/fido-device-onboard/go-fdo/protocol"
)

type receiverConfig struct {
	addr    string
	dir     string
	token   string
	logPath string
}

func describeProtocolKey(label string, key *protocol.PublicKey) string {
	if key == nil {
		return ""
	}
	desc := fmt.Sprintf("%s type=%d encoding=%d body_len=%d", label, key.Type, key.Encoding, len(key.Body))
	if len(key.Body) == 0 {
		return desc
	}

	var decoded any
	if err := cbor.Unmarshal(key.Body, &decoded); err != nil {
		return fmt.Sprintf("%s body_decode_error=%v", desc, err)
	}

	switch v := decoded.(type) {
	case []byte:
		sum := sha256.Sum256(v)
		desc += fmt.Sprintf(" raw_len=%d sha256=%s", len(v), hex.EncodeToString(sum[:8]))
	case [][]byte:
		desc += fmt.Sprintf(" chain_len=%d", len(v))
		if len(v) > 0 {
			sum := sha256.Sum256(v[0])
			desc += fmt.Sprintf(" first_sha256=%s", hex.EncodeToString(sum[:8]))
		}
	case []any:
		desc += fmt.Sprintf(" elements=%d", len(v))
	default:
		desc += fmt.Sprintf(" body_type=%T", v)
	}

	return desc
}

type response struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func main() {
	cfg := parseFlags()
	if err := os.MkdirAll(cfg.dir, 0o755); err != nil {
		log.Fatalf("failed to create receiver directory: %v", err)
	}

	if cfg.logPath != "" {
		f, err := os.OpenFile(cfg.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	}

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handlePush(w, r, cfg) }),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	log.Printf("voucher push receiver listening on %s, dir=%s", cfg.addr, cfg.dir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("receiver server error: %v", err)
	}
}

func parseFlags() *receiverConfig {
	cfg := &receiverConfig{}
	flag.StringVar(&cfg.addr, "addr", ":9090", "address to listen on")
	flag.StringVar(&cfg.dir, "dir", "/tmp/fdo_push_receiver", "directory to store received vouchers")
	flag.StringVar(&cfg.token, "token", "", "expected bearer token (optional)")
	flag.StringVar(&cfg.logPath, "log", "/tmp/fdo_push_receiver.log", "log file path")
	flag.Parse()
	return cfg
}

func handlePush(w http.ResponseWriter, r *http.Request, cfg *receiverConfig) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if cfg.token != "" {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.EqualFold(auth, "Bearer "+cfg.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	if err := r.ParseMultipartForm(16 << 20); err != nil {
		http.Error(w, fmt.Sprintf("failed to parse multipart data: %v", err), http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("voucher")
	if err != nil {
		http.Error(w, "voucher file missing", http.StatusBadRequest)
		return
	}
	defer file.Close()

	guid := r.FormValue("guid")
	if guid == "" {
		guid = fmt.Sprintf("unknown-%d", time.Now().UnixNano())
	}
	serial := r.FormValue("serial")
	model := r.FormValue("model")

	voucherPath := filepath.Join(cfg.dir, fmt.Sprintf("%s.fdoov", guid))
	out, err := os.Create(voucherPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create output file: %v", err), http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		http.Error(w, fmt.Sprintf("failed to write voucher: %v", err), http.StatusInternalServerError)
		return
	}
	out.Close()

	meta := map[string]any{
		"guid":        guid,
		"serial":      serial,
		"model":       model,
		"filename":    header.Filename,
		"received_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.Marshal(meta)
	log.Printf("metadata %s", string(metaBytes))

	if err := introspectVoucher(voucherPath, guid); err != nil {
		log.Printf("voucher introspection failed guid=%s err=%v", guid, err)
	}
	log.Printf("received voucher guid=%s serial=%s model=%s size=%d destination=%s", guid, serial, model, header.Size, voucherPath)
	writeJSON(w, response{Status: "ok", Message: "voucher stored"})
}

func writeJSON(w http.ResponseWriter, resp response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func introspectVoucher(path string, guid string) error {
	voucher, err := fdo.ParseVoucherFile(path)
	if err != nil {
		return fmt.Errorf("parse voucher: %w", err)
	}

	h := voucher.Header.Val
	guidHex := fmt.Sprintf("%x", h.GUID[:])
	if guidHex != strings.ToLower(guid) {
		log.Printf("voucher guid mismatch? stored=%s parsed=%s", guid, guidHex)
	}
	entryCount := len(voucher.Entries)
	rvCount := len(h.RvInfo)
	var rvDirs int
	for _, directives := range h.RvInfo {
		rvDirs += len(directives)
	}

	log.Printf("voucher summary guid=%s version=%d device=%s entries=%d rv_sets=%d rv_directives=%d manufacturer_key_type=%d",
		guidHex, voucher.Version, h.DeviceInfo, entryCount, rvCount, rvDirs, h.ManufacturerKey.Type)
	if desc := describeProtocolKey("manufacturer", &h.ManufacturerKey); desc != "" {
		log.Printf("manufacturer_key %s", desc)
	}

	for idx, entry := range voucher.Entries {
		payload := entry.Payload.Val
		if desc := describeProtocolKey(fmt.Sprintf("entry[%d].public_key", idx), &payload.PublicKey); desc != "" {
			log.Printf("%s", desc)
		}
		if len(payload.PreviousHash.Value) > 0 {
			log.Printf("entry[%d] prev_hash_alg=%d value=%s", idx, payload.PreviousHash.Algorithm,
				hex.EncodeToString(payload.PreviousHash.Value))
		}
		if payload.Extra != nil && payload.Extra.Val != nil {
			log.Printf("entry[%d] extra_keys=%d", idx, len(payload.Extra.Val))
			for k, v := range payload.Extra.Val {
				log.Printf("entry[%d] extra[%d]=%dbytes", idx, k, len(v))
			}
		}
	}
	return nil
}
