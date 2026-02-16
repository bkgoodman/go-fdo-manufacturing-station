// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0

package main

import (
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
)

type receiverConfig struct {
	addr    string
	dir     string
	token   string
	logPath string
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

	meta := map[string]string{
		"guid":        guid,
		"serial":      serial,
		"model":       model,
		"filename":    header.Filename,
		"received_at": time.Now().UTC().Format(time.RFC3339),
	}
	metaBytes, _ := json.MarshalIndent(meta, "", "  ")
	_ = os.WriteFile(filepath.Join(cfg.dir, fmt.Sprintf("%s.json", guid)), metaBytes, 0o644)

	log.Printf("received voucher guid=%s serial=%s model=%s size=%d destination=%s", guid, serial, model, header.Size, voucherPath)
	writeJSON(w, response{Status: "ok", Message: "voucher stored"})
}

func writeJSON(w http.ResponseWriter, resp response) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
