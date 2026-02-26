// SPDX-FileCopyrightText: (C) 2026 Dell Technologies
// SPDX-License-Identifier: Apache 2.0
// Author: Brad Goodman

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fido-device-onboard/go-fdo/did"
)

// TestDIDKeyResolution tests did:key resolution using the library's ParseDIDKey.
func TestDIDKeyResolution(t *testing.T) {
	ctx := context.Background()

	t.Run("P256", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		didURI := testECPublicKeyToDIDKey(t, &key.PublicKey)
		t.Logf("did:key URI: %s", didURI)

		resolver := NewDIDResolver(nil, nil)
		pubKey, voucherURL, err := resolver.ResolveDIDKey(ctx, didURI)
		if err != nil {
			t.Fatalf("ResolveDIDKey failed: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}
		if voucherURL != "" {
			t.Errorf("did:key should have no voucher URL, got %q", voucherURL)
		}

		// Verify the key matches
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
		}
		if ecPub.X.Cmp(key.X) != 0 || ecPub.Y.Cmp(key.Y) != 0 {
			t.Error("resolved key does not match original")
		}
	})

	t.Run("P384", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		didURI := testECPublicKeyToDIDKey(t, &key.PublicKey)
		t.Logf("did:key URI: %s", didURI)

		resolver := NewDIDResolver(nil, nil)
		pubKey, _, err := resolver.ResolveDIDKey(ctx, didURI)
		if err != nil {
			t.Fatalf("ResolveDIDKey failed: %v", err)
		}
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
		}
		if ecPub.X.Cmp(key.X) != 0 || ecPub.Y.Cmp(key.Y) != 0 {
			t.Error("resolved key does not match original")
		}
	})

	t.Run("InvalidDIDKey", func(t *testing.T) {
		resolver := NewDIDResolver(nil, nil)
		_, _, err := resolver.ResolveDIDKey(ctx, "did:key:zInvalid")
		if err == nil {
			t.Fatal("expected error for invalid did:key")
		}
	})
}

// TestDIDWebResolution tests did:web resolution via a local httptest server.
func TestDIDWebResolution(t *testing.T) {
	ctx := context.Background()

	// Generate a test key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	voucherRecipientURL := "https://owner.example.com/api/v1/vouchers"

	t.Run("WithVoucherRecipient", func(t *testing.T) {
		// Create a DID document using the library
		doc, err := did.NewDocument("did:web:localhost", key.Public(), voucherRecipientURL, "")
		if err != nil {
			t.Fatal(err)
		}
		docJSON, err := doc.JSON()
		if err != nil {
			t.Fatal(err)
		}

		// Serve it via httptest
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/did.json" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/did+ld+json")
			if _, err := w.Write(docJSON); err != nil {
				t.Logf("write error: %v", err)
			}
		}))
		defer srv.Close()

		// Extract host:port from server URL (e.g., "127.0.0.1:12345")
		host := strings.TrimPrefix(srv.URL, "http://")

		// Build did:web URI — colons in host must be percent-encoded
		didURI := did.WebDID(host, "")
		t.Logf("did:web URI: %s (server: %s)", didURI, srv.URL)

		// Override the document ID to match the did:web URI the resolver expects
		doc.ID = didURI
		doc.VerificationMethod[0].Controller = didURI
		doc.VerificationMethod[0].ID = didURI + "#key-1"
		doc.Authentication = []string{didURI + "#key-1"}
		doc.AssertionMethod = []string{didURI + "#key-1"}
		if len(doc.Service) > 0 {
			doc.Service[0].ID = didURI + "#voucher-recipient"
		}
		docJSON, _ = doc.JSON()

		// Re-serve with updated doc
		srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/did.json" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/did+ld+json")
			if _, err := w.Write(docJSON); err != nil {
				t.Logf("write error: %v", err)
			}
		})

		resolver := NewDIDResolver(nil, nil)
		resolver.SetInsecureHTTP(true)

		pubKey, resolvedURL, err := resolver.ResolveDIDKey(ctx, didURI)
		if err != nil {
			t.Fatalf("ResolveDIDKey failed: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}

		// Verify key matches
		ecPub, ok := pubKey.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PublicKey, got %T", pubKey)
		}
		if ecPub.X.Cmp(key.X) != 0 || ecPub.Y.Cmp(key.Y) != 0 {
			t.Error("resolved key does not match original")
		}

		if resolvedURL != voucherRecipientURL {
			t.Errorf("expected voucher recipient URL %q, got %q", voucherRecipientURL, resolvedURL)
		}
	})

	t.Run("NoVoucherRecipient", func(t *testing.T) {
		// DID document without service endpoints
		doc, err := did.NewDocument("did:web:localhost", key.Public(), "", "")
		if err != nil {
			t.Fatal(err)
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Update the doc ID to match the resolver's expected DID
			host := strings.TrimPrefix("http://"+r.Host, "http://")
			docURI := did.WebDID(host, "")
			doc.ID = docURI
			doc.VerificationMethod[0].Controller = docURI
			doc.VerificationMethod[0].ID = docURI + "#key-1"
			doc.Authentication = []string{docURI + "#key-1"}
			doc.AssertionMethod = []string{docURI + "#key-1"}

			docJSON, _ := doc.JSON()
			w.Header().Set("Content-Type", "application/did+ld+json")
			if _, err := w.Write(docJSON); err != nil {
				return
			}
		}))
		defer srv.Close()

		host := strings.TrimPrefix(srv.URL, "http://")
		didURI := did.WebDID(host, "")

		resolver := NewDIDResolver(nil, nil)
		resolver.SetInsecureHTTP(true)

		pubKey, resolvedURL, err := resolver.ResolveDIDKey(ctx, didURI)
		if err != nil {
			t.Fatalf("ResolveDIDKey failed: %v", err)
		}
		if pubKey == nil {
			t.Fatal("expected non-nil public key")
		}
		if resolvedURL != "" {
			t.Errorf("expected empty voucher URL, got %q", resolvedURL)
		}
	})

	t.Run("ServerError", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "internal error", http.StatusInternalServerError)
		}))
		defer srv.Close()

		host := strings.TrimPrefix(srv.URL, "http://")
		didURI := did.WebDID(host, "")

		resolver := NewDIDResolver(nil, nil)
		resolver.SetInsecureHTTP(true)

		_, _, err := resolver.ResolveDIDKey(ctx, didURI)
		if err == nil {
			t.Fatal("expected error for 500 response")
		}
	})
}

// TestDIDUnsupportedMethod tests that unsupported DID methods return an error.
func TestDIDUnsupportedMethod(t *testing.T) {
	resolver := NewDIDResolver(nil, nil)
	_, _, err := resolver.ResolveDIDKey(context.Background(), "did:example:123")
	if err == nil {
		t.Fatal("expected error for unsupported DID method")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected 'unsupported' in error, got: %v", err)
	}
}

// TestDIDDisabledResolution tests that resolution returns an error when disabled.
func TestDIDDisabledResolution(t *testing.T) {
	resolver := NewDIDResolver(nil, &DIDCache{Enabled: false})
	_, _, err := resolver.ResolveDIDKey(context.Background(), "did:key:z123")
	if err == nil {
		t.Fatal("expected error when DID resolution is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Errorf("expected 'disabled' in error, got: %v", err)
	}
}

// TestDIDIntegrationWithVoucher tests end-to-end DID integration with vouchers
func TestDIDIntegrationWithVoucher(t *testing.T) {
	t.Log("DID voucher integration tests not yet implemented")
}

// --- test helpers ---

// testECPublicKeyToDIDKey encodes an ECDSA public key as a did:key URI.
func testECPublicKeyToDIDKey(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()

	var prefix []byte
	switch pub.Curve {
	case elliptic.P256():
		prefix = []byte{0x80, 0x24}
	case elliptic.P384():
		prefix = []byte{0x81, 0x24}
	default:
		t.Fatalf("unsupported curve: %v", pub.Curve.Params().Name)
	}

	// Compress the point (SEC1 format)
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	compressed := make([]byte, 1+byteLen)
	if pub.Y.Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	copy(compressed[1+byteLen-len(xBytes):], xBytes)

	data := append(prefix, compressed...)
	encoded := testEncodeBase58BTC(data)
	return "did:key:z" + encoded
}

// testEncodeBase58BTC encodes bytes as base58-btc (Bitcoin alphabet).
func testEncodeBase58BTC(data []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	x := new(big.Int).SetBytes(data)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}

	for _, b := range data {
		if b != 0 {
			break
		}
		result = append(result, '1')
	}

	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return string(result)
}
