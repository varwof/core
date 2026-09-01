// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestVerifySCT(t *testing.T) {
	// Build a real leaf cert.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CT Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Log key: ECDSA P-256. log_id = base64(SHA-256(SPKI)).
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	logID := base64.StdEncoding.EncodeToString(sum[:])

	// Sign the SCT input with the log key.
	timestamp := uint64(1700000000000)
	sctVersion := 0

	// Build the signed data exactly as VerifySCT reconstructs it.
	var signed bytes.Buffer
	signed.WriteByte(byte(sctVersion))
	signed.WriteByte(0) // signature_type = certificate_timestamp
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	signed.Write(tsBuf[:])
	var entryBuf [2]byte
	binary.BigEndian.PutUint16(entryBuf[:], 0) // entry_type = x509_entry
	signed.Write(entryBuf[:])
	var certLen [3]byte
	certLen[0] = byte(len(leafCert.Raw) >> 16)
	certLen[1] = byte(len(leafCert.Raw) >> 8)
	certLen[2] = byte(len(leafCert.Raw))
	signed.Write(certLen[:])
	signed.Write(leafCert.Raw)
	signed.Write([]byte{0, 0}) // extensions length 0

	digest := sha256.Sum256(signed.Bytes())
	sigASN1, err := ecdsa.SignASN1(rand.Reader, logKey, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sigDER := make([]byte, 4+len(sigASN1))
	sigDER[0] = 4 // hashAlgo SHA-256
	sigDER[1] = 3 // sigAlgo ECDSA
	sigDER[2] = byte(len(sigASN1) >> 8)
	sigDER[3] = byte(len(sigASN1))
	copy(sigDER[4:], sigASN1)

	tests := []struct {
		name       string
		cert       *x509.Certificate
		logID      string
		timestamp  uint64
		extensions string
		sig        []byte
		key        crypto.PublicKey
		wantErr    bool
	}{
		{
			name:       "valid real ECDSA SCT",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        sigDER,
			key:        &logKey.PublicKey,
			wantErr:    false,
		},
		{
			name:       "nil cert",
			cert:       nil,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        sigDER,
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "too short sig",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        []byte{4, 3},
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "invalid hash algorithm",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        []byte{5, 3, 0, 0},
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "invalid sig algorithm",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        []byte{4, 4, 0, 0},
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "sigLen exceeds data",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        []byte{4, 3, 0, 5, 1, 2},
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "wrong key fails",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        sigDER,
			key:        func() crypto.PublicKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return &k.PublicKey }(),
			wantErr:    true,
		},
		{
			name:       "nil key rejected",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        sigDER,
			key:        nil,
			wantErr:    true,
		},
		{
			name:       "log id mismatch",
			cert:       leafCert,
			logID:      base64.StdEncoding.EncodeToString(make([]byte, 32)),
			timestamp:  timestamp,
			extensions: "",
			sig:        sigDER,
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "tampered signature",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp,
			extensions: "",
			sig:        func() []byte { b := append([]byte(nil), sigDER...); b[len(b)-1] ^= 0x01; return b }(),
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
		{
			name:       "tampered timestamp",
			cert:       leafCert,
			logID:      logID,
			timestamp:  timestamp + 1,
			extensions: "",
			sig:        sigDER,
			key:        &logKey.PublicKey,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySCT(tt.cert, 0, tt.logID, tt.timestamp, tt.extensions, tt.sig, tt.key)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSubmitCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CT Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("successful submission", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			if r.Header.Get("X-API-Key") != "test-key" {
				t.Fatalf("expected X-API-Key header")
			}
			resp := ctAddChainResponse{
				SCT: ctSCT{
					SCTVersion: 1,
					ID:         "aGVsbG8=",
					Timestamp:  1234567890,
					Extensions: "",
					Signature:  "AAECAwQ=",
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		sctVersion, logID, timestamp, extensions, sigDER, err := SubmitCertificate(srv.URL, "test-key", leafCert, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatalf("SubmitCertificate: %v", err)
		}
		if sctVersion != 1 {
			t.Fatalf("expected sctVersion 1, got %d", sctVersion)
		}
		if logID != "aGVsbG8=" {
			t.Fatalf("expected logID aGVsbG8=, got %s", logID)
		}
		if timestamp != 1234567890 {
			t.Fatalf("expected timestamp 1234567890, got %d", timestamp)
		}
		if extensions != "" {
			t.Fatalf("expected empty extensions, got %q", extensions)
		}
		expectedSig, _ := base64.StdEncoding.DecodeString("AAECAwQ=")
		if string(sigDER) != string(expectedSig) {
			t.Fatalf("signature mismatch")
		}
	})

	t.Run("non-200 response", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("bad request"))
		}))
		defer srv.Close()

		_, _, _, _, _, err := SubmitCertificate(srv.URL, "", leafCert, nil)
		if err == nil {
			t.Fatal("expected error for non-200")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("not-json"))
		}))
		defer srv.Close()

		_, _, _, _, _, err := SubmitCertificate(srv.URL, "", leafCert, nil)
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})

	t.Run("missing signature", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := ctAddChainResponse{
				SCT: ctSCT{
					SCTVersion: 0,
					ID:         "",
					Timestamp:  0,
					Extensions: "",
					Signature:  "!!!invalid-base64!!!",
				},
			}
			json.NewEncoder(w).Encode(resp)
		}))
		defer srv.Close()

		_, _, _, _, _, err := SubmitCertificate(srv.URL, "", leafCert, nil)
		if err == nil {
			t.Fatal("expected error for bad base64 signature")
		}
	})
}

func TestParseCTLogPublicKey(t *testing.T) {
	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&logKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(spki)
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	if _, err := ParseCTLogPublicKey(b64); err != nil {
		t.Fatalf("parse base64 DER: %v", err)
	}
	if _, err := ParseCTLogPublicKey(string(pemBlock)); err != nil {
		t.Fatalf("parse PEM: %v", err)
	}
	if _, err := ParseCTLogPublicKey(""); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := ParseCTLogPublicKey("not-a-key"); err == nil {
		t.Fatal("expected error for garbage key")
	}
}

// L20: Ed25519 SCTs are signed over the raw signed-data bytes (RFC 6962 §3.2;
// Ed25519 is a pure scheme and is NOT SHA-256 pre-hashed). Previously the
// verifier pre-hashed, so every valid Ed25519-log SCT failed verification.
func TestVerifySCTEd25519RawMessageL20(t *testing.T) {
	// Minimal self-signed leaf cert.
	_, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "ed25519-leaf.test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, leafTmpl, leafKey.Public(), leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Ed25519 log key.
	logPub, logPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(logPub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	logID := base64.StdEncoding.EncodeToString(sum[:])

	timestamp := uint64(1700000000010)

	// Reconstruct the exact bytes VerifySCT signs over.
	var signed bytes.Buffer
	signed.WriteByte(0) // sct_version
	signed.WriteByte(0) // signature_type = certificate_timestamp
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp)
	signed.Write(tsBuf[:])
	var entryBuf [2]byte
	binary.BigEndian.PutUint16(entryBuf[:], 0) // entry_type = x509_entry
	signed.Write(entryBuf[:])
	var certLen [3]byte
	certLen[0] = byte(len(leafCert.Raw) >> 16)
	certLen[1] = byte(len(leafCert.Raw) >> 8)
	certLen[2] = byte(len(leafCert.Raw))
	signed.Write(certLen[:])
	signed.Write(leafCert.Raw)
	signed.Write([]byte{0, 0}) // extensions length 0

	// Sign the RAW bytes (RFC 6962 Ed25519 — no SHA-256 pre-hash).
	sig := ed25519.Sign(logPriv, signed.Bytes())

	// DigitallySigned: [hashAlgo=4 (SHA-256), sigAlgo=6 (Ed25519), len, sig].
	sigDER := make([]byte, 4+len(sig))
	sigDER[0] = 4
	sigDER[1] = sctSigEd25519
	sigDER[2] = byte(len(sig) >> 8)
	sigDER[3] = byte(len(sig))
	copy(sigDER[4:], sig)

	// Must now verify successfully (L20 fix).
	if err := VerifySCT(leafCert, 0, logID, timestamp, "", sigDER, logPub); err != nil {
		t.Fatalf("valid Ed25519 SCT rejected (L20 double-hash?): %v", err)
	}

	// A tampered signature must be rejected (still fails closed on real forgery).
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0x01
	badDER := make([]byte, 4+len(bad))
	badDER[0] = 4
	badDER[1] = sctSigEd25519
	badDER[2] = byte(len(bad) >> 8)
	badDER[3] = byte(len(bad))
	copy(badDER[4:], bad)
	if err := VerifySCT(leafCert, 0, logID, timestamp, "", badDER, logPub); err == nil {
		t.Fatal("tampered Ed25519 SCT accepted")
	}
}
