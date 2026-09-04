// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package tsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTSAHandler_GetNotAllowed(t *testing.T) {
	cert, key := newTestSigner(t)
	h := NewHandler(&TSAConfig{SignerCert: cert, SignerKey: key})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/tsa", nil)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestTSAHandler_PostValid(t *testing.T) {
	cert, key := newTestSigner(t)
	h := NewHandler(&TSAConfig{SignerCert: cert, SignerKey: key})

	reqDER := makeTestReq(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsa", strings.NewReader(string(reqDER)))
	r.Header.Set("Content-Type", "application/timestamp-query")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/timestamp-reply" {
		t.Fatalf("expected application/timestamp-reply, got %q", ct)
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("empty response body")
	}
}

func TestTSAHandler_PostBadBody(t *testing.T) {
	cert, key := newTestSigner(t)
	h := NewHandler(&TSAConfig{SignerCert: cert, SignerKey: key})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/tsa", strings.NewReader("garbage body not a TSA request"))
	r.Header.Set("Content-Type", "application/timestamp-query")
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 (TSA error response), got %d", w.Code)
	}
	// Parse response to verify it's an error
	var resp TimeStampResp
	if _, err := asn1.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("expected valid TSA response: %v", err)
	}
	if resp.Status.Status == 0 {
		t.Fatal("expected non-zero TSA status for bad body")
	}
}

func TestTSAHandler_PutNotAllowed(t *testing.T) {
	cert, key := newTestSigner(t)
	h := NewHandler(&TSAConfig{SignerCert: cert, SignerKey: key})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/tsa", strings.NewReader("body"))
	h.ServeHTTP(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestBuildTSTInfo_Valid(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
		CertReq: true,
	}
	cfg := &TSTInfoConfig{
		Policy:          OIDTSAPolicyDefault,
		Ordering:        false,
		AccuracySeconds: 0,
		AccuracyMillis:  0,
		AccuracyMicros:  0,
	}
	der, status, err := BuildTSTInfo(req, 999, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
	if len(der) == 0 {
		t.Fatal("empty TSTInfo DER")
	}
	var info TSTInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if info.Version != 1 {
		t.Fatalf("expected version 1, got %d", info.Version)
	}
	if info.SerialNumber != 999 {
		t.Fatalf("expected serial 999, got %d", info.SerialNumber)
	}
}

func TestBuildTSTInfo_BadHashLength(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 16), // SHA-256 needs 32 bytes
		},
	}
	_, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
	if err == nil {
		t.Fatal("expected error for bad digest length")
	}
	if status != 2 {
		t.Fatalf("expected status 2, got %d", status)
	}
}

func TestBuildTSTInfo_CriticalExtension(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	extDER, err := asn1.Marshal(struct {
		ID       asn1.ObjectIdentifier
		Critical bool
		Value    []byte
	}{
		ID:       unknownOID,
		Critical: true,
		Value:    []byte{0x05, 0x00},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
		Extensions: []asn1.RawValue{{FullBytes: extDER}},
	}
	_, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
	if err == nil {
		t.Fatal("expected error for unknown critical extension")
	}
	if status != 2 {
		t.Fatalf("expected status 2, got %d", status)
	}
}

func TestBuildTSTInfo_UnrecognizedExtension(t *testing.T) {
	unknownOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	for _, critical := range []bool{true, false} {
		name := "non-critical"
		if critical {
			name = "critical"
		}
		t.Run(name, func(t *testing.T) {
			extDER, err := asn1.Marshal(struct {
				ID       asn1.ObjectIdentifier
				Critical bool
				Value    []byte
			}{
				ID:       unknownOID,
				Critical: critical,
				Value:    []byte{0x05, 0x00},
			})
			if err != nil {
				t.Fatal(err)
			}
			req := &TimeStampReq{
				Version: 1,
				MessageImprint: MessageImprint{
					HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
					HashedMessage: make([]byte, 32),
				},
				Extensions: []asn1.RawValue{{FullBytes: extDER}},
			}
			_, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
			if err == nil {
				t.Fatal("expected error for unrecognized extension")
			}
			if status != 2 {
				t.Fatalf("expected status 2, got %d", status)
			}
		})
	}
}

// The OCSP nonce is the one recognized request extension and must be accepted.
func TestBuildTSTInfo_NonceExtensionAccepted(t *testing.T) {
	extDER, err := asn1.Marshal(struct {
		ID       asn1.ObjectIdentifier
		Critical bool
		Value    []byte
	}{
		ID:       oidOCSPNonce,
		Critical: false,
		Value:    []byte{0x01, 0x02},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
		Extensions: []asn1.RawValue{{FullBytes: extDER}},
	}
	_, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
	if err != nil {
		t.Fatalf("nonce extension should be accepted: %v", err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
}

func TestBuildTSTInfo_WithNonce(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
		Nonce: big.NewInt(123456789),
	}
	der, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
	var info TSTInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatal(err)
	}
	if info.Nonce == nil || info.Nonce.Int64() != 123456789 {
		t.Fatalf("expected nonce 123456789, got %v", info.Nonce)
	}
}

func TestSignRequest_WithChain(t *testing.T) {
	// Create CA cert
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TSA CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Create TSA signer cert signed by CA
	signerTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "TSA Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	signerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signerDER, _ := x509.CreateCertificate(rand.Reader, signerTmpl, caCert, &signerKey.PublicKey, caKey)
	signerCert, _ := x509.ParseCertificate(signerDER)

	cfg := &TSAConfig{
		SignerCert: signerCert,
		SignerKey:  signerKey,
		Chain:      []*x509.Certificate{caCert},
	}

	reqDER := makeTestReq(t)
	respDER, err := SignRequest(reqDER, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(respDER) == 0 {
		t.Fatal("empty response")
	}

	var resp TimeStampResp
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status.Status != 0 {
		t.Fatalf("expected status 0, got %d: %v", resp.Status.Status, resp.Status.StatusString)
	}
}

func TestBuildTSTInfo_SHA384Digest(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA384},
			HashedMessage: make([]byte, 48),
		},
	}
	der, status, err := BuildTSTInfo(req, 42, &TSTInfoConfig{Policy: asn1.ObjectIdentifier{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
	var info TSTInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		t.Fatal(err)
	}
	if !info.Policy.Equal(asn1.ObjectIdentifier{1, 2, 3}) {
		t.Fatalf("expected policy {1,2,3}, got %v", info.Policy)
	}
}

func TestBuildTSTInfo_SHA512BadLength(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA512},
			HashedMessage: make([]byte, 32), // SHA-512 needs 64 bytes
		},
	}
	_, status, err := BuildTSTInfo(req, 1, &TSTInfoConfig{})
	if err == nil {
		t.Fatal("expected error for SHA-512 bad digest length")
	}
	if status != 2 {
		t.Fatalf("expected status 2, got %d", status)
	}
}

func TestSignRequest_BadVersion(t *testing.T) {
	cert, key := newTestSigner(t)
	req := TimeStampReq{
		Version: 2,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
	}
	der, _ := asn1.Marshal(req)
	cfg := &TSAConfig{SignerCert: cert, SignerKey: key}
	respDER, err := SignRequest(der, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var resp TimeStampResp
	if _, err := asn1.Unmarshal(respDER, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status.Status == 0 {
		t.Fatal("expected non-zero status for bad version")
	}
}

// compile-time checks
var _ = crypto.SHA256
