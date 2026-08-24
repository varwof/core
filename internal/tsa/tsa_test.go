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

func newTestSigner(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "TSA Test Signer",
			Organization: []string{"test"},
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func makeTestReq(t *testing.T) []byte {
	t.Helper()
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32), // zero hash
		},
		CertReq: true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseTimeStampReq(t *testing.T) {
	der := makeTestReq(t)
	req, err := ParseTimeStampReq(der)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != 1 {
		t.Fatalf("expected version 1, got %d", req.Version)
	}
	if !req.CertReq {
		t.Fatal("expected CertReq=true")
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDDigestSHA256) {
		t.Fatal("expected SHA-256 hash algorithm")
	}
}

func TestParseTimeStampReqInvalidVersion(t *testing.T) {
	req := TimeStampReq{
		Version:        2,
		MessageImprint: MessageImprint{HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256}},
	}
	der, _ := asn1.Marshal(req)
	_, err := ParseTimeStampReq(der)
	if err == nil {
		t.Fatal("expected error for version 2")
	}
}

func TestBuildTSTInfo(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
	}
	der, status, err := BuildTSTInfo(req, 42, &TSTInfoConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}

	var info TSTInfo
	_, err = asn1.Unmarshal(der, &info)
	if err != nil {
		t.Fatalf("unmarshal TSTInfo: %v", err)
	}
	if info.Version != 1 {
		t.Fatalf("expected version 1, got %d", info.Version)
	}
	if info.SerialNumber != 42 {
		t.Fatalf("expected serial 42, got %d", info.SerialNumber)
	}
	if len(info.GenTime.Bytes) == 0 {
		t.Fatal("empty genTime")
	}
	if info.Accuracy.Seconds != 0 {
		t.Fatalf("expected accuracy 0, got %d", info.Accuracy.Seconds)
	}
}

func TestSignRequest(t *testing.T) {
	cert, key := newTestSigner(t)
	reqDER := makeTestReq(t)

	cfg := &TSAConfig{
		SignerCert: cert,
		SignerKey:  key,
	}

	respDER, err := SignRequest(reqDER, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(respDER) == 0 {
		t.Fatal("empty response")
	}

	var resp TimeStampResp
	_, err = asn1.Unmarshal(respDER, &resp)
	if err != nil {
		t.Fatalf("unmarshal TimeStampResp: %v", err)
	}
	if len(resp.Status.StatusString) > 0 {
		t.Logf("Status strings: %v", resp.Status.StatusString)
	}
	if resp.Status.Status != 0 {
		t.Fatalf("expected status 0 (granted), got %d, msg: %v", resp.Status.Status, resp.Status.StatusString)
	}
}

func TestSignRequestBadHash(t *testing.T) {
	badOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: badOID},
			HashedMessage: make([]byte, 32),
		},
	}
	der, _ := asn1.Marshal(req)

	cert, key := newTestSigner(t)
	cfg := &TSAConfig{SignerCert: cert, SignerKey: key}

	respDER, err := SignRequest(der, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var resp TimeStampResp
	_, err = asn1.Unmarshal(respDER, &resp)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status.Status == 0 {
		t.Fatal("expected non-zero status for bad hash algorithm")
	}
}

func TestHandler(t *testing.T) {
	cert, key := newTestSigner(t)
	cfg := &TSAConfig{SignerCert: cert, SignerKey: key}
	h := NewHandler(cfg)

	reqDER := makeTestReq(t)
	httpReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(reqDER)))
	httpReq.Header.Set("Content-Type", "application/timestamp-query")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/timestamp-reply" {
		t.Fatalf("expected application/timestamp-reply, got %q", ct)
	}
	if len(w.Body.Bytes()) == 0 {
		t.Fatal("empty response body")
	}
}

func TestHandlerGet(t *testing.T) {
	cert, key := newTestSigner(t)
	h := NewHandler(&TSAConfig{SignerCert: cert, SignerKey: key})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", w.Code)
	}
}

func TestBuildTSTInfoPolicyOrdering(t *testing.T) {
	req := &TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: AlgorithmIdentifier{Algorithm: OIDDigestSHA256},
			HashedMessage: make([]byte, 32),
		},
	}
	policyOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	cfg := &TSTInfoConfig{
		Policy:          policyOID,
		Ordering:        true,
		AccuracySeconds: 1,
		AccuracyMillis:  500,
		AccuracyMicros:  250,
	}
	der, status, err := BuildTSTInfo(req, 1, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if status != 0 {
		t.Fatalf("expected status 0, got %d", status)
	}
	var info TSTInfo
	_, err = asn1.Unmarshal(der, &info)
	if err != nil {
		t.Fatalf("unmarshal TSTInfo: %v", err)
	}
	if !info.Policy.Equal(policyOID) {
		t.Fatalf("expected policy %v, got %v", policyOID, info.Policy)
	}
	if !info.Ordering {
		t.Fatal("expected ordering=true")
	}
	if info.Accuracy.Seconds != 1 || info.Accuracy.Millis != 500 || info.Accuracy.Micros != 250 {
		t.Fatalf("unexpected accuracy: %+v", info.Accuracy)
	}
}

func TestParseHashOID(t *testing.T) {
	oids := []asn1.ObjectIdentifier{OIDDigestSHA256, OIDDigestSHA384, OIDDigestSHA512}
	for _, oid := range oids {
		h, err := parseHashOID(oid)
		if err != nil {
			t.Fatalf("unexpected error for %v: %v", oid, err)
		}
		if h == 0 {
			t.Fatalf("zero hash for %v", oid)
		}
	}
	_, err := parseHashOID(asn1.ObjectIdentifier{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for unknown OID")
	}
}

func TestSerialFromBigInt(t *testing.T) {
	if s := SerialFromBigInt(big.NewInt(42)); s != 42 {
		t.Fatalf("expected 42, got %d", s)
	}
	if s := SerialFromBigInt(big.NewInt(0)); s != 0 {
		t.Fatalf("expected 0, got %d", s)
	}
	if s := SerialFromBigInt(big.NewInt(-1)); s != -1 {
		t.Fatalf("expected -1, got %d", s)
	}
}

func TestBuildTimeStampReq(t *testing.T) {
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}

	der, err := BuildTimeStampReq(crypto.SHA256, digest, nil)
	if err != nil {
		t.Fatalf("BuildTimeStampReq SHA256: %v", err)
	}
	var req TimeStampReq
	_, err = asn1.Unmarshal(der, &req)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Version != 1 {
		t.Fatalf("expected version 1, got %d", req.Version)
	}
	if !req.CertReq {
		t.Fatal("expected CertReq=true")
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDDigestSHA256) {
		t.Fatal("expected SHA-256 OID")
	}

	// With nonce
	der2, err := BuildTimeStampReq(crypto.SHA384, digest, big.NewInt(42))
	if err != nil {
		t.Fatalf("BuildTimeStampReq SHA384: %v", err)
	}
	var req2 TimeStampReq
	_, err = asn1.Unmarshal(der2, &req2)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req2.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDDigestSHA384) {
		t.Fatal("expected SHA-384 OID")
	}
	if req2.Nonce == nil || req2.Nonce.Int64() != 42 {
		t.Fatalf("expected nonce 42, got %v", req2.Nonce)
	}

	// SHA-512
	der3, err := BuildTimeStampReq(crypto.SHA512, digest, nil)
	if err != nil {
		t.Fatalf("BuildTimeStampReq SHA512: %v", err)
	}
	var req3 TimeStampReq
	_, err = asn1.Unmarshal(der3, &req3)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !req3.MessageImprint.HashAlgorithm.Algorithm.Equal(OIDDigestSHA512) {
		t.Fatal("expected SHA-512 OID")
	}
}

func TestHashOIDUnknown(t *testing.T) {
	// hashOID returns SHA-256 OID for unknown/unsupported hash
	oid := hashOID(crypto.MD5)
	if !oid.Equal(OIDDigestSHA256) {
		t.Fatal("expected SHA-256 OID fallback for MD5")
	}
}
