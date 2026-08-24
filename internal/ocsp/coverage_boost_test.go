package ocsp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func newTestLeafCert(t *testing.T, caCert *x509.Certificate, caKey crypto.Signer) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(500),
		Subject:      pkix.Name{CommonName: "leaf.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestCacheCleanup(t *testing.T) {
	c := NewCache(10, 5*time.Millisecond)
	c.Set("k1", []byte("v1"))
	got, ok := c.Get("k1")
	if !ok || string(got) != "v1" {
		t.Fatal("expected hit before expiry")
	}
	time.Sleep(20 * time.Millisecond)
	_, ok = c.Get("k1")
	if ok {
		t.Fatal("expected miss after TTL expiry (cleanup should remove)")
	}
}

func TestCacheCleanup_Concurrent(t *testing.T) {
	c := NewCache(100, 1*time.Millisecond)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			key := string(rune('a' + n%26))
			c.Set(key, []byte{byte(n)})
			_, _ = c.Get(key)
		}(i)
	}
	wg.Wait()
	time.Sleep(20 * time.Millisecond)
}

func TestExtractNonce_Present(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert, _ := newTestLeafCert(t, caCert, caKey)

	reqDER, err := ocsp.CreateRequest(leafCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	type rawTBSRequest struct {
		Version     int              `asn1:"explicit,tag:0,default:0,optional"`
		Requestor   asn1.RawValue   `asn1:"explicit,tag:1,optional"`
		RequestList []asn1.RawValue
		Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	type rawOCSPReq struct {
		TBSRequest rawTBSRequest
		Signature  asn1.RawValue `asn1:"explicit,tag:0,optional"`
	}
	var raw rawOCSPReq
	if _, err := asn1.Unmarshal(reqDER, &raw); err != nil {
		t.Fatal(err)
	}
	raw.TBSRequest.Extensions = append(raw.TBSRequest.Extensions, pkix.Extension{
		Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2},
		Value: []byte{0x04, 0x10, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
	})
	reqDER, err = asn1.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}

	got := extractNonce(reqDER)
	if len(got) == 0 {
		t.Fatal("expected non-nil nonce from request with nonce")
	}
}

func TestExtractNonce_Absent(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert, _ := newTestLeafCert(t, caCert, caKey)

	reqDER, err := ocsp.CreateRequest(leafCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := extractNonce(reqDER)
	if got != nil {
		t.Fatalf("expected nil nonce, got %v", got)
	}
}

func TestExtractNonce_InvalidDER(t *testing.T) {
	got := extractNonce([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	if got != nil {
		t.Fatalf("expected nil for invalid DER, got %v", got)
	}
}

func TestExtractRequestorName_Present(t *testing.T) {
	// Build a base OCSP request, then manually inject requestor field
	caCert, caKey := newTestCA(t)
	leafCert, _ := newTestLeafCert(t, caCert, caKey)
	baseDER, err := ocsp.CreateRequest(leafCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Parse TBSRequest from the base request using our raw struct
	var baseRaw rawOCSPReq
	if _, err := asn1.Unmarshal(baseDER, &baseRaw); err != nil {
		t.Fatal(err)
	}

	// Build requestor GeneralName [4] IMPLICIT: SEQUENCE { OID 2.5.4.3, UTF8String "test-req" }
	attrSeq, _ := asn1.Marshal(struct {
		Type  asn1.ObjectIdentifier
		Value asn1.RawValue
	}{
		Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
		Value: asn1.RawValue{Tag: 12, Bytes: []byte("test-req")},
	})
	generalNameDER := wrapImplicitTag(4, attrSeq)

	// Build the TBSRequest with requestorName and requestList
	var tbsContent []byte

	// [1] EXPLICIT wrapping GeneralName [4] IMPLICIT
	requestorDER := wrapExplicitTag(1, generalNameDER)
	tbsContent = append(tbsContent, requestorDER...)

	// requestList: marshal from parsed struct
	requestListDER, _ := asn1.Marshal(struct {
		Items []asn1.RawValue `asn1:"sequence"`
	}{Items: baseRaw.TBSRequest.RequestList})
	tbsContent = append(tbsContent, requestListDER...)

	tbsWrapped := wrapSequence(tbsContent)
	reqWrapped := wrapSequence(tbsWrapped)

	got := extractRequestorName(reqWrapped)
	if got == "" {
		t.Fatal("expected non-empty requestor name")
	}
}

func TestExtractRequestorName_Absent(t *testing.T) {
	caCert, caKey := newTestCA(t)
	leafCert, _ := newTestLeafCert(t, caCert, caKey)

	reqDER, err := ocsp.CreateRequest(leafCert, caCert, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := extractRequestorName(reqDER)
	if got != "" {
		t.Fatalf("expected empty requestor name, got %q", got)
	}
}

func TestExtractRequestorName_InvalidDER(t *testing.T) {
	got := extractRequestorName([]byte{0xFF, 0xFF})
	if got != "" {
		t.Fatalf("expected empty string for invalid DER, got %q", got)
	}
}

func wrapImplicitTag(tag byte, content []byte) []byte {
	return append([]byte{0xa0 | tag, byte(len(content))}, content...)
}

func wrapExplicitTag(tag byte, content []byte) []byte {
	return append([]byte{0xa0 | tag, byte(len(content))}, content...)
}

func wrapSequence(content []byte) []byte {
	if len(content) < 128 {
		return append([]byte{0x30, byte(len(content))}, content...)
	}
	lengthBytes := asn1LengthBytes(len(content))
	return append(append([]byte{0x30}, lengthBytes...), content...)
}

func asn1LengthBytes(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}
	var buf []byte
	for length > 0 {
		buf = append([]byte{byte(length & 0xff)}, buf...)
		length >>= 8
	}
	return append([]byte{byte(0x80 | len(buf))}, buf...)
}
