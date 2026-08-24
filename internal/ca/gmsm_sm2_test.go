//go:build gmsm

package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	gmx509 "github.com/tjfoc/gmsm/x509"

	"github.com/varwof/engine/db"
)

func TestSignSM2PureOID(t *testing.T) {
	// Generate an SM2 CA key and a self-signed SM2 CA cert (pure OID).
	caKey, err := generateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SM2 Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := createSM2Certificate(caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("self-sign CA: %v", err)
	}
	caCert, err := parseSM2Certificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf SM2 key + pub
	leafKey, err := generateSM2Key()
	if err != nil {
		t.Fatal(err)
	}

	d, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	sc := &SignConfig{
		DB:             d,
		CAKey:          caKey,
		CACert:         caCert,
		CAName:         "sm2-ca",
		SubjectPubKey:  leafKey.Public(),
		Profile:        ProfileTLSServer,
		CommonName:     "sm2.example.com",
		KeyType:        "sm2",
		Hash:           "sm3",
		Validity:       90 * 24 * time.Hour,
		DefaultCountry: "CN",
		DefaultOrg:     "example.com",
	}
	res, err := Sign(sc)
	if err != nil {
		t.Fatalf("sign SM2 leaf: %v", err)
	}

	// Parse with gmsm to assert the pure SM2-with-SM3 OID was used.
	gcert, err := gmx509.ParseCertificate(res.CertDER)
	if err != nil {
		t.Fatalf("gmsm parse: %v", err)
	}
	if gcert.SignatureAlgorithm != gmx509.SM2WithSM3 {
		t.Fatalf("expected SM2WithSM3 signature algorithm, got %v", gcert.SignatureAlgorithm)
	}

	// Stdlib cannot decode the SM2 curve, so parseSM2Certificate must still
	// return a cert object (with the raw DER intact) for downstream storage.
	if len(res.Cert.Raw) == 0 {
		t.Fatal("expected non-empty raw DER on returned cert")
	}
}

func TestKeyToPEMSM2RoundTrip(t *testing.T) {
	key, err := generateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := KeyToPEM(key)
	if err != nil {
		t.Fatalf("KeyToPEM: %v", err)
	}
	// The PEM must be loadable back as an SM2 signer.
	loaded, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("parse SM2 PEM: %v", err)
	}
	if !isSM2Key(loaded) {
		t.Fatal("expected loaded key to be an SM2 key")
	}
}
