package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := filepath.Join("testdata")
	os.MkdirAll(dir, 0755)

	// Root CA
	rootKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	rootDER, _ := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	rootCert, _ := x509.ParseCertificate(rootDER)
	writePEM(filepath.Join(dir, "test-root-ca.pem"), "CERTIFICATE", rootDER)
	writeKey(filepath.Join(dir, "test-root-ca.key"), rootKey)
	fmt.Println("generated: test-root-ca.pem + test-root-ca.key")

	// Issuing CA
	issKey, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	issTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Issuing CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}
	issDER, _ := x509.CreateCertificate(rand.Reader, issTmpl, rootCert, &issKey.PublicKey, rootKey)
	issCert, _ := x509.ParseCertificate(issDER)
	writePEM(filepath.Join(dir, "test-ca.pem"), "CERTIFICATE", issDER)
	writeKey(filepath.Join(dir, "test-ca.key"), issKey)
	fmt.Println("generated: test-ca.pem + test-ca.key")

	// OCSP signer
	ocspKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ocspTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test OCSP Signer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
	}
	ocspDER, _ := x509.CreateCertificate(rand.Reader, ocspTmpl, issCert, &ocspKey.PublicKey, issKey)
	writePEM(filepath.Join(dir, "test-ocsp.pem"), "CERTIFICATE", ocspDER)
	writeKey(filepath.Join(dir, "test-ocsp.key"), ocspKey)
	fmt.Println("generated: test-ocsp.pem + test-ocsp.key")

	// TSA signer
	tsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tsaTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "Test TSA Signer"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	tsaDER, _ := x509.CreateCertificate(rand.Reader, tsaTmpl, issCert, &tsaKey.PublicKey, issKey)
	writePEM(filepath.Join(dir, "test-tsa.pem"), "CERTIFICATE", tsaDER)
	writeKey(filepath.Join(dir, "test-tsa.key"), tsaKey)
	fmt.Println("generated: test-tsa.pem + test-tsa.key")

	// Sample CSR
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "test.example.com", Organization: []string{"Example"}},
		DNSNames: []string{"test.example.com", "www.test.example.com"},
	}
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, csrTmpl, csrKey)
	writePEM(filepath.Join(dir, "sample-csr.pem"), "CERTIFICATE REQUEST", csrDER)
	fmt.Println("generated: sample-csr.pem")

	fmt.Println("\ndone.")
}

func writePEM(path, typ string, der []byte) {
	f, _ := os.Create(path)
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}

func writeKey(path string, key *ecdsa.PrivateKey) {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	f, _ := os.Create(path)
	defer f.Close()
	pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
}
