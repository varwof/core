package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/varwof/engine/db"
)

const DefaultCACertURL = "https://curl.se/ca/cacert.pem"

type ImportTrustResult struct {
	Imported int
	Skipped  int
	Total    int
}

func ImportTrustBundle(database *db.DB, pemData []byte, source string) (*ImportTrustResult, error) {
	result := &ImportTrustResult{}

	existing, err := database.TrustAnchorHashIDs()
	if err != nil {
		return nil, fmt.Errorf("get existing hashes: %w", err)
	}

	var certs []*x509.Certificate
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remaining
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			rest = remaining
			continue
		}
		// Only include self-signed root CAs (RawSubject == RawIssuer)
		if !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			rest = remaining
			continue
		}
		certs = append(certs, cert)
		rest = remaining
	}

	result.Total = len(certs)

	for _, cert := range certs {
		hashID := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		if existing[hashID] {
			result.Skipped++
			continue
		}

		subjO, subjC, keyAlgo, keySize, sha1fp, pathLen := ExtractTrustAnchorFields(cert)

		record := &db.TrustAnchor{
			Name:            trustAnchorDisplayName(cert),
			HashID:          hashID,
			CertDER:         cert.Raw,
			Subject:         cert.Subject.String(),
			NotBefore:       cert.NotBefore,
			NotAfter:        cert.NotAfter,
			Issuer:          cert.Issuer.String(),
			Trusted:         true,
			Source:          source,
			SubjectO:        subjO,
			SubjectC:        subjC,
			KeyAlgo:         keyAlgo,
			KeySize:         keySize,
			SHA1Fingerprint: sha1fp,
			PathLen:         pathLen,
		}

		if err := database.InsertTrustAnchor(record); err != nil {
			return nil, fmt.Errorf("insert trust anchor %q: %w", hashID, err)
		}
		result.Imported++
	}

	return result, nil
}

func trustAnchorDisplayName(cert *x509.Certificate) string {
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		return cert.Subject.OrganizationalUnit[0]
	}
	s := cert.Subject.String()
	if s != "" {
		if len(s) > 80 {
			s = s[:80] + "..."
		}
		return s
	}
	return "(unnamed)"
}

// maxTrustBundleBytes caps the fetched trust bundle size (the curl bundle is
// a few MB; a much larger response is a sign of a misbehaving/malicious server).
const maxTrustBundleBytes = 32 << 20 // 32 MiB

func FetchCACertBundle(url string) ([]byte, error) {
	if url == "" {
		url = DefaultCACertURL
	}

	// TOFU hardening: only fetch over TLS so a network attacker cannot inject
	// a fake CA bundle. Loopback URLs are allowed for local test federations.
	u, err := neturl.Parse(url)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", url, err)
	}
	host := u.Hostname()
	if u.Scheme != "https" {
		ip := net.ParseIP(host)
		if host != "localhost" && !strings.HasPrefix(host, "127.") && !strings.HasPrefix(host, "::1") && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("fetch %s: refused non-TLS URL (scheme %q); use https:// for remote CA bundles", url, u.Scheme)
		}
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > maxTrustBundleBytes {
		return nil, fmt.Errorf("fetch %s: trust bundle exceeds %d MiB limit", url, maxTrustBundleBytes>>20)
	}

	// Validate the payload before returning it: it must contain at least one
	// parseable self-signed root CA. An HTML error page or an empty body must
	// not silently import zero anchors (and worse, hide a failed federation).
	if !bundleHasRootCA(data) {
		return nil, fmt.Errorf("fetch %s: response contains no valid root CA certificates", url)
	}

	return data, nil
}

// bundleHasRootCA reports whether the PEM data contains at least one
// self-signed CA certificate (subject == issuer, IsCA).
func bundleHasRootCA(pemData []byte) bool {
	rest := pemData
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			return false
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if cert.IsCA && cert.BasicConstraintsValid && bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			return true
		}
	}
}
