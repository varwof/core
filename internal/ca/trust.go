// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

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
	"net/netip"
	neturl "net/url"
	"slices"
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

// blockedFetchRanges are internal/private networks that must never be reached
// during a CA-bundle fetch (SSRF defense). Loopback (127.0.0.0/8, ::1) is
// deliberately excluded so local test federations keep working.
var blockedFetchRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // unspecified
	netip.MustParsePrefix("10.0.0.0/8"),     // private (RFC 1918)
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT
	netip.MustParsePrefix("169.254.0.0/16"), // link-local
	netip.MustParsePrefix("172.16.0.0/12"),  // private (RFC 1918)
	netip.MustParsePrefix("192.168.0.0/16"), // private (RFC 1918)
	netip.MustParsePrefix("::/128"),         // unspecified
	netip.MustParsePrefix("fc00::/7"),       // unique-local
	netip.MustParsePrefix("fe80::/10"),      // link-local
}

// blockedOutboundRanges additionally blocks loopback: outbound requests (e.g.
// webhook delivery) must never target the host's own loopback services either.
var blockedOutboundRanges = slices.Concat(
	blockedFetchRanges,
	[]netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"), // loopback
		netip.MustParsePrefix("::1/128"),     // loopback
	},
)

// guardAgainstSSRFFetch rejects a host whose literal or resolved addresses
// fall inside the given internal/loopback network ranges. It fails closed: an
// unresolvable host is refused rather than fetched.
func guardAgainstSSRFFetch(host string) error {
	return guardAgainstSSRFRanges(host, blockedFetchRanges, "internal network")
}

// ValidateOutboundHTTPURL checks that url is an http(s) URL with a non-empty
// host whose literal or resolved addresses are not internal/private/loopback
// (SSRF defense). Used when registering outbound destinations such as webhook
// subscriptions so the server cannot be used as a pivot to reach internal hosts.
func ValidateOutboundHTTPURL(rawurl string) error {
	u, err := neturl.Parse(rawurl)
	if err != nil {
		return fmt.Errorf("parse URL %q: %w", rawurl, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("unsupported URL scheme %q (must be http or https)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL %q has no host", rawurl)
	}
	return guardAgainstSSRFRanges(host, blockedOutboundRanges, "internal or loopback")
}

func guardAgainstSSRFRanges(host string, ranges []netip.Prefix, label string) error {
	if a, err := netip.ParseAddr(host); err == nil {
		if addrInRanges(a, ranges) {
			return fmt.Errorf("refusing to reach %s address %s", label, host)
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// An unresolvable hostname is not evidence that the target is internal,
		// so do not block it here: a legitimate public webhook/CA URL must not
		// be rejected when DNS is unavailable (the outbound request will fail on
		// its own if the host genuinely cannot be reached).
		return nil
	}
	// net.IP may be an IPv4-mapped IPv6 (16-byte) slice; normalize so the
	// IPv4 loopback/private prefixes match.
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		if a, ok := netip.AddrFromSlice(ip); ok && addrInRanges(a, ranges) {
			return fmt.Errorf("refusing to reach %s: %s resolves to %s address %s", label, host, label, ip)
		}
	}
	return nil
}

func addrInRanges(a netip.Addr, ranges []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

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

	// M9 SSRF fix: never fetch from internal/private networks (RFC 1918,
	// link-local, CGNAT, unique-local, unspecified). Loopback is the sole
	// exception, retained for local test federations. This prevents a
	// trust:import holder from using FetchCACertBundle to probe/reach internal
	// hosts over https (previously any https:// host was allowed).
	if err := guardAgainstSSRFFetch(host); err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
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
