// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ctChainRequest struct {
	Chain []string `json:"chain"`
}

type ctSCT struct {
	SCTVersion int    `json:"sct_version"`
	ID         string `json:"id"`
	Timestamp  uint64 `json:"timestamp"`
	Extensions string `json:"extensions"`
	Signature  string `json:"signature"`
}

type ctAddChainResponse struct {
	SCT ctSCT `json:"sct"`
}

// ctTimeout bounds the single HTTP request against a CT log (audit H11: the
// old code used the unbounded http.DefaultClient).
const ctTimeout = 30 * time.Second

// ctMaxResponseBytes caps the CT log response body. A valid add-chain response
// is a few KB of JSON; 1 MiB is far beyond any legitimate reply and bounds the
// memory a malicious/compromised log can force us to allocate.
const ctMaxResponseBytes = 1 << 20

func SubmitCertificate(url, apiKey string, cert *x509.Certificate, chain []*x509.Certificate, optHTTPClient ...*http.Client) (sctVersion int, logID string, timestamp uint64, extensions string, sigDER []byte, err error) {
	if !strings.HasPrefix(url, "https://") {
		return 0, "", 0, "", nil, fmt.Errorf("CT log URL must use HTTPS (got %q)", url)
	}

	certB64 := base64.StdEncoding.EncodeToString(cert.Raw)
	chainB64 := []string{certB64}
	for _, c := range chain {
		chainB64 = append(chainB64, base64.StdEncoding.EncodeToString(c.Raw))
	}

	body, err := json.Marshal(ctChainRequest{Chain: chainB64})
	if err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url+"/ct/v1/add-chain", bytes.NewReader(body))
	if err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	client := &http.Client{Timeout: ctTimeout}
	if len(optHTTPClient) > 0 && optHTTPClient[0] != nil {
		client = optHTTPClient[0]
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	// Cap the response size: a legitimate CT log JSON response is a few KB;
	// limit the read so a compromised/malicious log cannot exhaust memory.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, ctMaxResponseBytes))
	if err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 200 {
		return 0, "", 0, "", nil, fmt.Errorf("CT log returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result ctAddChainResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("parse response: %w", err)
	}

	sigDER, err = base64.StdEncoding.DecodeString(result.SCT.Signature)
	if err != nil {
		return 0, "", 0, "", nil, fmt.Errorf("decode signature: %w", err)
	}

	return result.SCT.SCTVersion, result.SCT.ID, result.SCT.Timestamp, result.SCT.Extensions, sigDER, nil
}

// SCTHashAlgorithm and SCTSignatureAlgorithm per RFC 6962 §3.2 DigitallySigned.
const (
	sctHashSHA256    = 4
	sctSigRSA        = 1
	sctSigECDSA      = 3
	sctSigEd25519    = 6
	sctEntryX509     = 0
	sctSigTypeCertTs = 0
)

// VerifySCT performs full RFC 6962 §3.2 signature verification of a v1 SCT
// against the CT log's public key. It reconstructs the exact TLS bytes the log
// signed over (SignedCertificateTimestamp → SCTSignedData: version | sig_type |
// timestamp | entry_type | 3-byte-length cert DER | 2-byte-length extensions)
// and verifies the DigitallySigned signature with the supplied log key.
//
// The previous implementation only validated the TLS framing (algo bytes +
// length prefix) and never touched the log signature — any garbage SCT passed.
// Pass a nil logPubKey to skip the cryptographic check (callers that do this
// MUST treat the result as unverified).
func VerifySCT(cert *x509.Certificate, sctVersion int, logID string, timestamp uint64, extensions string, sigDER []byte, logPubKey crypto.PublicKey) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	if len(sigDER) == 0 {
		return fmt.Errorf("empty SCT signature")
	}
	// DigitallySigned: HashAlgorithm (1) + SignatureAlgorithm (1) + Signature (2-byte length prefixed)
	if len(sigDER) < 4 {
		return fmt.Errorf("SCT signature too short: %d bytes", len(sigDER))
	}
	hashAlgo := sigDER[0]
	sigAlgo := sigDER[1]
	sigLen := int(sigDER[2])<<8 | int(sigDER[3])
	if sigLen+4 > len(sigDER) {
		return fmt.Errorf("SCT signature length %d exceeds data %d", sigLen, len(sigDER)-4)
	}
	sig := sigDER[4 : 4+sigLen]

	if sctVersion != 0 {
		return fmt.Errorf("unsupported SCT version %d (only v1 supported)", sctVersion)
	}
	if hashAlgo != sctHashSHA256 {
		return fmt.Errorf("unsupported SCT hash algorithm %d (only SHA-256)", hashAlgo)
	}
	if sigAlgo != sctSigRSA && sigAlgo != sctSigECDSA && sigAlgo != sctSigEd25519 {
		return fmt.Errorf("unsupported SCT signature algorithm %d", sigAlgo)
	}
	if logPubKey == nil {
		return fmt.Errorf("nil CT log public key: signature verification not possible")
	}

	// RFC 6962 §5.2: a TLS client MUST NOT use an SCT with a timestamp in
	// the future. Reject timestamps more than 5 minutes ahead as a
	// defence-in-depth against misconfigured or compromised CT logs.
	const maxFutureSkewMs = 5 * 60 * 1000 // 5 minutes in milliseconds
	if ts := int64(timestamp); ts > 0 {
		nowMs := time.Now().UnixMilli()
		if ts > nowMs+maxFutureSkewMs {
			return fmt.Errorf("SCT timestamp is %d ms in the future (max skew %d ms)", ts-nowMs, maxFutureSkewMs)
		}
	}

	// Reconstruct the SCT signed data per RFC 6962 §3.2.
	//   struct {
	//     Version sct_version;                    // 1 byte = 0
	//     SignatureType signature_type;           // 1 byte = certificate_timestamp
	//     uint64 timestamp;                       // 8 bytes big-endian
	//     LogEntryType entry_type;                // 2 bytes = x509_entry
	//     ASN.1Cert certificate;                  // 3-byte length + DER
	//     CtExtensions extensions;                // 2-byte length + bytes
	//   } SCTSignedData;
	var signed bytes.Buffer
	signed.WriteByte(byte(sctVersion)) // sct_version
	signed.WriteByte(sctSigTypeCertTs) // signature_type
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], timestamp) // timestamp
	signed.Write(tsBuf[:])
	var entryBuf [2]byte
	binary.BigEndian.PutUint16(entryBuf[:], sctEntryX509) // entry_type
	signed.Write(entryBuf[:])
	if len(cert.Raw) > 0xFFFFFF {
		return fmt.Errorf("certificate DER too large for SCT entry: %d bytes", len(cert.Raw))
	}
	var certLen [3]byte
	certLen[0] = byte(len(cert.Raw) >> 16)
	certLen[1] = byte(len(cert.Raw) >> 8)
	certLen[2] = byte(len(cert.Raw))
	signed.Write(certLen[:])
	signed.Write(cert.Raw)

	ext, err := base64.StdEncoding.DecodeString(extensions)
	if err != nil {
		return fmt.Errorf("decode SCT extensions: %w", err)
	}
	if len(ext) > 0xFFFF {
		return fmt.Errorf("SCT extensions too large: %d bytes", len(ext))
	}
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(ext)))
	signed.Write(extLen[:])
	signed.Write(ext)

	// If a log ID was supplied, cross-check it against the public key's SPKI
	// SHA-256 (RFC 6962 §3.1 log_id = SHA-256(public key)).
	if logID != "" {
		logIDBytes, err := base64.StdEncoding.DecodeString(logID)
		if err != nil || len(logIDBytes) != sha256.Size {
			return fmt.Errorf("invalid log ID: %q", logID)
		}
		spki, err := x509.MarshalPKIXPublicKey(logPubKey)
		if err != nil {
			return fmt.Errorf("marshal log public key: %w", err)
		}
		derived := sha256.Sum256(spki)
		if !bytes.Equal(derived[:], logIDBytes) {
			return fmt.Errorf("SCT log ID does not match public key SPKI SHA-256 (possible key confusion)")
		}
	}

	signedBytes := signed.Bytes()
	switch sigAlgo {
	case sctSigRSA:
		pub, ok := logPubKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("SCT signed with RSA but log key is %T", logPubKey)
		}
		h := sha256.Sum256(signedBytes)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig)
	case sctSigECDSA:
		pub, ok := logPubKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("SCT signed with ECDSA but log key is %T", logPubKey)
		}
		digest := sha256.Sum256(signedBytes)
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return fmt.Errorf("SCT ECDSA signature verification failed")
		}
		return nil
	case sctSigEd25519:
		pub, ok := logPubKey.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("SCT signed with Ed25519 but log key is %T", logPubKey)
		}
		// RFC 6962 §3.2: Ed25519 is a pure (non-prehashed) signature scheme and
		// signs the raw signed-bytes directly. Do NOT SHA-256 pre-hash here —
		// the previous double-hash made every valid Ed25519-log SCT fail
		// verification (L20).
		if !ed25519.Verify(pub, signedBytes, sig) {
			return fmt.Errorf("SCT Ed25519 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported SCT signature algorithm %d", sigAlgo)
	}
}

// ParseCTLogPublicKey parses a CT log public key given as either a base64
// DER SPKI string or a PEM block (PUBLIC KEY). It returns the parsed key.
func ParseCTLogPublicKey(s string) (crypto.PublicKey, error) {
	if s == "" {
		return nil, fmt.Errorf("empty CT log public key")
	}
	// Try PEM first (harmless if it's not PEM).
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return x509.ParsePKIXPublicKey(block.Bytes)
	}
	der, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode CT log public key (expected base64 DER or PEM): %w", err)
	}
	return x509.ParsePKIXPublicKey(der)
}
