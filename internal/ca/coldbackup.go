package ca

import (
	"crypto"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// ColdBackupEnvelope is the on-disk format for an offline Root CA cold backup.
// The private key is encrypted with PBES2 (AES-256-CBC, see pbes2.go) and the
// whole envelope carries an HMAC so tampering or a wrong password is detected
// before any secret key material is processed.
type ColdBackupEnvelope struct {
	Version        int    `json:"version"`
	CAName         string `json:"ca_name"`
	CreatedAt      string `json:"created_at"`
	CertPEM        string `json:"cert_pem"`
	EncryptedKey   string `json:"encrypted_key"`    // base64(PBES2 DER)
	CertSHA256     string `json:"cert_sha256"`      // hex
	KeyFP          string `json:"key_fingerprint"`  // hex SHA-256 of public key
	MAC            string `json:"mac"`              // base64(HMAC-SHA256 over canonical fields)
	MACSalt        string `json:"mac_salt,omitempty"` // base64(16B salt), M11+
	MACIterations  int    `json:"mac_iterations,omitempty"` // PBKDF2 iterations, M11+
}

// coldBackupMACIterations is the PBKDF2-SHA256 iteration count used to derive
// the MAC key from the backup password (M11 fix). Same order of magnitude as
// the PBES2 key-encryption KDF so a brute-forcer pays the full KDF cost.
const coldBackupMACIterations = 600000

// ColdBackupCA reads the CA certificate and key, encrypts the key under
// password, and writes a tamper-evident JSON envelope to outPath. The key is
// loaded via ParsePrivateKey (supports encrypted PEM via keyPassword).
func ColdBackupCA(caName, certPath, keyPath, password, keyPassword, outPath string) error {
	if caName == "" {
		return errors.New("ca_name is required")
	}
	if certPath == "" || keyPath == "" {
		return errors.New("--ca-cert and --ca-key are required")
	}
	if password == "" {
		return errors.New("a backup password is required")
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return errors.New("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	var signer crypto.Signer
	if kb != nil && kb.Type == "ENCRYPTED PRIVATE KEY" {
		if keyPassword == "" {
			keyPassword = os.Getenv("PKI_KEY_PASSWORD")
		}
		signer, err = DecryptKeyPKCS8(kb.Bytes, keyPassword)
		if err != nil {
			return fmt.Errorf("decrypt CA key: %w", err)
		}
	} else {
		signer, err = ParsePrivateKey(keyPEM, keyPassword)
		if err != nil {
			return fmt.Errorf("parse CA key: %w", err)
		}
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	enc, err := EncryptKeyDERPKCS8(keyDER, password)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	keyFP := sha256.Sum256(pubDER)
	certSHA := sha256.Sum256(cb.Bytes)

	env := ColdBackupEnvelope{
		Version:      2,
		CAName:       caName,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		CertPEM:      string(certPEM),
		EncryptedKey: base64.StdEncoding.EncodeToString(enc),
		CertSHA256:   fmt.Sprintf("%x", certSHA),
		KeyFP:        fmt.Sprintf("%x", keyFP),
	}
	// M11 fix: MAC key is derived via PBKDF2-SHA256 with a random salt instead
	// of a bare SHA256(password), so offline brute-force must pay the full KDF
	// cost. Version 2 carries the salt/iterations in the envelope.
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("mac salt: %w", err)
	}
	env.MACSalt = base64.StdEncoding.EncodeToString(salt)
	env.MACIterations = coldBackupMACIterations
	mac, err := coldBackupMAC(&env, password)
	if err != nil {
		return err
	}
	env.MAC = base64.StdEncoding.EncodeToString(mac)

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if err := os.WriteFile(outPath, data, 0600); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	_ = cert
	return nil
}

// VerifyColdBackup reads a cold backup envelope, verifies its MAC, decrypts the
// key, and checks that the decrypted key matches the enclosed certificate's
// public key. It returns a human-readable summary on success.
func VerifyColdBackup(inPath, password string) (string, error) {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return "", fmt.Errorf("read backup: %w", err)
	}
	var env ColdBackupEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return "", fmt.Errorf("parse envelope: %w", err)
	}
	if env.Version != 1 && env.Version != 2 {
		return "", fmt.Errorf("unsupported envelope version %d", env.Version)
	}

	expect, err := coldBackupMAC(&env, password)
	if err != nil {
		return "", err
	}
	got, err := base64.StdEncoding.DecodeString(env.MAC)
	if err != nil {
		return "", errors.New("invalid mac field")
	}
	if !hmac.Equal(expect, got) {
		return "", errors.New("MAC mismatch: wrong password or tampered backup")
	}

	enc, err := base64.StdEncoding.DecodeString(env.EncryptedKey)
	if err != nil {
		return "", fmt.Errorf("decode encrypted key: %w", err)
	}
	signer, err := DecryptKeyPKCS8(enc, password)
	if err != nil {
		return "", fmt.Errorf("decrypt key: %w", err)
	}

	cb, _ := pem.Decode([]byte(env.CertPEM))
	if cb == nil {
		return "", errors.New("invalid cert in backup")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	if !publicKeysEqual(cert.PublicKey, signer.Public()) {
		return "", errors.New("key does not match certificate")
	}

	summary := fmt.Sprintf("cold backup OK: ca=%s created=%s cert_sha256=%s key_fingerprint=%s",
		env.CAName, env.CreatedAt, env.CertSHA256, env.KeyFP)
	return summary, nil
}

func coldBackupMAC(env *ColdBackupEnvelope, password string) ([]byte, error) {
	payload := fmt.Sprintf("%d|%s|%s|%s|%s|%s",
		env.Version, env.CAName, env.CreatedAt, env.CertPEM, env.EncryptedKey, env.KeyFP)
	macKey, err := coldBackupMACKey(env, password)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, macKey)
	if _, err := mac.Write([]byte(payload)); err != nil {
		return nil, err
	}
	return mac.Sum(nil), nil
}

// coldBackupMACKey derives the HMAC key. Version 2 uses PBKDF2-SHA256 with the
// envelope salt (M11); legacy v1 envelopes fall back to the historical
// SHA256(password) derivation so existing backups still verify.
func coldBackupMACKey(env *ColdBackupEnvelope, password string) ([]byte, error) {
	if env.Version >= 2 && env.MACSalt != "" {
		salt, err := base64.StdEncoding.DecodeString(env.MACSalt)
		if err != nil || len(salt) == 0 {
			return nil, errors.New("invalid mac_salt in envelope")
		}
		iterations := env.MACIterations
		if iterations <= 0 {
			iterations = coldBackupMACIterations
		}
		key, err := pbkdf2.Key(sha256.New, password, salt, iterations, 32)
		if err != nil {
			return nil, fmt.Errorf("derive mac key: %w", err)
		}
		return key, nil
	}
	h := sha256.Sum256([]byte(password))
	return h[:], nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	da, err1 := x509.MarshalPKIXPublicKey(a)
	db, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return hmac.Equal(da, db)
}
