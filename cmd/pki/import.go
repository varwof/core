package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	p12 "software.sslmate.com/src/go-pkcs12"
)

func cmdImport(cfg *internal.Config, args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "ca":
			return cmdImportCA(cfg, args[1:])
		}
	}

	fs := flag.NewFlagSet("import", flag.ExitOnError)
	indexPath := fs.String("index", "index.txt", "OpenSSL index.txt path")
	certDir := fs.String("cert-dir", "", "certificates directory (default: same as index.txt)")
	caName := fs.String("ca", "issuing", bundle.T(curLang, "cli.flag_ca"))
	caCertPath := fs.String("ca-cert", "", bundle.T(curLang, "cli.flag_cacert"))
	fs.Parse(args)

	if *certDir == "" {
		*certDir = filepath.Dir(*indexPath)
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	if *caCertPath == "" {
		if caCfg, ok := cfg.CAs[*caName]; ok && caCfg.Cert != "" {
			*caCertPath = caCfg.Cert
		}
	}
	if *caCertPath != "" {
		if err := registerCACert(database, *caName, *caCertPath); err != nil {
			return fmt.Errorf("register CA: %w", err)
		}
	}

	f, err := os.Open(*indexPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", *indexPath, err)
	}
	defer f.Close()

	reasonMap := map[string]int{
		"unspecified":          0,
		"keyCompromise":        1,
		"cACompromise":         2,
		"affiliationChanged":   3,
		"superseded":           4,
		"cessationOfOperation": 5,
		"certificateHold":      6,
	}

	imported := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Split(line, "\t")
		if len(fields) < 6 {
			continue
		}

		status := fields[0]
		if status != "V" && status != "R" && status != "E" {
			continue
		}

		serialsIdx, revDateIdx, reasonIdx := fieldIndices(len(fields))

		serialHex := fields[serialsIdx]
		certRelPath := fields[len(fields)-2]

		certPEM, err := loadCertFile(*certDir, certRelPath, serialHex)
		if err != nil {
			slog.Warn("import: load cert", "serial", serialHex, "error", err)
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			slog.Warn("import: no PEM block", "serial", serialHex)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Warn("import: parse cert", "serial", serialHex, "error", err)
			continue
		}

		statusCode := "V"
		var revokedAt *time.Time
		var revokeReason *int

		if status == "R" || status == "E" {
			statusCode = status
			if revDateStr := fields[revDateIdx]; revDateStr != "" && revDateStr != "-" {
				t, err := time.Parse("060102150405Z", revDateStr)
				if err == nil {
					revokedAt = &t
				}
			}
			if reasonIdx >= 0 {
				if r, ok := reasonMap[fields[reasonIdx]]; ok {
					revokeReason = &r
				}
			}
		}

		normalized, err := ca.NormalizeSerial(serialHex)
		if err != nil {
			slog.Warn("import: normalize serial", "serial", serialHex, "error", err)
			continue
		}

		record := &db.CertRecord{
			SerialNumber: normalized,
			CAName:       *caName,
			Status:       statusCode,
			Subject:      cert.Subject.String(),
			CommonName:   cert.Subject.CommonName,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,
			RevokedAt:    revokedAt,
			RevokeReason: revokeReason,
			CertDER:      cert.Raw,
			Fingerprint:  db.Fingerprint(cert.Raw),
		}

		if err := database.InsertCert(record); err != nil {
			slog.Warn("import: insert cert", "ca", *caName, "serial", serialHex, "error", err)
			continue
		}
		imported++
	}

	fmt.Printf("imported: %d certificates\n", imported)
	return scanner.Err()
}

func fieldIndices(n int) (serialIdx, revDateIdx, reasonIdx int) {
	if n >= 7 {
		return 4, 2, 3
	}
	return 3, 2, -1
}

func registerCACert(d *db.DB, name, certPath string) error {
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return fmt.Errorf("no PEM block in CA cert")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	record := &db.CAMeta{
		Name:         name,
		CertDER:      cert.Raw,
		Subject:      cert.Subject.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		KeyAlgorithm: pubKeyAlgorithm(cert.PublicKey),
		Fingerprint:  db.Fingerprint(cert.Raw),
	}

	return d.InsertCAMeta(record)
}

func loadCertFile(certDir, relPath, serialHex string) ([]byte, error) {
	certPath := relPath
	if !filepath.IsAbs(certPath) {
		certPath = filepath.Join(certDir, certPath)
	}

	pemData, err := os.ReadFile(certPath)
	if err == nil {
		return pemData, nil
	}

	// Fallback: try <serial>.pem in cert-dir
	altPath := filepath.Join(certDir, serialHex+".pem")
	pemData, err = os.ReadFile(altPath)
	if err == nil {
		return pemData, nil
	}

	return nil, fmt.Errorf("read cert: tried %q and %q: %v", certPath, altPath, err)
}

func pubKeyAlgorithm(pub any) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		return fmt.Sprintf("ecdsa-p%d", k.Curve.Params().BitSize)
	case *rsa.PublicKey:
		return fmt.Sprintf("rsa-%d", k.N.BitLen())
	default:
		return fmt.Sprintf("%T", pub)
	}
}

func cmdImportCA(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("import ca", flag.ExitOnError)
	name := fs.String("name", "", "CA name")
	certPath := fs.String("cert", "", "CA certificate PEM file path")
	keyPath := fs.String("key", "", "CA private key PEM file path")
	p12Path := fs.String("p12", "", "PKCS#12/PFX file path")
	p12Password := fs.String("password", "", "PKCS#12 password")
	keyPassword := fs.String("key-password", "", "Password for encrypting private key in DB (default: PKI_KEY_PASSWORD env)")
	writeConfig := fs.String("write-config", "", "Write CA entry to config file")
	force := fs.Bool("force", false, "override root CA safety check")
	fs.Parse(args)

	if *name == "" {
		return fmt.Errorf("--name is required")
	}

	var certPEM, keyPEM []byte
	var err error

	if *p12Path != "" {
		pfxData, err := os.ReadFile(*p12Path)
		if err != nil {
			return fmt.Errorf("read p12: %w", err)
		}
		pwd := *p12Password
		if pwd == "" {
			pwd = os.Getenv("PKI_KEY_PASSWORD")
		}
		// We reuse PKCS#12 loading from the pkcs12 package
		certPEM, keyPEM, err = extractP12(pfxData, pwd)
		if err != nil {
			return fmt.Errorf("extract p12: %w", err)
		}
	} else {
		if *certPath == "" {
			return fmt.Errorf("--cert is required")
		}
		if *keyPath == "" {
			return fmt.Errorf("--key is required")
		}
		certPEM, err = os.ReadFile(*certPath)
		if err != nil {
			return fmt.Errorf("read cert: %w", err)
		}
		keyPEM, err = os.ReadFile(*keyPath)
		if err != nil {
			return fmt.Errorf("read key: %w", err)
		}
	}

	password := *keyPassword
	if password == "" {
		password = os.Getenv("PKI_KEY_PASSWORD")
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	certBlock, _ := pem.Decode(certPEM)
	if certBlock != nil {
		if cert, parseErr := x509.ParseCertificate(certBlock.Bytes); parseErr == nil {
			if cert.IsCA && string(cert.RawIssuer) == string(cert.RawSubject) && !*force {
				return errors.New(bundle.T(curLang, "cli.import_ca_root_rejected"))
			}
		}
	}

	record, err := ca.ImportExternalCA(database, *name, certPEM, keyPEM, password)
	if err != nil {
		return fmt.Errorf("import CA: %w", err)
	}

	fmt.Printf("CA %q imported successfully\n", *name)
	fmt.Printf("  Subject:      %s\n", record.Subject)
	fmt.Printf("  Fingerprint:  %s\n", record.Fingerprint)
	fmt.Printf("  Not After:    %s\n", record.NotAfter.Format("2006-01-02"))
	fmt.Printf("  Key Stored:   %v\n", len(record.KeyEncrypted) > 0)

	if *writeConfig != "" {
		if err := appendCAConfig(*writeConfig, *name, *certPath, *keyPath); err != nil {
			return fmt.Errorf("write config: %w", err)
		}
		fmt.Printf("  Config:       appended to %s\n", *writeConfig)
	}

	return nil
}

func extractP12(pfxData []byte, password string) (certPEM, keyPEM []byte, err error) {
	priv, cert, chain, err := p12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("decode p12: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for _, c := range chain {
		cpem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		certPEM = append(certPEM, cpem...)
	}
	return certPEM, keyPEM, nil
}

func appendCAConfig(configPath, name, certPath, keyPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfgMap map[string]interface{}
	if err := json.Unmarshal(data, &cfgMap); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}

	cas, ok := cfgMap["cas"].(map[string]interface{})
	if !ok {
		cas = make(map[string]interface{})
		cfgMap["cas"] = cas
	}

	entry := map[string]string{
		"cert": certPath,
		"key":  keyPath,
	}
	cas[name] = entry

	written, err := json.MarshalIndent(cfgMap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	return os.WriteFile(configPath, written, 0644)
}
