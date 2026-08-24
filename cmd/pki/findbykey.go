package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

// cmdFindByKey looks up certificates by SPKI hash (SHA-256 of the PKIX public
// key), either from an explicit --hash, a certificate file, or a key file.
func cmdFindByKey(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("find-by-key", flag.ExitOnError)
	hash := fs.String("hash", "", bundle.T(curLang, "cli.flag_hash"))
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_cert_file"))
	keyFile := fs.String("key", "", bundle.T(curLang, "cli.flag_key_file"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	status := fs.String("status", "", bundle.T(curLang, "cli.flag_status"))
	jsonOut := fs.Bool("json", false, bundle.T(curLang, "cli.flag_json"))
	fs.Parse(args)

	if *hash == "" && *certFile == "" && *keyFile == "" {
		return ef("cli.err_hash_or_file")
	}
	if *hash == "" {
		if *certFile != "" {
			h, err := spkiHashFromCert(*certFile)
			if err != nil {
				return err
			}
			*hash = h
		} else {
			h, err := spkiHashFromKey(*keyFile)
			if err != nil {
				return err
			}
			*hash = h
		}
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	records, err := database.GetCertBySPKIHash(*hash, *caName, *status)
	if err != nil {
		return fmt.Errorf("query by spki hash: %w", err)
	}

	type certRow struct {
		SerialNumber string `json:"serial_number"`
		CAName       string `json:"ca_name"`
		CommonName   string `json:"common_name"`
		Status       string `json:"status"`
		NotAfter     string `json:"not_after"`
	}
	rows := make([]certRow, 0, len(records))
	for _, r := range records {
		rows = append(rows, certRow{
			SerialNumber: r.SerialNumber,
			CAName:       r.CAName,
			CommonName:   r.CommonName,
			Status:       r.Status,
			NotAfter:     r.NotAfter.Format("2006-01-02 15:04:05"),
		})
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)
	}

	if len(rows) == 0 {
		fmt.Println("No certificates found for this public key")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SERIAL\tCA\tCN\tSTATUS\tNOT AFTER")
	for _, r := range rows {
		short := r.SerialNumber
		if len(short) > 16 {
			short = short[:16]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", short, r.CAName, r.CommonName, r.Status, r.NotAfter)
	}
	w.Flush()
	return nil
}

func spkiHashFromCert(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read cert file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("no PEM data in cert file")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	return ca.ExtractSPKIHash(cert), nil
}

func spkiHashFromKey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read key file: %w", err)
	}
	key, err := ca.ParsePrivateKey(data)
	if err != nil {
		return "", fmt.Errorf("parse private key: %w", err)
	}
	pub, ok := key.(interface{ Public() crypto.PublicKey })
	if !ok {
		return "", fmt.Errorf("key does not expose public key")
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pub.Public())
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	h := sha256.Sum256(pubBytes)
	return fmt.Sprintf("%x", h), nil
}
