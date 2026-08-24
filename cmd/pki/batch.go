// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

func cmdBatch(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("batch", flag.ExitOnError)
	csvPath := fs.String("csv", "", bundle.T(curLang, "cli.flag_csv"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	outDir := fs.String("out-dir", "", bundle.T(curLang, "cli.flag_out_dir"))
	fs.Parse(args)

	if *csvPath == "" {
		return ef("cli.err_csv_required")
	}

	if *caName == "" {
		*caName = cfg.Defaults.CA
	}

	caInfo, ok := cfg.CAs[*caName]
	if !ok {
		return fmt.Errorf("CA %q not found in config — add it to the 'cas' section of your config file, or use 'pki ca init' with --password to store the key in DB", *caName)
	}

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	issuerCert, issuerKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
	if err != nil {
		return fmt.Errorf("load CA %q: %w", *caName, err)
	}

	f, err := os.Open(*csvPath)
	if err != nil {
		return fmt.Errorf("open csv: %w", err)
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	r.ReuseRecord = true

	// Read header
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("read csv header: %w", err)
	}
	colIndex := make(map[string]int, len(header))
	for i, h := range header {
		colIndex[strings.ToLower(strings.TrimSpace(h))] = i
	}

	required := []string{"cn"}
	for _, name := range required {
		if _, ok := colIndex[name]; !ok {
			return fmt.Errorf("csv missing required column: %s", name)
		}
	}

	okCount := 0
	errCount := 0
	lineNo := 1 // header is line 1

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		lineNo++
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d: read error: %v\n", lineNo, err)
			errCount++
			continue
		}

		cn := colVal(rec, colIndex, "cn")
		sanStr := colVal(rec, colIndex, "san")
		profile := colVal(rec, colIndex, "profile")
		keyType := colVal(rec, colIndex, "key-type")
		validityStr := colVal(rec, colIndex, "validity")
		mustStapleStr := colVal(rec, colIndex, "must-staple")
		ekuStr := colVal(rec, colIndex, "eku-oid")

		if cn == "" {
			fmt.Fprintln(os.Stderr, bundle.T(curLang, "cli.batch_line_skip", lineNo))
			errCount++
			continue
		}

		if profile == "" {
			profile = cfg.Defaults.Profile
		}
		if keyType == "" {
			keyType = cfg.Defaults.KeyType
		}
		validity := 365
		if validityStr != "" {
			if v, err := strconv.Atoi(validityStr); err == nil && v > 0 {
				validity = v
			}
		}

		privKey, err := ca.GenerateKey(keyType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d (%s): generate key: %v\n", lineNo, cn, err)
			errCount++
			continue
		}

		signCfg := &ca.SignConfig{
			DB:                    database,
			CAKey:                 issuerKey,
			CACert:                issuerCert,
			CAName:                *caName,
			CommonName:            cn,
			SubjectPubKey:         privKey.Public(),
			Profile:               ca.Profile(profile),
			Hash:                  cfg.Defaults.Hash,
			Validity:              time.Duration(validity) * 24 * time.Hour,
			CRLBaseURL:            cfg.CRL.CRLBaseURL,
			OCSPURL:               cfg.Defaults.OCSPURL,
			IssuerURL:             cfg.Defaults.IssuerURL,
			IssuerAltNames:        cfg.Defaults.IssuerAltNames,
			SubjectInfoAccess:     cfg.Defaults.SubjectInfoAccess,
			PolicyOIDs:            cfg.Defaults.PolicyOIDs,
			PolicyMappings:        mustPolicyMappings(cfg.Defaults.PolicyMappings),
			RequireExplicitPolicy: cfg.Defaults.RequireExplicitPolicy,
			InhibitPolicyMapping:  cfg.Defaults.InhibitPolicyMapping,
			InhibitAnyPolicy:      cfg.Defaults.InhibitAnyPolicy,
			DefaultOrg:            cfg.Defaults.DefaultOrg,
			DefaultCountry:        cfg.Defaults.DefaultCountry,
			DedupCN:               true,
			MustStaple:            mustStapleStr == "true" || mustStapleStr == "1" || mustStapleStr == "yes",
			ExtraEKUOIDs:          splitCSV(ekuStr),
			PolicyFile:            cfg.Policy,
		}

		if sanStr != "" {
			for _, s := range strings.Split(sanStr, ",") {
				s = strings.TrimSpace(s)
				if s != "" {
					signCfg.SANs = append(signCfg.SANs, s)
				}
			}
		}

		result, err := ca.Sign(signCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d (%s): sign: %v\n", lineNo, cn, err)
			errCount++
			continue
		}

		notifyEvent(cfg, database, "cert_issued", *caName, result.SerialHex, cn, "")

		if cfg.KeyEscrow.AdminPublicKey != "" && result.PrivateKey != nil {
			adminPub, err := ca.LoadAdminPublicKey(cfg.KeyEscrow.AdminPublicKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d (%s): load admin key: %v\n", lineNo, cn, err)
				errCount++
				continue
			}
			privDER, err := x509.MarshalPKCS8PrivateKey(result.PrivateKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d (%s): marshal key: %v\n", lineNo, cn, err)
				errCount++
				continue
			}
			encBlob, err := ca.EncryptPrivateKey(privDER, adminPub)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d (%s): escrow encrypt: %v\n", lineNo, cn, err)
				errCount++
				continue
			}
			if err := database.StoreEscrowedKey(*caName, result.SerialHex, encBlob); err != nil {
				fmt.Fprintf(os.Stderr, "line %d (%s): store escrow: %v\n", lineNo, cn, err)
				errCount++
				continue
			}
		}

		logs := cfg.CTLog.AllLogs()
		for _, l := range logs {
			var chain []*x509.Certificate
			if caInfo, ok := cfg.CAs[*caName]; ok && caInfo.Chain != "" {
				chainPEM, err := os.ReadFile(caInfo.Chain)
				if err == nil {
					rest := chainPEM
					for {
						var b *pem.Block
						b, rest = pem.Decode(rest)
						if b == nil {
							break
						}
						c, cerr := x509.ParseCertificate(b.Bytes)
						if cerr != nil {
							break
						}
						chain = append(chain, c)
					}
				}
			}
			sctVersion, logID, timestamp, extensions, sigDER, err := ca.SubmitCertificate(l.URL, l.APIKey, result.Cert, chain)
			if err != nil {
				fmt.Fprintf(os.Stderr, "line %d (%s): ct submit to %s: %v\n", lineNo, cn, l.URL, err)
			} else {
				if err := database.StoreSCT(*caName, result.SerialHex, sctVersion, logID, timestamp, sigDER); err != nil {
					fmt.Fprintf(os.Stderr, "line %d (%s): ct store: %v\n", lineNo, cn, err)
				}
				if err := verifySCTWithKey(result.Cert, sctVersion, logID, timestamp, extensions, sigDER, l.PublicKey); err != nil {
					fmt.Fprintf(os.Stderr, "line %d (%s): ct verify: %v\n", lineNo, cn, err)
				}
			}
		}

		certOut := cn + ".pem"
		keyOut := cn + ".key"
		if *outDir != "" {
			certOut = filepath.Join(*outDir, cn+".pem")
			keyOut = filepath.Join(*outDir, cn+".key")
		}

		if err := os.WriteFile(certOut, ca.CertToPEM(result.CertDER), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "line %d (%s): write cert: %v\n", lineNo, cn, err)
			errCount++
			continue
		}

		keyPEM, err := ca.KeyToPEM(privKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "line %d (%s): key to pem: %v\n", lineNo, cn, err)
			errCount++
			continue
		}
		if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "line %d (%s): write key: %v\n", lineNo, cn, err)
			errCount++
			continue
		}

		fmt.Println(bundle.T(curLang, "cli.file_written_pair", cn, certOut, keyOut))
		okCount++
	}

	fmt.Print(bundle.T(curLang, "cli.batch_summary", okCount, errCount) + "\n")
	if errCount > 0 {
		return ef("cli.batch_error", errCount)
	}
	return nil
}

func colVal(rec []string, idx map[string]int, name string) string {
	if i, ok := idx[name]; ok && i < len(rec) {
		return strings.TrimSpace(rec[i])
	}
	return ""
}
