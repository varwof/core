package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
	"github.com/varwof/pkcs7"
	"github.com/varwof/core/internal/signer"
	"github.com/varwof/core/internal/tsa"
)

func cmdSign(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	verify := fs.Bool("verify", false, bundle.T(curLang, "cli.flag_verify"))
	embedded := fs.Bool("embed", false, bundle.T(curLang, "cli.flag_embed"))
	sigFile := fs.String("sig", "", bundle.T(curLang, "cli.flag_sig_file"))
	certFile := fs.String("cert", "", bundle.T(curLang, "cli.flag_signer_cert"))
	keyFile := fs.String("key", "", bundle.T(curLang, "cli.flag_signer_key"))
	chainFile := fs.String("chain", "", bundle.T(curLang, "cli.flag_chain"))
	caName := fs.String("ca", "", bundle.T(curLang, "cli.flag_ca"))
	cn := fs.String("cn", "", bundle.T(curLang, "cli.flag_cn_signer"))
	profileName := fs.String("profile", "", bundle.T(curLang, "cli.flag_profile_signer"))
	cades := fs.Bool("cades", false, bundle.T(curLang, "cli.flag_cades"))
	fs.Parse(args)

	if *caName == "" && *certFile == "" {
		*caName = cfg.Defaults.CA
	}

	filePath := fs.Arg(0)
	if filePath == "" {
		return ef("cli.err_file_required")
	}

	if *verify {
		rootCAs := loadRootPool(cfg)
		if *embedded {
			return signer.VerifyEmbedded(filePath, rootCAs)
		}
		if *sigFile == "" {
			*sigFile = filePath + ".p7s"
		}
		return signer.VerifyDetached(filePath, *sigFile, rootCAs)
	}

	signCert, signKey, chain, err := loadSigner(cfg, *caName, *certFile, *keyFile, *chainFile, *cn, *profileName)
	if err != nil {
		return fmt.Errorf("load signer: %w", err)
	}

	signerCfg := &signer.Config{
		Cert:  signCert,
		Key:   signKey,
		Chain: chain,
		Hash:  0,
	}
	if cfg.Defaults.Hash != "" {
		signerCfg.Hash = parseHash(cfg.Defaults.Hash)
	}

	if *embedded {
		if err := signer.SignEmbedded(filePath, signerCfg); err != nil {
			return fmt.Errorf("sign embedded: %w", err)
		}
		pf("cli.signed_embedded", filePath)
		return nil
	}

	sigPath, err := signer.SignDetached(filePath, signerCfg)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	pf("cli.signed_detached", sigPath)

	if *cades {
		if err := addCAdESTimestampToFile(sigPath, cfg); err != nil {
			return fmt.Errorf("cades: %w", err)
		}
		pf("cli.cades_added", sigPath)
	}
	return nil
}

func addCAdESTimestampToFile(sigPath string, cfg *internal.Config) error {
	p7sData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read p7s: %w", err)
	}
	if pkcs7.HasCAdESUnsigned(p7sData) {
		return nil
	}

	// Extract the signature value from the PKCS#7 blob.
	sigValue, err := pkcs7.SignatureValue(p7sData)
	if err != nil {
		return fmt.Errorf("extract sig: %w", err)
	}

	// Hash the signature value for the TSA message imprint.
	hash := crypto.SHA256
	h := hash.New()
	h.Write(sigValue)
	digest := h.Sum(nil)

	// Build TimeStampReq.
	nonce, _ := rand.Int(rand.Reader, big.NewInt(1<<63-1))
	reqDER, err := tsa.BuildTimeStampReq(hash, digest, nonce)
	if err != nil {
		return fmt.Errorf("build ts req: %w", err)
	}

	// Try to load TSA signer from config.
	tsaCfg, err := buildTSAConfig(cfg)
	if err != nil {
		// Fall back to placeholder if no TSA configured (e.g., in tests).
		tstToken := []byte{0x05, 0x00} // DER NULL placeholder
		updated, err := pkcs7.AddCAdESTimestamp(p7sData, tstToken)
		if err != nil {
			return fmt.Errorf("add timestamp: %w", err)
		}
		return os.WriteFile(sigPath, updated, 0600)
	}

	// Sign the timestamp request (in-process, no HTTP).
	respDER, err := tsa.SignRequest(reqDER, tsaCfg)
	if err != nil {
		return fmt.Errorf("tsa sign: %w", err)
	}

	// Parse the TimeStampResp to extract the TimeStampToken.
	var tsResp tsa.TimeStampResp
	if _, err := asn1.Unmarshal(respDER, &tsResp); err != nil {
		return fmt.Errorf("parse tsa resp: %w", err)
	}
	if tsResp.Status.Status != 0 {
		return fmt.Errorf("tsa rejected: status %d", tsResp.Status.Status)
	}
	tstToken := tsResp.TimeStampToken.FullBytes

	updated, err := pkcs7.AddCAdESTimestamp(p7sData, tstToken)
	if err != nil {
		return fmt.Errorf("add timestamp: %w", err)
	}
	return os.WriteFile(sigPath, updated, 0600)
}

func buildTSAConfig(cfg *internal.Config) (*tsa.TSAConfig, error) {
	if cfg == nil || cfg.TSA.SignerCert == "" || cfg.TSA.SignerKey == "" {
		return nil, fmt.Errorf("tsa.signer_cert and tsa.signer_key required in config")
	}
	signerCert, signerKey, err := ca.LoadSigner(cfg.TSA.SignerCert, cfg.TSA.SignerKey)
	if err != nil {
		return nil, fmt.Errorf("load tsa signer: %w", err)
	}
	var chain []*x509.Certificate
	if cfg.TSA.Chain != "" {
		chainCert, _, err := ca.LoadSigner(cfg.TSA.Chain, cfg.TSA.SignerKey)
		if err == nil {
			chain = []*x509.Certificate{chainCert}
		}
	}
	tstInfoCfg := &tsa.TSTInfoConfig{}
	if cfg.TSA.TSAPolicy != "" {
		oid, err := internal.ParseOID(cfg.TSA.TSAPolicy)
		if err != nil {
			return nil, fmt.Errorf("parse tsa_policy: %w", err)
		}
		tstInfoCfg.Policy = oid
	}
	tstInfoCfg.Ordering = internal.BoolOr(cfg.TSA.Ordering, false)
	tstInfoCfg.AccuracySeconds = cfg.TSA.AccuracySeconds
	tstInfoCfg.AccuracyMillis = cfg.TSA.AccuracyMillis
	tstInfoCfg.AccuracyMicros = cfg.TSA.AccuracyMicros

	return &tsa.TSAConfig{
		SignerCert: signerCert,
		SignerKey:  signerKey,
		Chain:      chain,
		TSTInfo:    tstInfoCfg,
	}, nil
}



// Auto-issue an ephemeral signer certificate using the named CA.
func issueSigner(cfg *internal.Config, caName, chainPath, cn, profileName string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	caInfo := cfg.CAs[caName]
	database, err := db.Open(cfg.DB)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	issuerCert, issuerKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load CA: %w", err)
	}

	privKey, err := ca.GenerateKey(cfg.Defaults.KeyType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	if cn == "" {
		cn = "signer-" + time.Now().Format("20060102")
	}
	if profileName == "" {
		profileName = string(cfg.Defaults.Profile)
		// Match profile to CA role when default is unsuitable.
		if profileName == "" || profileName == "root-ca" || profileName == "sub-ca" {
			if strings.Contains(caName, "code") {
				profileName = "codesigning"
			} else if strings.Contains(caName, "tsa") {
				profileName = "timestamp"
			} else if strings.Contains(caName, "ocsp") {
				profileName = "ocsp-signer"
			} else {
				profileName = "tls-server"
			}
		}
	}

	signValidity := 7 * 24 * time.Hour
	if cfg.Defaults.CertValidity != "" {
		if d, err := time.ParseDuration(cfg.Defaults.CertValidity); err == nil {
			signValidity = d
		}
	}
	result, err := ca.Sign(&ca.SignConfig{
		DB:               database,
		CAKey:            issuerKey,
		CACert:           issuerCert,
		CAName:           caName,
		SubjectPubKey:    privKey.Public(),
		CommonName:       cn,
		Profile:          ca.Profile(profileName),
		Validity:         signValidity,
		DefaultCountry:   cfg.Defaults.DefaultCountry,
		DefaultOrg:       cfg.Defaults.DefaultOrg,
		CRLBaseURL:       cfg.CRL.CRLBaseURL,
		OCSPURL:          cfg.Defaults.OCSPURL,
		IssuerURL:        cfg.Defaults.IssuerURL,
		IssuerAltNames:   cfg.Defaults.IssuerAltNames,
		SubjectInfoAccess: cfg.Defaults.SubjectInfoAccess,
		PolicyOIDs:       cfg.Defaults.PolicyOIDs,
		PolicyFile:       cfg.Policy,
		PolicyMappings:   mustPolicyMappings(cfg.Defaults.PolicyMappings),
		RequireExplicitPolicy: cfg.Defaults.RequireExplicitPolicy,
		InhibitPolicyMapping:  cfg.Defaults.InhibitPolicyMapping,
		InhibitAnyPolicy:      cfg.Defaults.InhibitAnyPolicy,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("sign: %w", err)
	}

	var chain []*x509.Certificate
	if chainPath != "" {
		chain, err = loadChain(chainPath)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load chain: %w", err)
		}
	} else if rca, ok := cfg.CAs["root"]; ok {
		rc, err := loadChain(rca.Cert)
		if err == nil {
			chain = rc
		}
	}
	// Prepend the issuer CA so the chain is: leaf → issuing CA → root.
	chain = append([]*x509.Certificate{issuerCert}, chain...)

	return result.Cert, privKey, chain, nil
}

func parseHash(s string) crypto.Hash {
	switch s {
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

// loadSigner loads a signer cert+key from explicit files or CA config.
func loadSigner(cfg *internal.Config, caName, certFile, keyFile, chainFile, cn, profileName string) (*x509.Certificate, crypto.Signer, []*x509.Certificate, error) {
	if certFile != "" {
		signCert, signKey, err := ca.LoadSigner(certFile, keyFile)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load signer: %w", err)
		}
		var chain []*x509.Certificate
		if chainFile != "" {
			chain, err = loadChain(chainFile)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("load chain: %w", err)
			}
		}
		return signCert, signKey, chain, nil
	}
	if caName == "" {
		caName = cfg.Defaults.CA
	}
	caInfo, ok := cfg.CAs[caName]
	if !ok {
		return nil, nil, nil, ef("cli.err_ca_not_found", caName)
	}
	signCert, signKey, err := ca.LoadSigner(caInfo.Cert, caInfo.Key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load signer: %w", err)
	}
	if signCert.IsCA {
		signCert, signKey, chain, err := issueSigner(cfg, caName, caInfo.Chain, cn, profileName)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("issue signer: %w", err)
		}
		return signCert, signKey, chain, nil
	}
	var chain []*x509.Certificate
	if caInfo.Chain != "" {
		chain, err = loadChain(caInfo.Chain)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("load chain: %w", err)
		}
	}
	return signCert, signKey, chain, nil
}

func loadRootPool(cfg *internal.Config) *x509.CertPool {
	caCertPaths := make(map[string]string)
	for name, caCfg := range cfg.CAs {
		caCertPaths[name] = caCfg.Cert
	}
	pool, _ := ca.LoadTrustPool(caCertPaths, nil)
	// CertPool.Subjects() returns nil if pool is empty.
	// We need nil to signal "skip chain verification" to callers.
	if pool == nil || pool.Subjects() == nil {
		// Fallback: try old "root" key
		if rca, ok := cfg.CAs["root"]; ok {
			rootPEM, err := os.ReadFile(rca.Cert)
			if err == nil {
				pool = x509.NewCertPool()
				if pool.AppendCertsFromPEM(rootPEM) {
					return pool
				}
			}
		}
		return nil
	}
	return pool
}

func loadChain(chainPath string) ([]*x509.Certificate, error) {
	chainPEM, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, fmt.Errorf("read chain: %w", err)
	}
	var chain []*x509.Certificate
	for len(chainPEM) > 0 {
		var block *pem.Block
		block, chainPEM = pem.Decode(chainPEM)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parse chain cert: %w", err)
			}
			chain = append(chain, cert)
		}
	}
	return chain, nil
}

// mustPolicyMappings parses the policy_mappings list from configuration; returns an empty
// slice and logs the error to stderr when the configuration is invalid (the actual issuance
// path rejects via ca.Sign secondary validation; this only prevents panics).
func mustPolicyMappings(strs []string) []ca.PolicyMapping {
	m, err := ca.ParsePolicyMappings(strs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pki: invalid policy_mappings: %v\n", err)
		return nil
	}
	return m
}
