package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/core/auth"
	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/engine/db"
)

var fullInitSubCAs = []struct {
	Name         string
	DisplayAlias string
	KeyType      string
	Purpose      string
}{
	{"management", "Management", "ecdsa-p256", "Management client certs (admin/operator/auditor/readonly)"},
	{"tls", "TLS", "ecdsa-p256", "TLS/OCSP/gateway service certs"},
	{"agent", "Agent", "ecdsa-p256", "AI Agent certs (AIC extension)"},
	{"codesign", "CodeSign", "rsa-4096", "Code signing certs"},
	{"tsa", "TSA", "rsa-4096", "Timestamp signing certs"},
	{"hr", "HR", "ecdsa-p256", "HR department certs"},
	{"vpn", "VPN", "ecdsa-p256", "VPN client certs (WireGuard/OpenVPN)"},
	{"acme", "ACME", "ecdsa-p256", "ACME/SCEP auto-enrollment"},
}

// serviceCertDef defines service certificates to be auto-issued during init-full.
type serviceCertDef struct {
	Name       string   // directory name
	CN         string   // CommonName
	Profile    string   // certificate profile
	SANs       []string // SAN (used for server certificates)
	SubCAName  string   // issuing sub-CA name (must exist in fullInitSubCAs)
	SubDir     string   // sub-directory (e.g., ocsp issues ocsp-signer)
	CAScope    string   // admin scope: which CAs this admin can manage
}

func cmdInitFull(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("init-full", flag.ExitOnError)
	rootName := fs.String("root", "",  bundle.T(curLang, "cli.flag_root_name"))
	defaultKeyType := fs.String("default-key-type", "ecdsa-p384", bundle.T(curLang, "cli.flag_root_key_type"))
	valDays := fs.Int("root-validity", 7300, bundle.T(curLang, "cli.flag_root_validity"))
	org := fs.String("org", "", bundle.T(curLang, "cli.flag_org"))
	country := fs.String("country", "CN", bundle.T(curLang, "cli.flag_country"))
	baseDir := fs.String("out-dir", "./pki", bundle.T(curLang, "cli.flag_out_dir"))
	encPassword := fs.String("encrypt-keys", "", bundle.T(curLang, "cli.flag_encrypt_keys"))
	hierarchy := fs.String("hierarchy", "simple", "CA hierarchy: simple(3-layer) | enterprise(4-layer)")
	importRootCert := fs.String("import-root-cert", "", "Path to existing Root CA cert PEM (skip root creation)")
	importRootKey := fs.String("import-root-key", "", "Path to existing Root CA key PEM (skip root creation)")
	domain := fs.String("domain", "", "Domain for server certificates (SAN)")
		configOut := fs.String("config-out", "", "Path to generated config file")
		adminNames := fs.String("admin-names", "", "Admin real names: John(superadmin),Jane(operator)...")
		skipServiceCerts := fs.Bool("skip-service-certs", false, "Skip automatic service certificate issuance")
		authzFile := fs.String("authorization-file", "", "Path to authz.json policy (default: write built-in authz.json to --out-dir)")
		fs.Parse(args)
		authzPath := *authzFile
		if *org == "" {
		return fmt.Errorf("--org is required (e.g. --org MyCorp)")
		}
		if *domain == "" {
		return fmt.Errorf("--domain is required (e.g. --domain mycorp.com)")
		}
		// Derive root CA name from org if not explicitly set
		if *rootName == "" {
		*rootName = *org + " Root CA"
		}

		// Parse --admin-names: "John(admin),Jane(operator)" → replace default role certs
		// superadmin is the full-featured certificate required for bootstrapping (the only role with all PA grants under cert-first).
		adminCerts := []serviceCertDef{
		{"superadmin", "superadmin@" + *domain, "m-superadmin", nil, "management", "users", ""},
		{"admin", "admin@" + *domain, "m-admin", nil, "management", "users", ""},
		{"operator", "operator@" + *domain, "m-operator", nil, "management", "users", ""},
		{"auditor", "auditor@" + *domain, "m-auditor", nil, "management", "users", ""},
		{"readonly", "readonly@" + *domain, "m-readonly", nil, "management", "users", ""},
		{"auto-renew", "auto-renew@" + *domain, "m-auto-renew", nil, "management", "users", ""},
	}
	if *adminNames != "" {
		adminCerts = nil
		for _, entry := range strings.Split(*adminNames, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			// Parse "name(role)"
			paren := strings.Index(entry, "(")
			if paren < 0 || !strings.HasSuffix(entry, ")") {
				return fmt.Errorf("invalid admin-names entry: %s (need name(role))", entry)
			}
			name := entry[:paren]
			role := entry[paren+1 : len(entry)-1]
			var profile string
			switch role {
			case "superadmin":
				profile = "m-superadmin"
			case "admin":
				profile = "m-admin"
			case "operator":
				profile = "m-operator"
			case "auditor":
				profile = "m-auditor"
			case "readonly":
				profile = "m-readonly"
			case "auto-renew":
				profile = "m-auto-renew"
			default:
				return fmt.Errorf("unknown admin role: %s (need superadmin|admin|operator|auditor|readonly|auto-renew)", role)
			}
			certName := "user-" + role + "-" + name
			adminCerts = append(adminCerts, serviceCertDef{certName, name, profile, nil, "management", "users", ""})
		}
	}

	cfg.Defaults.DefaultOrg = *org
	cfg.Defaults.DefaultCountry = *country
	if cfg.Defaults.OCSPURL == "" {
		cfg.Defaults.OCSPURL = "http://ocsp." + *domain + "/ocsp"
	}
	if cfg.Defaults.IssuerURL == "" {
		cfg.Defaults.IssuerURL = "http://" + *domain + "/pki"
	}
	if cfg.CRL.CRLBaseURL == "" {
		cfg.CRL.CRLBaseURL = "http://" + *domain + "/crl"
	}

	// Use database in output directory (init-full creates a fresh PKI)
	dbPath := filepath.Join(*baseDir, "pki.db")
	database, err := db.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()

	fmt.Println(bundle.T(curLang, "cli.init_full_banner"))
	fmt.Println(bundle.T(curLang, "cli.init_full_root_info", *rootName, *defaultKeyType, *valDays))

	rootDir := filepath.Join(*baseDir, "root")
	os.MkdirAll(rootDir+"/certs", 0755)
	os.MkdirAll(rootDir+"/private", 0755)
	rootCert := filepath.Join(rootDir, "certs", "ca.pem")
	rootKey := filepath.Join(rootDir, "private", "ca.key")

	// ---- Root CA ----
	// Validate import-root pair
	if (*importRootCert != "") != (*importRootKey != "") {
		return fmt.Errorf("--import-root-cert and --import-root-key must be used together")
	}
	if *importRootCert != "" && *importRootKey != "" {
		// Import existing root (passwordless keys)
		if err := copyFile(*importRootCert, rootCert); err != nil {
			return fmt.Errorf("copy root cert: %w", err)
		}
		if err := copyFile(*importRootKey, rootKey); err != nil {
			return fmt.Errorf("copy root key: %w", err)
		}
		fmt.Println("  root CA imported:", *importRootCert)
		// Register existing root in DB
		rootCertDER, err := os.ReadFile(rootCert)
		if err != nil {
			return fmt.Errorf("read root cert: %w", err)
		}
		rootParsed, err := x509.ParseCertificate(rootCertDER)
		if err != nil {
			return fmt.Errorf("parse root cert: %w", err)
		}
		if err := database.InsertCAMeta(&db.CAMeta{
			Name:    *rootName,
			CertDER: rootParsed.Raw,
		}); err != nil {
			return fmt.Errorf("import root to db: %w", err)
		}
	} else {
		if _, err := os.Stat(rootCert); err == nil {
			fmt.Println(bundle.T(curLang, "cli.init_full_skip"))
		} else {
			if err := createCA(database, cfg, caCreateOpts{
				name: *rootName, profile: "root-ca",
				keyType: *defaultKeyType, validity: *valDays,
				certPath: rootCert, keyPath: rootKey, password: *encPassword,
			}); err != nil {
				return err
			}
			fmt.Println(bundle.T(curLang, "cli.init_full_root_done", rootCert))
		}
	}

	// Determine which name to sign sub-CAs under
	immediateParentName := *rootName
	immediateParentKey := rootKey
	policyCADir := ""

	// ---- Enterprise: Policy CA (L2) ----
	if *hierarchy == "enterprise" {
		policyCADir = filepath.Join(*baseDir, "policy")
		os.MkdirAll(policyCADir+"/certs", 0755)
		os.MkdirAll(policyCADir+"/private", 0755)
		policyCert := filepath.Join(policyCADir, "certs", "ca.pem")
		policyKey := filepath.Join(policyCADir, "private", "ca.key")

		if _, err := os.Stat(policyCert); err == nil {
			fmt.Println("  policy CA already exists, skip")
		} else {
			if err := createSubCA(database, cfg, caCreateOpts{
				name: *org + " Policy CA", profile: "policy-ca",
				keyType: *defaultKeyType, validity: *valDays / 2,
				certPath: policyCert, keyPath: policyKey, password: *encPassword,
				parentName: immediateParentName, parentKeyPath: immediateParentKey,
			}); err != nil {
				return err
			}
			fmt.Println("  policy CA created:", policyCert)
		}
		immediateParentName = *org + " Policy CA"
		immediateParentKey = policyKey
	}

	// ---- Sub-CAs (L3) ----
	for _, sub := range fullInitSubCAs {
		subDir := filepath.Join(*baseDir, sub.Name)
		os.MkdirAll(subDir+"/certs", 0755)
		os.MkdirAll(subDir+"/private", 0755)
		subCert := filepath.Join(subDir, "certs", "ca.pem")
		subKey := filepath.Join(subDir, "private", "ca.key")

		if _, err := os.Stat(subCert); err == nil {
			fmt.Println(bundle.T(curLang, "cli.init_full_sub_skip", sub.Name))
			continue
		}
		var nameConstraints *ca.NameConstraints
		if sub.Name == "acme" {
			nameConstraints = &ca.NameConstraints{
				PermittedDomains: []string{*domain},
			}
		}
		subName := *org + " " + sub.DisplayAlias + " CA"
		if err := createSubCA(database, cfg, caCreateOpts{
			name: subName, profile: "sub-ca",
			keyType: sub.KeyType, validity: 1825,
			certPath: subCert, keyPath: subKey, password: *encPassword,
			parentName: immediateParentName, parentKeyPath: immediateParentKey,
			nameConstraints: nameConstraints,
		}); err != nil {
			return err
		}
		fmt.Println(bundle.T(curLang, "cli.init_full_sub_done", sub.Name, sub.Purpose, subCert))
	}

	// ---- Service Certs ----
	// Load authorization policy (authz.json) so management certificates like m-superadmin
	// automatically carry full PrincipalAuthorization grants during issuance (cert-first bootstrap depends on this).
	if authzPath == "" {
		authzPath = filepath.Join(*baseDir, "authz.json")
		if err := os.WriteFile(authzPath, auth.DefaultAuthzJSON, 0644); err != nil {
			return fmt.Errorf("write built-in authz.json: %w", err)
		}
		fmt.Println("  authorization policy:", authzPath)
	}
	if p, err := auth.LoadPolicy(authzPath); err != nil {
		return fmt.Errorf("load authorization policy: %w", err)
	} else {
		auth.SetPolicy(p)
	}

	if !*skipServiceCerts {
					// Infrastructure certs (always issued)
			infraCerts := []serviceCertDef{
				{"ocsp", "ocsp." + *domain, "ocsp-signer", nil, "tls", "ocsp", ""},
				{"api", *domain, "tls-server", []string{"DNS:" + *domain}, "tls", "api", ""},
				{"gateway", "gateway." + *domain, "tls-server", []string{"DNS:gateway." + *domain}, "tls", "gateway", ""},
				{"tsa-signer", "tsa." + *domain, "timestamp", nil, "tsa", "tsa", ""},
			}
			// Combine: infra + admins
		serviceCerts := append(infraCerts, adminCerts...)
		for _, s := range serviceCerts {
			subDir := filepath.Join(*baseDir, s.SubCAName)
			srvDir := filepath.Join(subDir, s.SubDir)
			os.MkdirAll(srvDir+"/certs", 0755)
			os.MkdirAll(srvDir+"/private", 0755)
			certPath := filepath.Join(srvDir, "certs", s.Name+".pem")
			keyPath := filepath.Join(srvDir, "private", s.Name+".key")
			if _, err := os.Stat(certPath); err == nil {
				fmt.Println("  service cert already exists:", s.Name)
				continue
			}
			if err := issueServiceCert(database, cfg, *baseDir, *org, s, certPath, keyPath, *encPassword); err != nil {
				return fmt.Errorf("issue %s: %w", s.Name, err)
			}
			fmt.Println("  service cert issued:", certPath)
		}
	}

	// ---- Generate Config ----
	if *configOut == "" {
		*configOut = filepath.Join(*baseDir, "pki.json")
	}
		if err := generateConfig(*baseDir, *configOut, *domain, *org, authzPath); err != nil {
			return fmt.Errorf("generate config: %w", err)
		}
		fmt.Println("  config file:", *configOut)

	// ---- Initial CRLs ----
	// Generate initial empty CRLs for each issuing CA to prevent healthz from reporting
	// "crl_status: error: no CRL found" (degraded) on first startup.
	crlOut := filepath.Join(*baseDir, "crl")
	os.MkdirAll(crlOut, 0755)
	crlIssuers := []struct{ dir, caName string }{
		{filepath.Join(*baseDir, "management"), *org + " Management CA"},
		{filepath.Join(*baseDir, "tls"), *org + " TLS CA"},
		{filepath.Join(*baseDir, "agent"), *org + " Agent CA"},
		{filepath.Join(*baseDir, "codesign"), *org + " CodeSign CA"},
		{filepath.Join(*baseDir, "tsa"), *org + " TSA CA"},
		{filepath.Join(*baseDir, "hr"), *org + " HR CA"},
		{filepath.Join(*baseDir, "vpn"), *org + " VPN CA"},
		{filepath.Join(*baseDir, "acme"), *org + " ACME CA"},
	}
	if policyCADir != "" {
		crlIssuers = append(crlIssuers, struct{ dir, caName string }{policyCADir, *org + " Policy CA"})
	}
	for _, c := range crlIssuers {
		certFile := filepath.Join(c.dir, "certs", "ca.pem")
		keyFile := filepath.Join(c.dir, "private", "ca.key")
		if _, err := os.Stat(certFile); err != nil {
			continue // CA directory does not exist (may have been skipped)
		}
		caCert, caKey, err := ca.LoadSigner(certFile, keyFile, *encPassword)
		if err != nil {
			return fmt.Errorf("load CA %q for initial CRL: %w", c.caName, err)
		}
		crlDER, err := ca.GenerateCRL(&ca.CRLConfig{
			DB:           database,
			CACert:       caCert,
			CAKey:        caKey,
			CAName:       c.caName,
			ValidityDays: 30,
		})
		if err != nil {
			return fmt.Errorf("generate initial CRL for %q: %w", c.caName, err)
		}
		if err := os.WriteFile(filepath.Join(crlOut, ca.SanitizeCAName(c.caName)+".crl"), crlDER, 0644); err != nil {
			return fmt.Errorf("write initial CRL for %q: %w", c.caName, err)
		}
		fmt.Println("  initial CRL:", c.caName)
	}

	// ---- Summary ----
	fmt.Println()
	fmt.Println(bundle.T(curLang, "cli.init_full_done"))
	fmt.Println(bundle.T(curLang, "cli.init_full_dir", *baseDir))
	if *hierarchy == "enterprise" {
		fmt.Println("  └── policy CA (L2 strategy buffer)")
		for _, sub := range fullInitSubCAs {
			fmt.Println("        └──", sub.Name, "-", sub.Purpose)
		}
	} else {
		for _, sub := range fullInitSubCAs {
			fmt.Println("  └──", sub.Name, "-", sub.Purpose)
		}
	}
	fmt.Println("  └── service certs: ocsp, tsa-signer, api, superadmin + admin + roles")
	fmt.Println()
	fmt.Println(bundle.T(curLang, "cli.init_full_usage_title"))
				fmt.Println("  cd " + *baseDir + " && pki serve")
		fmt.Println("  pki issue --ca " + *org + " TLS CA" + " --cn my-server --san DNS:my-server." + *domain + " --profile tls-server")
	fmt.Println()
		if *encPassword != "" {
			fmt.Println()
			fmt.Println("  ⚠ Keys encrypted with --encrypt-keys.")
			fmt.Println("  Set PKI_KEY_PASSWORD env var or add password to each CA in pki.json")
			fmt.Println("  before running pki serve.")
			fmt.Println("    export PKI_KEY_PASSWORD=" + *encPassword)
			fmt.Println("    cd " + *baseDir + " && pki serve")
		}
	return nil
}

// issueServiceCert issues a single service certificate.
func issueServiceCert(database *db.DB, cfg *internal.Config, baseDir string, orgName string, s serviceCertDef, certPath, keyPath, encPassword string) error {
	subCAName := orgName + " " + subDisplayName(s.SubCAName) + " CA"
	subCADir := filepath.Join(baseDir, s.SubCAName)
	subCertFile := filepath.Join(subCADir, "certs", "ca.pem")
	subKeyFile := filepath.Join(subCADir, "private", "ca.key")

	issuerCert, issuerKey, err := ca.LoadSigner(subCertFile, subKeyFile, encPassword)
	if err != nil {
		return fmt.Errorf("load sub-ca %q: %w", s.SubCAName, err)
	}

	privKey, err := ca.GenerateKey("ecdsa-p256")
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	signCfg := &ca.SignConfig{
		DB:             database,
		CAKey:          issuerKey,
		CACert:         issuerCert,
		CAName:         subCAName,
		CommonName:     s.CN,
		SubjectPubKey:  privKey.Public(),
		Profile:        ca.Profile(s.Profile),
		Hash:           cfg.Defaults.Hash,
		Validity:       365 * 24 * time.Hour,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
		OCSPURL:        cfg.Defaults.OCSPURL,
		IssuerURL:      cfg.Defaults.IssuerURL,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
		DefaultCountry: cfg.Defaults.DefaultCountry,
	}
	if s.CAScope != "" {
		signCfg.CAScope = []string{s.CAScope}
	}
	if len(s.SANs) > 0 {
		signCfg.SANs = s.SANs
	}
	// OCSP signer needs MustStaple
	if s.Profile == "ocsp-signer" {
		signCfg.MustStaple = true
		signCfg.ExtraEKUOIDs = []string{"1.3.6.1.5.5.7.3.9"}
	}

	result, err := ca.Sign(signCfg)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if err := os.WriteFile(certPath, ca.CertToPEM(result.CertDER), 0644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return err
	}
	return os.WriteFile(keyPath, pemEncode("PRIVATE KEY", keyDER), 0600)
}

// generateConfig generates a ready-to-use pki.json configuration file.
func generateConfig(baseDir, configPath, domain, org, authzPath string) error {
	absBase, _ := filepath.Abs(baseDir)
	cfg := map[string]any{
		"db": filepath.Join(absBase, "pki.db"),
		"authorization_file": authzPath,
		"defaults": map[string]any{
			"org":        org,
			"country":    "CN",
			"domain":     domain,
			"hash":       "sha256",
			"ca":         org + " TLS CA",
			"ocsp_url":   "http://ocsp." + domain + "/ocsp",
			"issuer_url": "http://" + domain + "/pki",
		},
		"serve": map[string]any{
			"addr":     ":443",
			"api_addr": "127.0.0.1:9081",
			"tls_cert": filepath.Join(absBase, "tls", "api", "certs", "api.pem"),
			"tls_key":  filepath.Join(absBase, "tls", "api", "private", "api.key"),
		},
		"ca_defaults": map[string]any{
			"ocsp_url":   "http://ocsp." + domain + "/ocsp",
			"issuer_url": "http://" + domain + "/pki",
		},
		"cas": map[string]any{
			org + " Root CA": map[string]any{
				"cert": filepath.Join(absBase, "root", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "root", "private", "ca.key"),
			},
			org + " Management CA": map[string]any{
				"cert": filepath.Join(absBase, "management", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "management", "private", "ca.key"),
			},
			org + " TLS CA": map[string]any{
				"cert": filepath.Join(absBase, "tls", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "tls", "private", "ca.key"),
			},
			org + " Agent CA": map[string]any{
				"cert": filepath.Join(absBase, "agent", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "agent", "private", "ca.key"),
			},
			org + " CodeSign CA": map[string]any{
				"cert": filepath.Join(absBase, "codesign", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "codesign", "private", "ca.key"),
			},
			org + " TSA CA": map[string]any{
				"cert": filepath.Join(absBase, "tsa", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "tsa", "private", "ca.key"),
			},
			org + " HR CA": map[string]any{
				"cert": filepath.Join(absBase, "hr", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "hr", "private", "ca.key"),
			},
			org + " VPN CA": map[string]any{
				"cert": filepath.Join(absBase, "vpn", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "vpn", "private", "ca.key"),
			},
			org + " ACME CA": map[string]any{
				"cert": filepath.Join(absBase, "acme", "certs", "ca.pem"),
				"key":  filepath.Join(absBase, "acme", "private", "ca.key"),
			},
		},
		"tsa": map[string]any{
			"addr":        ":3180",
			"signer_cert": filepath.Join(absBase, "tsa", "tsa", "certs", "tsa-signer.pem"),
			"signer_key":  filepath.Join(absBase, "tsa", "tsa", "private", "tsa-signer.key"),
		},
		"ocsp": map[string]any{
			"addr":        "127.0.0.1:9080",
			"signer_cert": filepath.Join(absBase, "tls", "ocsp", "certs", "ocsp.pem"),
			"signer_key":  filepath.Join(absBase, "tls", "ocsp", "private", "ocsp.key"),
		},
		"crl": map[string]any{
			"addr":          ":8081",
			"crl_base_url":  "http://" + domain + "/crl",
			"validity_days": 30,
			"output_dir":    filepath.Join(absBase, "crl"),
			"renew_interval": "24h",
		},
		"gateway": map[string]any{
			"addr":     ":9443",
			"tls_cert": filepath.Join(absBase, "tls", "gateway", "certs", "gateway.pem"),
			"tls_key":  filepath.Join(absBase, "tls", "gateway", "private", "gateway.key"),
			"ca":       org + " TLS CA",
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configPath, data, 0644)
}

// subDisplayName returns the display name for a sub-CA.
func subDisplayName(name string) string {
	for _, s := range fullInitSubCAs {
		if s.Name == name {
			return s.DisplayAlias
		}
	}
	return name
}

// copyFile performs a simple file copy.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

type caCreateOpts struct {
	name, displayName, profile, keyType     string
	validity, maxPathLen                    int
	certPath, keyPath, password string
	parentName, parentKeyPath  string
	subject                    string
	nameConstraints            *ca.NameConstraints
}

func createCA(database *db.DB, cfg *internal.Config, o caCreateOpts) error {
	cc := &ca.CreateConfig{
		DB:             database,
		Name:           o.name,
		Profile:        ca.Profile(o.profile),
		KeyType:        o.keyType,
		Validity:       time.Duration(o.validity) * 24 * time.Hour,
		DefaultCountry: cfg.Defaults.DefaultCountry,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
		MaxPathLen:     o.maxPathLen,
		OCSPURL:        cfg.Defaults.OCSPURL,
		IssuerURL:      cfg.Defaults.IssuerURL,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
	}

	r, err := ca.CreateCA(cc)
	if err != nil {
		return fmt.Errorf("create %s: %w", o.name, err)
	}

	if err := os.WriteFile(o.certPath, ca.CertToPEM(r.CertDER), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyPEM, err := ca.KeyToPEM(r.Signer)
	if err != nil {
		return fmt.Errorf("key pem: %w", err)
	}
	if o.password != "" {
		enc, err := ca.EncryptKeyPKCS8(r.Signer, o.password)
		if err != nil {
			return fmt.Errorf("encrypt key: %w", err)
		}
		keyPEM = pemEncode("ENCRYPTED PRIVATE KEY", enc)
	}
	return os.WriteFile(o.keyPath, keyPEM, 0600)
}

func createSubCA(database *db.DB, cfg *internal.Config, o caCreateOpts) error {
	parentMeta, err := database.GetCAMeta(o.parentName)
	if err != nil {
		return fmt.Errorf("load parent %q: %w", o.parentName, err)
	}
	parentCert, err := x509.ParseCertificate(parentMeta.CertDER)
	if err != nil {
		return fmt.Errorf("parse parent cert: %w", err)
	}
	parentKey, err := ca.LoadPrivateKey(o.parentKeyPath, o.password)
	if err != nil {
		return fmt.Errorf("load parent key: %w", err)
	}

	cc := &ca.CreateConfig{
		DB:             database,
		Name:           o.name,
		Profile:        ca.Profile(o.profile),
		KeyType:        o.keyType,
		Validity:       time.Duration(o.validity) * 24 * time.Hour,
		Parent:         parentCert,
		ParentKey:      parentKey,
		DefaultCountry: cfg.Defaults.DefaultCountry,
		DefaultOrg:     cfg.Defaults.DefaultOrg,
		OCSPURL:        cfg.Defaults.OCSPURL,
		IssuerURL:      cfg.Defaults.IssuerURL,
		CRLBaseURL:     cfg.CRL.CRLBaseURL,
	}

	if o.nameConstraints != nil {
		cc.PermittedDomains = o.nameConstraints.PermittedDomains
		cc.ExcludedDomains = o.nameConstraints.ExcludedDomains
		cc.PermittedEmails = o.nameConstraints.PermittedEmails
		cc.ExcludedEmails = o.nameConstraints.ExcludedEmails
		cc.PermittedURIs = o.nameConstraints.PermittedURIs
		cc.ExcludedURIs = o.nameConstraints.ExcludedURIs
		cc.PermittedIPRanges = o.nameConstraints.PermittedIPRanges
		cc.ExcludedIPRanges = o.nameConstraints.ExcludedIPRanges
	}

	r, err := ca.CreateCA(cc)
	if err != nil {
		return fmt.Errorf("create %s: %w", o.name, err)
	}

	if err := os.WriteFile(o.certPath, ca.CertToPEM(r.CertDER), 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}

	keyPEM, err := ca.KeyToPEM(r.Signer)
	if err != nil {
		return fmt.Errorf("key pem: %w", err)
	}
	if o.password != "" {
		enc, err := ca.EncryptKeyPKCS8(r.Signer, o.password)
		if err != nil {
			return fmt.Errorf("encrypt key: %w", err)
		}
		keyPEM = pemEncode("ENCRYPTED PRIVATE KEY", enc)
	}
	return os.WriteFile(o.keyPath, keyPEM, 0600)
}
