// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/i18n"
	"github.com/varwof/core/internal/provisioner"
	"github.com/varwof/core/internal/serve"
	"github.com/varwof/engine/db"
)

// TestUser is a signed end-entity user certificate used as the DA signer for
// AIC issuance (PrincipalUid.keyHash = SPKI SHA-256 of this cert).
type TestUser struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM string
	CN      string
	PUID    string // principal_uid communication string
}

// Env is the embedded server + PKI environment for the load test.
type Env struct {
	opts   Options
	DB     *db.DB
	DBPath string
	Addr   string
	hSrv   *http.Server
	ln     net.Listener

	RootCA    *x509.Certificate
	RootKey   crypto.Signer
	PeopleCA  *x509.Certificate
	PeopleKey crypto.Signer

	AdminUser  string
	AdminPass  string
	APIToken   string
	Users      []TestUser
	caCertPath string
	caKeyPath  string
	caDir      string
	mux        *serve.Server
}

// NewEnv builds the Root→People CA hierarchy, seeds the admin user, starts an
// embedded full varwof-core server on 127.0.0.1, and signs `users` end-entity
// certificates under the People CA (DA signers for AIC issuance).
func NewEnv(opts Options) (*Env, error) {
	slog.SetLogLoggerLevel(slog.LevelError)

	d, err := db.Open(opts.DBPath)
	if err != nil {
		return nil, fmt.Errorf("open db %s: %w", opts.DBPath, err)
	}
	e := &Env{opts: opts, DB: d, DBPath: opts.DBPath,
		AdminUser: "admin", AdminPass: "admin"}

	if err := e.genCA(); err != nil {
		d.Close()
		return nil, err
	}
	if err := e.insertCAsAndSeedUser(); err != nil {
		d.Close()
		return nil, err
	}
	if opts.Scenario == "aic" {
		if err := e.genUsers(opts.Users); err != nil {
			d.Close()
			return nil, err
		}
	}
	if err := e.startServer(); err != nil {
		d.Close()
		return nil, err
	}
	return e, nil
}

// genCA creates a self-signed Root CA and a People sub-CA signed by it.
func (e *Env) genCA() error {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return err
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(20 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create root ca: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return err
	}
	e.RootCA, e.RootKey = rootCert, rootKey

	peopleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	peopleTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "People CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	peopleDER, err := x509.CreateCertificate(rand.Reader, peopleTpl, rootCert, &peopleKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create people ca: %w", err)
	}
	peopleCert, err := x509.ParseCertificate(peopleDER)
	if err != nil {
		return err
	}
	e.PeopleCA, e.PeopleKey = peopleCert, peopleKey
	return nil
}

// writeFile writes a PEM file with the given type and DER bytes.
func writeFile(path, typ string, der []byte) error {
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
		return err
	}
	return nil
}

// insertCAsAndSeedUser records both CAs in ca_meta, writes the People CA key
// pair to disk (for cfg.CAs), and seeds the operator-capable basic-auth user.
func (e *Env) insertCAsAndSeedUser() error {
	if err := e.DB.InsertCAMeta(&db.CAMeta{
		Name: "root", CertDER: e.RootCA.Raw, Subject: e.RootCA.Subject.String(),
		NotBefore: e.RootCA.NotBefore, NotAfter: e.RootCA.NotAfter,
		KeyAlgorithm: "ecdsa-p384", Fingerprint: db.Fingerprint(e.RootCA.Raw),
	}); err != nil {
		return fmt.Errorf("insert root cameta: %w", err)
	}
	if err := e.DB.InsertCAMeta(&db.CAMeta{
		Name: "people", CertDER: e.PeopleCA.Raw, Subject: e.PeopleCA.Subject.String(),
		NotBefore: e.PeopleCA.NotBefore, NotAfter: e.PeopleCA.NotAfter,
		KeyAlgorithm: "ecdsa-p256", Fingerprint: db.Fingerprint(e.PeopleCA.Raw),
	}); err != nil {
		return fmt.Errorf("insert people cameta: %w", err)
	}

	// The CA pair must be on disk for cfg.CAs. For file-backed DBs it sits next
	// to the DB; for remote DSNs (`mysql://…`/`postgres://…`) filepath.Dir would
	// mangle the DSN into a junk `mysql:/…` directory, so write it to a temp dir.
	var dir string
	if strings.Contains(e.DBPath, "://") {
		td, err := os.MkdirTemp("", "bench-cas-*")
		if err != nil {
			return fmt.Errorf("mkdir temp cas dir: %w", err)
		}
		e.caDir = td
		dir = td
	} else {
		dir = filepath.Join(filepath.Dir(e.DBPath), "cas")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	e.caCertPath = filepath.Join(dir, "people.pem")
	e.caKeyPath = filepath.Join(dir, "people.key")
	if err := writeFile(e.caCertPath, "CERTIFICATE", e.PeopleCA.Raw); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(e.PeopleKey)
	if err != nil {
		return err
	}
	if err := writeFile(e.caKeyPath, "PRIVATE KEY", keyDER); err != nil {
		return err
	}

	salt, err := db.GenerateSalt()
	if err != nil {
		return err
	}
	if _, err := e.DB.GetUserByUsername(e.AdminUser); err != nil {
		if err := e.DB.CreateUser(e.AdminUser, db.HashPassword(e.AdminPass, salt), salt, "admin"); err != nil {
			return fmt.Errorf("seed admin: %w", err)
		}
	}
	return nil
}

// genUsers signs `n` end-entity user certificates under the People CA, each
// carrying a PrincipalAuthorization grant of cert:issue so they are usable as
// DA signer certificates.
func (e *Env) genUsers(n int) error {
	e.Users = make([]TestUser, 0, n)
	for i := 0; i < n; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		cn := fmt.Sprintf("user-%d", i)
		paExt, err := ca.BuildPrincipalAuthorizationExtension(ca.PrincipalAuthorizationConfig{
			Grants: []ca.Capability{
				{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"},
			},
		})
		if err != nil {
			return err
		}
		tmpl := &x509.Certificate{
			SerialNumber:    big.NewInt(time.Now().UnixNano() + int64(i)),
			Subject:         pkix.Name{CommonName: cn},
			NotBefore:       time.Now().Add(-time.Hour),
			NotAfter:        time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			ExtraExtensions: []pkix.Extension{paExt},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, e.PeopleCA, &key.PublicKey, e.PeopleKey)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		e.Users = append(e.Users, TestUser{
			Cert:    cert,
			Key:     key,
			CertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
			CN:      cn,
		})
	}
	return nil
}

// startServer builds the internal.Config and startServers-equivalent wiring.
func (e *Env) startServer() error {
	cfg := internal.DefaultConfig()
	cfg.DB = e.DBPath
	cfg.Serve.Addr = e.listenAddr()
	cfg.Serve.Static = ""
	cfg.Serve.TLSAddr = ""
	cfg.Serve.AgentSessionMaxTTL = "24h"
	cfg.Defaults.CA = "people"
	cfg.Defaults.Profile = "tls-client"
	cfg.Defaults.KeyType = "ecdsa-p256"
	cfg.Defaults.Hash = "sha256"
	cfg.Defaults.DefaultCountry = "CN"
	cfg.Defaults.DefaultOrg = "Varwof"
	cfg.Defaults.Realm = "varwof"
	// Apply the device profile preset BEFORE bench overrides engine/record_buffer
	// with explicit values, so the profile's defaults are used where bench did
	// not explicitly set a value.
	if e.opts.DeviceProfile != "" {
		cfg.DeviceProfile = e.opts.DeviceProfile
	}
	cfg.ApplyDeviceProfile()
	cfg.CAs = map[string]internal.CAConfig{
		"people": {Cert: e.caCertPath, Key: e.caKeyPath},
	}
	// Rate limiters: disabled in stress (unlimited) unless configured; keep the
	// limiter off so the bench measures raw ingestion throughput.
	cfg.RateLimit.Enabled = internal.BoolPtr(false)

	// Record-buffer backpressure knob: keep the production default unless the
	// user overrides; -sync disables the write pipeline entirely.
	if e.opts.MaxPending > 0 {
		mp := e.opts.MaxPending
		cfg.RecordBuffer.MaxPending = &mp
	}
	// Engine mode (production architecture): memory-is-truth with async
	// persistence. The default in-memory caps (200K certs / 100K DA nonces)
	// would backpressure within minutes at 4K req/s, so size them for the run.
	// Preserve any engine fields already set by the device profile (e.g.
	// write_workers) by mutating the existing config rather than replacing it.
	if e.opts.Engine {
		if cfg.Engine == nil {
			cfg.Engine = &internal.EngineConfig{}
		}
		if cfg.Engine.MaxCerts <= 0 {
			cfg.Engine.MaxCerts = 10_000_000
		}
		if cfg.Engine.MaxDANonces <= 0 {
			cfg.Engine.MaxDANonces = 20_000_000
		}
		if cfg.Engine.MaxNonces <= 0 {
			cfg.Engine.MaxNonces = 20_000_000
		}
		if e.opts.MaxPending > 0 {
			cfg.Engine.WriteMaxPending = int32(e.opts.MaxPending)
		}
	}

	tsaDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.Write([]byte("tsa-ok"))
	})
	ocspDummy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write([]byte("ocsp-ok"))
	})

	b := i18n.NewBundle()
	mux := serve.NewFull(&cfg, e.DB, b, tsaDummy, ocspDummy)
	mux.Version = "varwof-core/bench"
	e.mux = mux
	if e.opts.Verbose {
		var rbmp int
		if cfg.RecordBuffer.MaxPending != nil {
			rbmp = *cfg.RecordBuffer.MaxPending
		}
		fmt.Fprintf(os.Stderr, "bench config: profile=%q record_buffer{threshold=%d max_pending=%d}", cfg.DeviceProfile, cfg.RecordBuffer.Threshold, rbmp)
		if cfg.Engine != nil {
			fmt.Fprintf(os.Stderr, " engine{max_certs=%d max_da_nonces=%d write_max_pending=%d write_threshold=%d write_workers=%d}",
				cfg.Engine.MaxCerts, cfg.Engine.MaxDANonces, cfg.Engine.WriteMaxPending, cfg.Engine.WriteThreshold, cfg.Engine.WriteWorkers)
		}
		fmt.Fprintln(os.Stderr)
	}
	switch {
	case e.opts.Engine:
		if err := mux.EnableEngine(&cfg); err != nil {
			return fmt.Errorf("enable engine: %w", err)
		}
	case e.opts.Sync:
		// synchronous DB writes, no write pipeline
	default:
		if err := mux.EnableRecordBuffer(&cfg); err != nil {
			slog.Warn("bench: record buffer disabled, using synchronous writes", "error", err)
		}
	}

	reg := provisioner.NewRegistry()
	reg.Register(provisioner.NewMTLSProvisioner())
	reg.Register(provisioner.NewTokenProvisioner())
	provisioner.UserResolver = func(username string) (string, []string, error) {
		user, err := e.DB.GetUserByUsername(username)
		if err != nil {
			return "", nil, err
		}
		if !user.Enabled {
			return "", nil, nil
		}
		return user.Role, nil, nil
	}
	provisioner.SetTokenResolver(func(token string) (*provisioner.AuthResult, error) {
		return nil, nil
	})
	mux.SetProvisioners(reg)

	mux.SetRouteRules(serve.LoadDefaultRouteRules())

	e.ln, _ = net.Listen("tcp", cfg.Serve.Addr)
	e.Addr = e.ln.Addr().String()
	e.hSrv = &http.Server{Handler: serve.WrapHandler(mux), Addr: e.Addr}
	go func() {
		if err := e.hSrv.Serve(e.ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "bench: server error: %v\n", err)
		}
	}()

	// Wait until the server answers.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + e.Addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if time.Now().After(deadline) {
		return fmt.Errorf("server did not become ready")
	}

	// Authenticate once with the operator password (one Argon2 hash) and reuse
	// a Bearer token for every subsequent request. Per-request Basic Auth would
	// re-verify (adding ~20-50ms Argon2id per request on cache miss); token
	// auth is a plain DB lookup, matching the production operator flow.
	token, err := e.loginToken()
	if err != nil {
		return fmt.Errorf("login: %w", err)
	}
	e.APIToken = token
	return nil
}

// loginToken exchanges the operator password for a scoped API token.
func (e *Env) loginToken() (string, error) {
	reqBody := bytes.NewBufferString(fmt.Sprintf(`{"username":%q,"password":%q}`, e.AdminUser, e.AdminPass))
	resp, err := http.Post("http://"+e.Addr+"/api/v1/users/login", "application/json", reqBody)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var lr struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return "", err
	}
	if lr.Token == "" {
		return "", fmt.Errorf("login returned no token (status %d)", resp.StatusCode)
	}
	return lr.Token, nil
}

func (e *Env) listenAddr() string {
	if e.opts.Port > 0 {
		return fmt.Sprintf("127.0.0.1:%d", e.opts.Port)
	}
	return "127.0.0.1:0"
}

// DBSize returns the total on-disk size of the SQLite database (main + WAL + SHM).
func (e *Env) DBSize() int64 {
	var total int64
	for _, p := range []string{e.DBPath, e.DBPath + "-wal", e.DBPath + "-shm"} {
		if fi, err := os.Stat(p); err == nil {
			total += fi.Size()
		}
	}
	return total
}

// CountCerts returns the current certificate row count in the DB.
func (e *Env) CountCerts() (int64, error) {
	var n int64
	row := e.DB.QueryRow("SELECT COUNT(*) FROM certificates")
	if err := row.Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// CountCertsInFile reopens a closed file-backed DB read-only and counts the
// certificate rows, giving the settled post-flush row count for reports.
func CountCertsInFile(path string) int64 {
	d, err := db.Open(path)
	if err != nil {
		return -1
	}
	defer d.Close()
	var n int64
	if err := d.QueryRow("SELECT COUNT(*) FROM certificates").Scan(&n); err != nil {
		return -1
	}
	return n
}

// Close flushes the record buffer, shuts down the HTTP server, then the DB.
func (e *Env) Close() {
	if e.mux != nil {
		// Shut down HTTP first so no new requests land, then drain whatever the
		// record buffer still holds into SQLite before the DB connection closes.
		if e.hSrv != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = e.hSrv.Shutdown(ctx)
			cancel()
		}
		e.mux.StopRecordBuffer()
		e.mux.StopEngine()
	}
	if e.DB != nil {
		e.DB.Close()
	}
	if e.caDir != "" {
		os.RemoveAll(e.caDir)
	}
}

// client returns a keep-alive HTTP client (pool sized for the worker set).
func (e *Env) client(maxConns int) *http.Client {
	tr := &http.Transport{
		MaxIdleConns:        maxConns * 2,
		MaxIdleConnsPerHost: maxConns * 2,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: tr}
}
