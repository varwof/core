// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
	"github.com/varwof/core/internal/remotesigner"
	"github.com/varwof/core/internal/serve"
	"github.com/varwof/core/internal/tsa"
	"github.com/varwof/engine/db"
)

// initRemoteSigner initializes the remote signer from config.
func initRemoteSigner(cfg *internal.Config) error {
	if cfg.KeyBackend.Type != "remote_hsm" || cfg.KeyBackend.URL == "" {
		return nil
	}
	rc := &remotesigner.Config{
		Endpoint:  cfg.KeyBackend.URL,
		KeyAlias:  cfg.KeyBackend.KeyAlias,
		TLSCert:   cfg.KeyBackend.TLS.Cert,
		TLSKey:    cfg.KeyBackend.TLS.Key,
		CACert:    cfg.KeyBackend.TLS.CACert,
		AuthToken: cfg.KeyBackend.Token,
	}
	ca.SetRemoteSignerConfig(rc)
	slog.Info("remote signer enabled", "url", cfg.KeyBackend.URL, "key_alias", cfg.KeyBackend.KeyAlias)
	return nil
}

// serveCmd dispatches to the appropriate modular service.
// serve [tsa|ocsp|crl|api] — starts only that service on its configured port.
func serveCmd(cfg *internal.Config, args []string) error {
	if err := initRemoteSigner(cfg); err != nil {
		return fmt.Errorf("remote signer: %w", err)
	}
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return serveFull(cfg, args) // full all-in-one mode
	}
	sub := args[0]
	rest := args[1:]

	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()
	localCfg = cfg

	switch sub {
	case "tsa":
		return serveTSA(cfg, database, rest)
	case "ocsp":
		return serveOCSP(cfg, database, rest)
	case "crl":
		return serveCRL(cfg, database, rest)
	case "api":
		return serveAPI(cfg, database, rest)
	default:
		return fmt.Errorf("unknown serve subcommand: %s (use: tsa, ocsp, crl, api)", sub)
	}
}

// serveTSA starts only the TSA service on tsa.addr (or serve.addr).
func serveTSA(cfg *internal.Config, database *db.DB, _ []string) error {
	addr := cfg.TSA.Addr
	if addr == "" {
		addr = cfg.Serve.Addr
	}

	tsaHandler, tsaRC, err := loadTSAConfig(cfg)
	if err != nil {
		return err
	}

	// Start TSA renewal loop
	stopCh := make(chan struct{})
	go tsa.SignerRenewLoop(tsaRC, &tsa.RenewalConfig{
		CoreURL:       cfg.TSA.CoreURL,
		CertFile:      cfg.TSA.SignerCert,
		KeyFile:       cfg.TSA.SignerKey,
		CACertFile:    cfg.TSA.TLSCACert,
		CAName:        cfg.TSA.CAName,
		ValidityDays:  cfg.TSA.ValidityDays,
		TLSClientCert: cfg.TSA.TLSClientCert,
		TLSClientKey:  cfg.TSA.TLSClientKey,
	}, stopCh)

	srv := &http.Server{
		Addr:    addr,
		Handler: tsaHandler,
	}
	go func() {
		slog.Info("serve: tsa (standalone)", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve: tsa error", "error", err)
		}
	}()

	localCfg = cfg
	err = serveWait(srv, nil)
	close(stopCh)
	return err
}

// serveOCSP starts only the OCSP service on ocsp.addr (or serve.addr).
func serveOCSP(cfg *internal.Config, database *db.DB, _ []string) error {
	addr := cfg.OCSP.Addr
	if addr == "" {
		addr = cfg.Serve.Addr
	}

	ocspHandler, err := loadOCSPConfig(cfg, database)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    addr,
		Handler: ocspHandler,
	}
	go func() {
		slog.Info("serve: ocsp (standalone)", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve: ocsp error", "error", err)
		}
	}()

	localCfg = cfg
	return serveWait(srv, nil)
}

// serveCRL starts CRL generation and distribution on crl.addr (or serve.addr).
// Serves CRL files from CRL output directory.
func serveCRL(cfg *internal.Config, database *db.DB, _ []string) error {
	addr := cfg.CRL.Addr
	if addr == "" {
		addr = cfg.Serve.Addr
	}

	// Start CRL auto-renewal in background (standalone CRL mode has no
	// resident memory engine; revoked entries come from the DB directly).
	startCRL(database, nil, cfg)

	mux := serve.NewPublic(cfg, database, bundle)
	if internal.BoolOr(cfg.RateLimit.Enabled, false) {
		rl := serve.NewRateLimiter(cfg.RateLimit.Rate, cfg.RateLimit.Burst)
		mux.SetRateLimiter(rl)
	}
	mux.Version = versionString()

	wrapFn := serve.WrapHandler
	if internal.BoolOr(cfg.Serve.MetricsEnabled, false) {
		wrapFn = serve.WrapHandlerWithMetrics
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: wrapFn(mux),
	}
	go func() {
		slog.Info("serve: crl (standalone)", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve: crl error", "error", err)
		}
	}()

	localCfg = cfg
	return serveWait(srv, nil)
}

// serveAPI starts only the REST API + Web UI + ACME on api.addr (or serve.addr).
func serveAPI(cfg *internal.Config, database *db.DB, _ []string) error {
	addr := cfg.Serve.APIAddr
	if addr == "" {
		addr = cfg.Serve.Addr
	}
	slog.Debug("serve: api config", "APIAddr", cfg.Serve.APIAddr, "Addr", cfg.Serve.Addr, "resolved", addr)

	mux := serve.NewFull(cfg, database, bundle,
		http.NotFoundHandler(),
		http.NotFoundHandler(),
	)
	if err := mux.EnableRecordBuffer(cfg); err != nil {
		slog.Warn("serve: record buffer disabled, using synchronous writes", "error", err)
	}
	rbStopFn = mux.StopRecordBuffer
	if cfg.Engine != nil {
		if err := mux.EnableEngine(cfg); err != nil {
			slog.Warn("serve: memory engine disabled, using DB-only access paths", "error", err)
		}
	}
	engineStopFn = mux.StopEngine
	if internal.BoolOr(cfg.RateLimit.Enabled, false) {
		rl := serve.NewRateLimiter(cfg.RateLimit.Rate, cfg.RateLimit.Burst)
		mux.SetRateLimiter(rl)
	}
	mux.Version = versionString()

	wrapFn := serve.WrapHandler
	if internal.BoolOr(cfg.Serve.MetricsEnabled, false) {
		wrapFn = serve.WrapHandlerWithMetrics
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: wrapFn(mux),
	}
	go func() {
		slog.Info("serve: api+web (standalone)", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("serve: api error", "error", err)
		}
	}()

	localCfg = cfg
	return serveWait(srv, nil)
}

// serveFull starts all services on one port (original all-in-one).
func serveFull(cfg *internal.Config, args []string) error {
	database, err := db.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() {
		if err != nil {
			database.Close()
		}
	}()

	if err := startServers(cfg, database); err != nil {
		database.Close()
		return err
	}
	currentDB = database

	setReloadHandler(func() {
		reloadConfigNow(configPath)
	})

	localCfg = cfg
	return serveWait(httpServer, tlsServer)
}
