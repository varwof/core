package main

import (
	"time"

	"github.com/varwof/core/internal"
)

// Shared server state used by both the full (serve.go) and modular
// (serve_modular.go) entrypoints, independent of the host OS. Declared here
// (rather than in serve_unix.go) so the Windows build also compiles.
var (
	reloadFn        func()
	shutdownTimeout = 10 * time.Second
	localCfg        *internal.Config
)

func setReloadHandler(fn func()) {
	reloadFn = fn
}

func setShutdownTimeout(cfg *internal.Config) {
	if cfg != nil && cfg.Serve.ShutdownTimeout != "" {
		if d, err := time.ParseDuration(cfg.Serve.ShutdownTimeout); err == nil {
			shutdownTimeout = d
		}
	}
}
