// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

func serveWait(httpServer, tlsServer *http.Server) error {
	setShutdownTimeout(localCfg)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)
	return serveWaitSignal(httpServer, tlsServer, sigCh)
}

func serveWaitSignal(httpServer, tlsServer *http.Server, sigCh <-chan os.Signal) error {
	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			slog.Info("SIGHUP received, reloading config")
			reloadConfig()
		default:
			slog.Info("shutting down", "signal", sig)
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if httpServer != nil {
				httpServer.Shutdown(ctx)
			}
			if tlsServer != nil {
				tlsServer.Shutdown(ctx)
			}
			// Flush buffered cert records so a clean shutdown loses nothing.
			stopRecordBuffer()
			// Flush pending engine writes (memory → DB) before exit.
			stopEngine()
			return nil
		}
	}
}

func reloadConfig() {
	if reloadFn != nil {
		reloadFn()
	} else {
		slog.Warn("no reload handler registered")
	}
}

func installService() error {
	return fmt.Errorf("service installation is only supported on Windows")
}

func removeService() error {
	return fmt.Errorf("service removal is only supported on Windows")
}
