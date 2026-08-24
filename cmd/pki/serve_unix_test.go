// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

//go:build !windows

package main

import (
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestServeWaitSignalSIGHUP(t *testing.T) {
	reloadCalled := false
	setReloadHandler(func() { reloadCalled = true })
	defer setReloadHandler(nil)

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveWaitSignal(nil, nil, sigCh)
	}()

	sigCh <- syscall.SIGHUP
	// Give the goroutine time to process
	select {
	case err := <-done:
		t.Fatalf("unexpected return: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	if !reloadCalled {
		t.Fatal("reload handler not called on SIGHUP")
	}
}

func TestServeWaitSignalShutdown(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	srv := &http.Server{Addr: "127.0.0.1:1"}
	done := make(chan error, 1)
	go func() {
		done <- serveWaitSignal(srv, nil, sigCh)
	}()

	sigCh <- syscall.SIGTERM
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveWaitSignal did not return after SIGTERM")
	}
}

func TestServeWaitSignalShutdownTLS(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	srv := &http.Server{Addr: "127.0.0.1:1"}
	tlsSrv := &http.Server{Addr: "127.0.0.1:2"}
	done := make(chan error, 1)
	go func() {
		done <- serveWaitSignal(srv, tlsSrv, sigCh)
	}()

	sigCh <- syscall.SIGINT
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveWaitSignal did not return after SIGINT")
	}
}

func TestReloadConfig(t *testing.T) {
	reloadCalled := false
	setReloadHandler(func() { reloadCalled = true })
	defer setReloadHandler(nil)

	reloadConfig()
	if !reloadCalled {
		t.Fatal("reload handler not called")
	}
}

func TestReloadConfigNoHandler(t *testing.T) {
	setReloadHandler(nil)
	// Should not panic
	reloadConfig()
}

func TestInstallService(t *testing.T) {
	err := installService()
	if err == nil {
		t.Fatal("expected error on Unix")
	}
}

func TestRemoveService(t *testing.T) {
	err := removeService()
	if err == nil {
		t.Fatal("expected error on Unix")
	}
}

func TestServeWaitSignalShutdownWithTimeout(t *testing.T) {
	origTimeout := shutdownTimeout
	shutdownTimeout = 100 * time.Millisecond
	defer func() { shutdownTimeout = origTimeout }()

	srv := &http.Server{Addr: "127.0.0.1:1"}

	sigCh := make(chan os.Signal, 1)
	done := make(chan error, 1)
	go func() {
		done <- serveWaitSignal(srv, nil, sigCh)
	}()

	sigCh <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}
