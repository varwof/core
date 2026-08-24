package main

import (
	"testing"

	"github.com/varwof/core/internal"
)

func TestBenchmarkDefault(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{"--duration", "100ms"})
	if err != nil {
		t.Fatalf("benchmark failed: %v", err)
	}
}

func TestBenchmarkHashOnly(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{"--algo", "sha256", "--size", "256", "--duration", "100ms"})
	if err != nil {
		t.Fatalf("benchmark hash failed: %v", err)
	}
}

func TestBenchmarkSignOnly(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{"--algo", "ecdsa-p256", "--size", "256", "--duration", "100ms"})
	if err != nil {
		t.Fatalf("benchmark sign failed: %v", err)
	}
}

func TestBenchmarkJSON(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{"--algo", "sha256", "--size", "256", "--duration", "100ms", "--json"})
	if err != nil {
		t.Fatalf("benchmark json failed: %v", err)
	}
}

func TestBenchmarkAllAlgos(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{
		"--algo", "sha256,sha384,sha512,rsa-2048,rsa-4096,ecdsa-p256,ecdsa-p384,ed25519",
		"--size", "256",
		"--duration", "50ms",
	})
	if err != nil {
		t.Fatalf("benchmark all algos failed: %v", err)
	}
}

func TestBenchmarkConcurrent(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{
		"--algo", "sha256,ed25519",
		"--size", "256",
		"--duration", "200ms",
		"--concurrency", "4",
	})
	if err != nil {
		t.Fatalf("benchmark concurrent(%d) failed: %v", 4, err)
	}
}

func TestBenchmarkConcurrentSingle(t *testing.T) {
	cfg := &internal.Config{}
	err := cmdBenchmark(cfg, []string{
		"--algo", "sha256,ed25519",
		"--size", "256",
		"--duration", "200ms",
		"--concurrency", "1",
	})
	if err != nil {
		t.Fatalf("benchmark concurrent(1) failed: %v", err)
	}
}
