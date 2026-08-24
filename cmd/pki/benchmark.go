// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/core/internal/ca"
)

type benchResult struct {
	Algorithm  string `json:"algorithm"`
	Operation  string `json:"operation"`
	Size       int    `json:"size"`
	OpsPerSec  int64  `json:"ops_per_sec"`
	Latency    string `json:"latency"`
	Throughput string `json:"throughput,omitempty"`
}

func cmdBenchmark(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("benchmark", flag.ExitOnError)
	algoFilter := fs.String("algo", "", "comma-separated algorithm filter")
	sizeBytes := fs.Int("size", 0, "data size in bytes (0 = all default sizes)")
	duration := fs.Duration("duration", 2*time.Second, "benchmark duration per round")
	concurrency := fs.Int("concurrency", 1, "number of parallel goroutines")
	jsonOutput := fs.Bool("json", false, "JSON output")
	fs.Parse(args)

	if *duration < 100*time.Millisecond {
		*duration = 100 * time.Millisecond
	}

	sizes := []int{1024, 2048, 4096, 8192, 12288, 16384, 20480, 32768, 65536}
	if *sizeBytes > 0 {
		sizes = []int{*sizeBytes}
	}

	hashAlgos := []string{"sha256", "sha384", "sha512"}
	signAlgos := []string{"rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519"}

	var filteredHash, filteredSign []string
	if *algoFilter != "" {
		requested := strings.Split(*algoFilter, ",")
		for _, a := range requested {
			a = strings.TrimSpace(a)
			switch a {
			case "sha256", "sha384", "sha512":
				filteredHash = append(filteredHash, a)
			case "rsa-2048", "rsa-4096", "ecdsa-p256", "ecdsa-p384", "ed25519":
				filteredSign = append(filteredSign, a)
			default:
				fmt.Fprintf(os.Stderr, "unknown algorithm: %s\n", a)
			}
		}
		hashAlgos = filteredHash
		signAlgos = filteredSign
	}

	var results []benchResult

	fmt.Fprintf(os.Stderr, "pki benchmark: duration=%s sizes=%v concurrency=%d\n", *duration, humanSizes(sizes), *concurrency)

	for _, hashName := range hashAlgos {
		h := hashCrypto(hashName)
		if h == 0 {
			continue
		}
		for _, size := range sizes {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 251)
			}
			r := benchHash(h, hashName, data, *duration, *concurrency)
			results = append(results, r)
		}
	}

	for _, signName := range signAlgos {
		signer, err := ca.GenerateKey(signName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", signName, err)
			continue
		}
		pub := signer.Public()
		for _, size := range sizes {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i % 251)
			}
			hash := hashForSign(signName)
			sr := benchSign(signName, signer, pub, data, hash, *duration, *concurrency)
			results = append(results, sr...)
		}
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}

	return printBenchTable(results)
}

func hashCrypto(name string) crypto.Hash {
	switch name {
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	}
	return 0
}

func hashForSign(signName string) crypto.Hash {
	switch {
	case strings.HasPrefix(signName, "ecdsa-p256"):
		return crypto.SHA256
	case strings.HasPrefix(signName, "ecdsa-p384"):
		return crypto.SHA384
	case strings.HasPrefix(signName, "rsa-"):
		return crypto.SHA256
	default:
		return crypto.SHA512
	}
}

func benchHash(h crypto.Hash, name string, data []byte, dur time.Duration, concurrency int) benchResult {
	var totalOps atomic.Int64
	start := time.Now()

	if concurrency <= 1 {
		hasher := h.New()
		for time.Since(start) < dur {
			hasher.Reset()
			hasher.Write(data)
			_ = hasher.Sum(nil)
			totalOps.Add(1)
		}
	} else {
		var wg sync.WaitGroup
		wg.Add(concurrency)
		for range concurrency {
			go func() {
				defer wg.Done()
				hasher := h.New()
				for time.Since(start) < dur {
					hasher.Reset()
					hasher.Write(data)
					_ = hasher.Sum(nil)
					totalOps.Add(1)
				}
			}()
		}
		wg.Wait()
	}

	elapsed := time.Since(start)
	ops := totalOps.Load()
	latency := time.Duration(float64(elapsed) / float64(ops))
	throughput := float64(ops) * float64(len(data)) / elapsed.Seconds() / (1024 * 1024)
	return benchResult{
		Algorithm:  strings.ToUpper(name),
		Operation:  "hash",
		Size:       len(data),
		OpsPerSec:  int64(float64(ops) / elapsed.Seconds()),
		Latency:    fmtDuration(latency),
		Throughput: fmt.Sprintf("%.0f MB/s", throughput),
	}
}

func benchSign(name string, signer crypto.Signer, pub crypto.PublicKey, data []byte, hash crypto.Hash, dur time.Duration, concurrency int) []benchResult {
	isEd25519 := strings.HasPrefix(name, "ed25519")
	var signData []byte
	var signHash crypto.Hash
	if isEd25519 {
		signData = data
		signHash = crypto.Hash(0)
	} else {
		h := hash.New()
		h.Write(data)
		signData = h.Sum(nil)
		signHash = hash
	}

	if concurrency <= 1 {
		return benchSignSingle(signer, pub, name, signData, signHash, dur, len(data))
	}

	var totalSignOps, totalVerifyOps atomic.Int64
	start := time.Now()
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for range concurrency {
		go func() {
			defer wg.Done()
			var sig []byte
			localStart := time.Now()
			signOps := int64(0)
			for time.Since(localStart) < dur {
				var err error
				sig, err = signer.Sign(nil, signData, signHash)
				if err != nil {
					fmt.Fprintf(os.Stderr, "sign error %s: %v\n", name, err)
					return
				}
				signOps++
			}
			totalSignOps.Add(signOps)

			localStart = time.Now()
			verifyOps := int64(0)
			for time.Since(localStart) < dur {
				err := verifySig(pub, signData, sig, signHash)
				if err != nil {
					fmt.Fprintf(os.Stderr, "verify error %s: %v\n", name, err)
					return
				}
				verifyOps++
			}
			totalVerifyOps.Add(verifyOps)
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	signElapsed := elapsed
	verifyElapsed := elapsed

	signOps := totalSignOps.Load()
	verifyOps := totalVerifyOps.Load()

	return []benchResult{
		{
			Algorithm: strings.ToUpper(name),
			Operation: "sign",
			Size:      len(data),
			OpsPerSec: int64(float64(signOps) / signElapsed.Seconds()),
			Latency:   fmtDuration(time.Duration(float64(signElapsed) / float64(signOps))),
		},
		{
			Algorithm: strings.ToUpper(name),
			Operation: "verify",
			Size:      len(data),
			OpsPerSec: int64(float64(verifyOps) / verifyElapsed.Seconds()),
			Latency:   fmtDuration(time.Duration(float64(verifyElapsed) / float64(verifyOps))),
		},
	}
}

func benchSignSingle(signer crypto.Signer, pub crypto.PublicKey, name string, signData []byte, signHash crypto.Hash, dur time.Duration, dataSize int) []benchResult {
	ops := int64(0)
	start := time.Now()
	var sig []byte
	for time.Since(start) < dur {
		var err error
		sig, err = signer.Sign(nil, signData, signHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sign error %s: %v\n", name, err)
			return nil
		}
		ops++
	}
	elapsed := time.Since(start)
	signResult := benchResult{
		Algorithm: strings.ToUpper(name),
		Operation: "sign",
		Size:      dataSize,
		OpsPerSec: int64(float64(ops) / elapsed.Seconds()),
		Latency:   fmtDuration(time.Duration(float64(elapsed) / float64(ops))),
	}

	ops = 0
	start = time.Now()
	for time.Since(start) < dur {
		err := verifySig(pub, signData, sig, signHash)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify error %s: %v\n", name, err)
			return nil
		}
		ops++
	}
	elapsed = time.Since(start)
	verifyResult := benchResult{
		Algorithm: strings.ToUpper(name),
		Operation: "verify",
		Size:      dataSize,
		OpsPerSec: int64(float64(ops) / elapsed.Seconds()),
		Latency:   fmtDuration(time.Duration(float64(elapsed) / float64(ops))),
	}

	return []benchResult{signResult, verifyResult}
}

func fmtDuration(d time.Duration) string {
	if d < time.Microsecond {
		return fmt.Sprintf("%.0fns", float64(d.Nanoseconds()))
	}
	if d < time.Millisecond {
		return fmt.Sprintf("%.1fμs", float64(d.Microseconds()))
	}
	return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000)
}

func printBenchTable(results []benchResult) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "Algorithm\tOperation\tSize\tOps/s\tLatency\tThroughput")
	fmt.Fprintln(w, "─────────\t─────────\t────\t─────\t───────\t──────────")
	for _, r := range results {
		sizeStr := formatSize(r.Size)
		opsStr := formatOps(r.OpsPerSec)
		tp := r.Throughput
		if tp == "" {
			tp = "—"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			r.Algorithm, r.Operation, sizeStr, opsStr, r.Latency, tp)
	}
	w.Flush()
	return nil
}

func formatSize(b int) string {
	switch {
	case b >= 1048576:
		return fmt.Sprintf("%dMB", b/1048576)
	case b >= 1024:
		return fmt.Sprintf("%dKB", b/1024)
	default:
		return fmt.Sprintf("%dB", b)
	}
}

func humanSizes(sizes []int) string {
	parts := make([]string, len(sizes))
	for i, s := range sizes {
		parts[i] = formatSize(s)
	}
	return strings.Join(parts, " ")
}

func formatOps(ops int64) string {
	if ops >= 1000000 {
		return fmt.Sprintf("%.2fM", float64(ops)/1000000)
	}
	if ops >= 1000 {
		return fmt.Sprintf("%.1fK", float64(ops)/1000)
	}
	return fmt.Sprintf("%d", ops)
}

func verifySig(pub crypto.PublicKey, data, sig []byte, hash crypto.Hash) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hash, data, sig)
	case *ecdsa.PublicKey:
		var es struct {
			R, S *big.Int
		}
		rest, err := asn1.Unmarshal(sig, &es)
		if err != nil {
			return fmt.Errorf("unmarshal ecdsa sig: %w", err)
		}
		if len(rest) > 0 {
			return fmt.Errorf("trailing bytes in ecdsa signature")
		}
		if !ecdsa.Verify(k, data, es.R, es.S) {
			return fmt.Errorf("ecdsa verify failed")
		}
		return nil
	case ed25519.PublicKey:
		if !ed25519.Verify(k, data, sig) {
			return fmt.Errorf("ed25519 verify failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", pub)
	}
}
