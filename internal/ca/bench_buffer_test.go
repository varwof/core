// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/varwof/engine/db"
)

func BenchmarkBatchPersist(b *testing.B) {
	tmpDir := b.TempDir()
	extDB, err := db.Open(tmpDir + "/bench.db")
	if err != nil {
		b.Fatal(err)
	}
	defer extDB.Close()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Bench CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	concurrency := 12
	total := 100000
	batchSizes := []int{100, 500, 1000, 2000}

	for _, bs := range batchSizes {
		buf, _ := NewMemoryBuffer(extDB, PersistConfig{
			Mode: PersistBatch, BatchSize: bs,
			BatchInterval: 5 * time.Second, QueueSize: total + 10000,
		})

		b.Run("", func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()

			var issued int64
			var wg sync.WaitGroup
			sem := make(chan struct{}, concurrency)
			idGen := &atomic.Int64{}
			tmplBase := x509.Certificate{
				NotBefore: time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}

			start := time.Now()
			for i := 0; i < total; i++ {
				wg.Add(1)
				sem <- struct{}{}
				go func() {
					defer wg.Done()
					defer func() { <-sem }()

					id := idGen.Add(1)
					key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

					tmpl := tmplBase
					tmpl.SerialNumber = big.NewInt(id)
					tmpl.Subject = pkix.Name{CommonName: "c" + big.NewInt(id).String()}

					der, _ := x509.CreateCertificate(rand.Reader, &tmpl, caCert, &key.PublicKey, caKey)
					cert, _ := x509.ParseCertificate(der)

					record := &db.CertRecord{
						SerialNumber: cert.SerialNumber.Text(16),
						CAName:       "Bench CA", Status: "active",
						Subject:    cert.Subject.String(),
						CommonName: tmpl.Subject.CommonName,
						NotBefore:  cert.NotBefore, NotAfter: cert.NotAfter,
						CertDER: der, Profile: "tls-client",
					}

					if err := buf.Add(&CertBufferItem{Record: record}); err != nil {
						b.Error(err)
					}
					atomic.AddInt64(&issued, 1)
				}()
			}
			wg.Wait()
			buf.Flush()

			elapsed := time.Since(start)
			b.ReportMetric(float64(elapsed.Milliseconds()), "ms")
			b.ReportMetric(float64(total)/elapsed.Seconds(), "certs/sec")
			b.Logf("batch_size=%d total=%d elapsed=%v rate=%.0f/sec",
				bs, total, elapsed, float64(total)/elapsed.Seconds())
		})
		buf.Close()
	}
}

func BenchmarkBatchSigned(b *testing.B) {
	tmpDir := b.TempDir()
	extDB, _ := db.Open(tmpDir + "/bench2.db")
	defer extDB.Close()

	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Bench CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)

	// Compare: raw signing without any DB
	b.Run("sign-only", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(1)
		var wg sync.WaitGroup
		sem := make(chan struct{}, 12)
		start := time.Now()
		for i := 0; i < 100000; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func(id int) {
				defer wg.Done()
				defer func() { <-sem }()
				key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				tmpl := &x509.Certificate{
					SerialNumber: big.NewInt(int64(id)),
					Subject:      pkix.Name{CommonName: "s" + big.NewInt(int64(id)).String()},
					NotBefore:    time.Now(), NotAfter: time.Now().Add(365 * 24 * time.Hour),
					KeyUsage:    x509.KeyUsageDigitalSignature,
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				}
				x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
			}(i)
		}
		wg.Wait()
		elapsed := time.Since(start)
		b.ReportMetric(float64(100000)/elapsed.Seconds(), "certs/sec")
	})
}
