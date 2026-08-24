// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package ca

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/varwof/engine/db"
)

// PersistMode defines the persistence mode after certificate issuance.
type PersistMode int

const (
	PersistRealtime PersistMode = iota // Realtime persistence: write to external DB immediately after each issuance
	PersistBatch                       // Batch persistence: accumulate N records then batch write
	PersistAsync                       // Async persistence: write only to memory buffer, background async persistence
)

// PersistConfig is the runtime persistence configuration.
type PersistConfig struct {
	Mode          PersistMode
	BatchSize     int           // Batch trigger count (default 100)
	BatchInterval time.Duration // Timer trigger interval (default 5 seconds)
	QueueSize     int           // Queue capacity limit (default 10000)
}

// DefaultPersistConfig returns the default persistence configuration (realtime mode, compatible with existing behavior).
func DefaultPersistConfig() PersistConfig {
	return PersistConfig{
		Mode:          PersistRealtime,
		BatchSize:     100,
		BatchInterval: 5 * time.Second,
		QueueSize:     10000,
	}
}

// CertBufferItem is a single record pending persistence in the memory buffer.
type CertBufferItem struct {
	Record *db.CertRecord
	Key    crypto.Signer
}

// MemoryBuffer is a high-speed memory buffer for certificate issuance.
// It accumulates certificate records pending persistence and triggers batch writes to the external DB periodically or on count threshold.
type MemoryBuffer struct {
	mu         sync.Mutex
	db         *db.DB // external persistence DB
	cfg        PersistConfig
	pending    []*CertBufferItem
	closed     chan struct{}
	flushWg    sync.WaitGroup
	queueSize  int
	retryLimit int
	logger     *slog.Logger
}

// NewMemoryBuffer creates a memory buffer and starts the background persistence goroutine.
func NewMemoryBuffer(extDB *db.DB, cfg PersistConfig) (*MemoryBuffer, error) {
	b := &MemoryBuffer{
		db:         extDB,
		cfg:        cfg,
		pending:    make([]*CertBufferItem, 0, cfg.BatchSize),
		closed:     make(chan struct{}),
		queueSize:  cfg.QueueSize,
		retryLimit: 3,
		logger:     slog.Default(),
	}

	if cfg.Mode != PersistRealtime {
		b.flushWg.Add(1)
		go b.persistLoop()
	}

	return b, nil
}

// Add adds a certificate record to the buffer.
// In realtime mode, writes directly to the external DB; in batch/async mode, writes to the in-memory queue.
func (b *MemoryBuffer) Add(item *CertBufferItem) error {
	if b.cfg.Mode == PersistRealtime {
		return b.db.InsertCert(item.Record)
	}

	b.mu.Lock()
	if len(b.pending) >= b.queueSize {
		b.mu.Unlock()
		slog.Warn("buffer queue full, falling back to realtime write",
			"serial", item.Record.SerialNumber)
		return b.db.InsertCert(item.Record)
	}
	b.pending = append(b.pending, item)
	size := len(b.pending)
	b.mu.Unlock()
	if b.cfg.Mode == PersistBatch && size >= b.cfg.BatchSize {
		b.flushWg.Add(1)
		go func() {
			defer b.flushWg.Done()
			b.Flush()
		}()
	}
	return nil
}

// Flush batch writes all pending persistence records from the buffer to the external DB.
func (b *MemoryBuffer) Flush() error {
	b.mu.Lock()
	if len(b.pending) == 0 {
		b.mu.Unlock()
		return nil
	}
	batch := b.pending
	b.pending = make([]*CertBufferItem, 0, b.cfg.BatchSize)
	b.mu.Unlock()

	return b.flushBatch(batch)
}

func (b *MemoryBuffer) flushBatch(batch []*CertBufferItem) error {
	records := make([]*db.CertRecord, len(batch))
	for i, item := range batch {
		records[i] = item.Record
	}

	var err error
	for attempt := 0; attempt < b.retryLimit; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<attempt) * time.Second
			time.Sleep(backoff)
		}
		var n int
		n, err = b.db.BulkInsertCertRecords(records)
		if err == nil {
			slog.Debug("batch persist", "n", n, "total", len(records))
			return nil
		}
		slog.Warn("batch persist failed", "attempt", attempt+1, "error", err)
	}

	slog.Error("batch persist failed after retries, falling back", "error", err)
	for _, item := range batch {
		if insertErr := b.db.InsertCert(item.Record); insertErr != nil {
			slog.Error("fallback insert failed", "serial", item.Record.SerialNumber, "error", insertErr)
		}
	}
	return nil
}

func (b *MemoryBuffer) persistLoop() {
	defer b.flushWg.Done()
	interval := b.cfg.BatchInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			b.Flush()
		case <-b.closed:
			b.Flush()
			return
		}
	}
}

// Close closes the buffer, flushes all pending data, and releases resources.
func (b *MemoryBuffer) Close() error {
	close(b.closed)
	b.flushWg.Wait()
	return nil
}

// Size returns the number of records currently pending persistence.
func (b *MemoryBuffer) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.pending)
}

// ---- Integration helpers for the issuance flow ----

// IssueResult is the result of a single certificate issuance.
type IssueResult struct {
	Cert   *x509.Certificate
	Record *db.CertRecord
	Key    crypto.Signer
}

// IssueAndBuffer issues a certificate and adds it to the memory buffer.
func IssueAndBuffer(signerCfg *SignConfig, buffer *MemoryBuffer) (*IssueResult, error) {
	result, err := Sign(signerCfg)
	if err != nil {
		return nil, err
	}

	record := buildCertRecord(result, signerCfg)
	if buffer != nil {
		if err := buffer.Add(&CertBufferItem{Record: record}); err != nil {
			return nil, fmt.Errorf("buffer add: %w", err)
		}
	} else if signerCfg.DB != nil {
		if err := signerCfg.DB.InsertCert(record); err != nil {
			return nil, fmt.Errorf("insert cert: %w", err)
		}
	}

	return &IssueResult{Cert: result.Cert, Record: record, Key: result.PrivateKey}, nil
}

func buildCertRecord(result *SignResult, cfg *SignConfig) *db.CertRecord {
	cert := result.Cert
	return &db.CertRecord{
		SerialNumber: result.SerialHex,
		CAName:       cfg.CAName,
		Status:       "active",
		Subject:      cert.Subject.String(),
		CommonName:   cfg.CommonName,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		CertDER:      result.CertDER,
		Profile:      string(cfg.Profile),
	}
}

// ParsePersistConfig parses the persistence mode from a configuration string.
func ParsePersistConfig(mode string) PersistMode {
	switch mode {
	case "batch":
		return PersistBatch
	case "async":
		return PersistAsync
	default:
		return PersistRealtime
	}
}
