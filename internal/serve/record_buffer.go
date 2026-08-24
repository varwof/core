package serve

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/engine/db"
)

const (
	defaultMaxPending  = 20000
	defaultMaxLatency  = 500 * time.Millisecond
	defaultFlushBatch  = 500
	fsyncEveryNRecords = 100
	fsyncMaxInterval   = 100 * time.Millisecond
	// checkpointInterval is the minimum interval between WAL checkpoints. SQLite auto-checkpoint
	// is suppressed when concurrent readers exist (auto-checkpoint needs exclusive access), and
	// high-throughput issuance causes pki.db-wal to grow unbounded; this interval forces a
	// periodic convergence to avoid the lock overhead of checkpointing on every flush.
	checkpointInterval = 2 * time.Second
)

// RecordBuffer batches certificate records, flushing to DB after reaching threshold records
// or maxLatency. Features WAL write-ahead logging (crash safe), MaxPending hard limit (backpressure),
// and MaxLatency (maximum delay).
type RecordBuffer struct {
	mu         sync.Mutex
	records    []*db.CertRecord
	pending    atomic.Int32
	threshold  int
	maxPending int32
	maxLatency time.Duration
	flushCh    chan struct{}

	walPath   string
	walFile   *os.File
	walBuf    *bufio.Writer
	fsyncCnt  int
	lastFsync time.Time

	cancel context.CancelFunc
	db     func() *db.DB
	done   chan struct{} // closed when run() returns; Stop waits on it
}

// NewRecordBuffer creates a record buffer.
// getDB: retrieves the current DB pointer (supports hot reload)
// threshold: record count that triggers a flush (recommended 100)
// maxPending: hard limit on pending records, Add returns false when exceeded (recommended 5000)
// maxLatency: maximum wait time before forced flush (recommended 500ms)
// walPath: WAL file path, empty string = WAL disabled (crash unsafe)
func NewRecordBuffer(getDB func() *db.DB, threshold int, maxPending int32, maxLatency time.Duration, walPath string) (*RecordBuffer, error) {
		// Replay existing WAL first (restart recovery)
	if walPath != "" {
		if err := replayWAL(getDB, walPath); err != nil {
			slog.Warn("record_buffer: WAL replay failed, continuing", "path", walPath, "error", err)
		}
	}

	f, err := openWAL(walPath)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	rb := &RecordBuffer{
		threshold:  threshold,
		maxPending: maxPending,
		maxLatency: maxLatency,
		flushCh:    make(chan struct{}, 1),
		walPath:    walPath,
		walFile:    f,
		// 64KB bufio: each JSON record ~2KB, approximately 32 records trigger one locked write()
		// syscall (at default 4KB it triggers every 2 records, making rb.mu a hotspot under high concurrency)
		walBuf:    bufio.NewWriterSize(f, 64*1024),
		lastFsync: time.Now(),
		cancel:    cancel,
		db:        getDB,
		done:      make(chan struct{}),
	}
	go rb.run(ctx)
	return rb, nil
}

// replayWAL reads the WAL file, batch inserts certificate records not yet in the DB,
// and truncates the WAL upon completion.
func replayWAL(getDB func() *db.DB, walPath string) error {
	data, err := os.ReadFile(walPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if len(data) == 0 {
		return nil
	}

	var records []*db.CertRecord
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		var rec db.CertRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			slog.Warn("record_buffer: skip corrupt WAL line", "error", err)
			continue
		}
		records = append(records, &rec)
	}
	if len(records) == 0 {
		return nil
	}

	d := getDB()
	if d == nil {
		return nil
	}
	n, err := d.BulkInsertCertRecords(records)
	if err != nil {
		return err
	}
	slog.Info("record_buffer: WAL replayed", "inserted", n, "total", len(records))
	return nil
}

// openWAL opens the WAL file (truncate mode); returns (nil, nil) when walPath is empty.
func openWAL(walPath string) (*os.File, error) {
	if walPath == "" {
		return nil, nil
	}
	f, err := os.OpenFile(walPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// IsFull returns whether the buffer is full (for pre-check backpressure).
// maxPending<=0 means backpressure is disabled (never returns true).
func (rb *RecordBuffer) IsFull() bool {
	return rb.maxPending > 0 && rb.pending.Load() >= rb.maxPending
}

// Add adds a certificate record to the buffer.
// Returns false when the buffer is full; the caller should return HTTP 503.
// maxPending<=0 disables backpressure, always returns true.
func (rb *RecordBuffer) Add(rec *db.CertRecord) bool {
	if rb.maxPending > 0 && rb.pending.Load() >= rb.maxPending {
		return false
	}

		// json.Marshal outside lock (reduces lock hold time)
	var line []byte
	if rb.walBuf != nil {
		line, _ = json.Marshal(rec)
	}

	rb.mu.Lock()
	if rb.walBuf != nil && line != nil {
		rb.walBuf.Write(line)
		rb.walBuf.WriteByte('\n')
	}
	rb.records = append(rb.records, rec)
	n := len(rb.records)
	// H4 fix: increment pending under the lock. Previously the increment
	// happened after Unlock, so a concurrent flush could observe pending==0
	// (via pending.Add(-n)) and truncate the WAL just as this record was being
	// written — silently losing a record the caller was told (200) was durable.
	rb.pending.Add(1)

	// Periodic fsync (also under the lock — H4 fix: fsyncCnt/lastFsync and the
	// bufio flush were previously written without the lock, racing the WAL
	// truncate path which shares the same buffer/file).
	if rb.walBuf != nil {
		rb.fsyncCnt++
		if rb.fsyncCnt%fsyncEveryNRecords == 0 || time.Since(rb.lastFsync) > fsyncMaxInterval {
			rb.walBuf.Flush()
			rb.walFile.Sync()
			rb.lastFsync = time.Now()
		}
	}
	rb.mu.Unlock()

	if n >= rb.threshold {
		select {
		case rb.flushCh <- struct{}{}:
		default:
		}
	}
	return true
}

func (rb *RecordBuffer) flush() {
	flushStart := time.Now()
	rb.mu.Lock()
	if len(rb.records) == 0 {
		rb.mu.Unlock()
		return
	}
	n := len(rb.records)
	batch := make([]*db.CertRecord, n)
	copy(batch, rb.records)
	rb.mu.Unlock()

	d := rb.db()
	if d == nil {
		return
	}

	if _, err := d.BulkInsertCertRecords(batch); err != nil {
		slog.Warn("record_buffer: bulk insert failed", "n", len(batch), "error", err)
		return
	}
	if dur := time.Since(flushStart); dur > 50*time.Millisecond {
		slog.Info("record_buffer: slow flush", "n", n, "dur_ms", dur.Milliseconds(), "pending", rb.pending.Load())
	}

		// Flush succeeded: remove flushed records from memory buffer
	rb.mu.Lock()
	if len(rb.records) >= n {
		rb.records = rb.records[n:]
	} else {
		rb.records = nil
	}
	// H4 fix: decrement pending and decide on truncation under the lock.
	// Previously truncate happened after Unlock with a bare pending==0 read —
	// a concurrent Add that appended a record (but had not yet incremented
	// pending) between the snapshot and this point would see its WAL entry
	// truncated while the record was not in the DB batch: a returned-200 record
	// silently lost on crash. Double-check under the lock that nothing remains
	// buffered before truncating.
	rb.pending.Add(-int32(n))
	if len(rb.records) == 0 && rb.walFile != nil {
		rb.walBuf.Flush()
		rb.walFile.Truncate(0)
		rb.walFile.Seek(0, io.SeekStart)
	}
	rb.mu.Unlock()
	slog.Debug("record_buffer: flushed", "n", n)
}

func (rb *RecordBuffer) flushAll() {
	rb.flush()
	if rb.walBuf != nil {
		rb.walBuf.Flush()
		rb.walFile.Sync()
	}
}

func (rb *RecordBuffer) run(ctx context.Context) {
	defer close(rb.done)
	flushTicker := time.NewTicker(rb.maxLatency)
	defer flushTicker.Stop()
		// Checkpoint runs on an independent cycle: WAL grows fast under high throughput, but
		// checkpoint holds the lock and blocks all writes when WAL is large (merging hundreds of
		// MB WAL into the main DB file). Running under high load would stall drain → 503 storm.
		// Only checkpoint when the buffer is idle (pending==0): at that point there are no
		// records pending persistence, so merging WAL does not block any requests.
	ckptTicker := time.NewTicker(checkpointInterval)
	defer ckptTicker.Stop()
	for {
		select {
		case <-rb.flushCh:
			rb.drain()
		case <-flushTicker.C:
			rb.drain()
		case <-ckptTicker.C:
			if rb.pending.Load() == 0 {
				if d := rb.db(); d != nil {
					d.CheckpointWAL()
				}
			}
		case <-ctx.Done():
			rb.flushAll()
			if rb.walFile != nil {
				rb.walFile.Close()
			}
			return
		}
	}
}

// drain continuously flushes until the pending record count drops below threshold.
// flushCh is a capacity-1 channel; under high throughput signals are lost (flush in progress).
// If only one flush response is waited on before the maxLatency ticker, drain frequency is
// limited to ~2/s, with a few hundred records per batch, throughput limited to ~1K/s — far
// below BulkInsert's actual capacity (~30K/s). Continuous draining eliminates this throttle.
func (rb *RecordBuffer) drain() {
	for {
		rb.flush()
		if rb.pending.Load() < int32(rb.threshold) {
			return
		}
	}
}

// Stop stops the background goroutine, flushes remaining records, and closes the WAL.
// It blocks until run() has fully drained and closed the WAL, so callers can be
// certain the previous goroutine is no longer touching the file before a reload
// creates a new RecordBuffer over the same WAL (H4 fix).
func (rb *RecordBuffer) Stop() {
	rb.cancel()
	<-rb.done
}
