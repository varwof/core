package ca

import (
	"crypto/x509"
	"sync"
	"sync/atomic"
	"time"
)

// AggregatorConfig is the aggregator configuration.
type AggregatorConfig struct {
	Window       time.Duration // Time window (default 200ms)
	BatchMax     int           // Maximum batch size (default 1000)
	AutoSwitchAt int           // Queue depth threshold for auto-switching to aggregation mode (default 50)
	BufferSize   int           // Pending issuance queue capacity (default 10000)
}

// DefaultAggregatorConfig returns the default configuration.
func DefaultAggregatorConfig() AggregatorConfig {
	return AggregatorConfig{
		Window:       200 * time.Millisecond,
		BatchMax:     1000,
		AutoSwitchAt: 50,
		BufferSize:   10000,
	}
}

// AggregatorReq is a single issuance request in the aggregator.
type AggregatorReq struct {
	CN      string
	Profile string
	KeyType string
	CAName  string
	SAN     string
	Result  chan *AggregatorResult // Result channel
}

// AggregatorResult is the issuance result.
type AggregatorResult struct {
	Serial string
	Cert   *x509.Certificate
	Err    error
}

// CertAggregator is the certificate issuance aggregator.
// Issues instantly under low load, automatically switches to time-window batch issuance under high load.
type CertAggregator struct {
	cfg      AggregatorConfig
	signer   CertSigner // The actual signing interface
	queue    chan *AggregatorReq
	done     chan struct{}
	wg       sync.WaitGroup
	inFlight atomic.Int64 // Current number of pending requests
}

// CertSigner is the signing interface called by the aggregator.
type CertSigner interface {
	SignBatch(items []*AggregatorReq, caName string) []*AggregatorResult
}

// NewCertAggregator creates an aggregator and starts the background processing goroutine.
func NewCertAggregator(cfg AggregatorConfig, signer CertSigner) *CertAggregator {
	if cfg.Window <= 0 {
		cfg.Window = 200 * time.Millisecond
	}
	if cfg.BatchMax <= 0 {
		cfg.BatchMax = 1000
	}
	if cfg.AutoSwitchAt <= 0 {
		cfg.AutoSwitchAt = 50
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 10000
	}

	a := &CertAggregator{
		cfg:    cfg,
		signer: signer,
		queue:  make(chan *AggregatorReq, cfg.BufferSize),
		done:   make(chan struct{}),
	}
	go a.loop()
	return a
}

// Request submits an issuance request.
// Under low load, issues instantly and returns directly; under high load, enqueues for batch processing.
func (a *CertAggregator) Request(req *AggregatorReq) *AggregatorResult {
	// Adaptive instant/aggregation switching
	if a.inFlight.Load() < int64(a.cfg.AutoSwitchAt) {
		// Low load: instant issuance
		a.inFlight.Add(1)
		defer a.inFlight.Add(-1)
		results := a.signer.SignBatch([]*AggregatorReq{req}, req.CAName)
		if len(results) > 0 {
			return results[0]
		}
		return &AggregatorResult{Err: ErrNoResult}
	}

	// High load: enqueue for batch processing
	a.inFlight.Add(1)
	req.Result = make(chan *AggregatorResult, 1)
	select {
	case a.queue <- req:
		// Enqueue successful, wait for result
		select {
		case result := <-req.Result:
			return result
		case <-time.After(5 * time.Second):
			a.inFlight.Add(-1)
			return &AggregatorResult{Err: ErrTimeout}
		}
	default:
		// Queue full: degrade to instant issuance
		a.inFlight.Add(-1)
		results := a.signer.SignBatch([]*AggregatorReq{req}, req.CAName)
		if len(results) > 0 {
			return results[0]
		}
		return &AggregatorResult{Err: ErrNoResult}
	}
}

// loop is the background goroutine: aggregates and batch-issues by time window.
func (a *CertAggregator) loop() {
	ticker := time.NewTicker(a.cfg.Window)
	defer ticker.Stop()

	pending := make([]*AggregatorReq, 0, a.cfg.BatchMax)

	for {
		select {
		case req := <-a.queue:
			pending = append(pending, req)
			if len(pending) >= a.cfg.BatchMax {
				a.flush(&pending)
			}

		case <-ticker.C:
			if len(pending) > 0 {
				a.flush(&pending)
			}

		case <-a.done:
			if len(pending) > 0 {
				a.flush(&pending)
			}
			return
		}
	}
}

// flush issues a batch of certificates and returns the results.
func (a *CertAggregator) flush(pending *[]*AggregatorReq) {
	batch := *pending
	*pending = (*pending)[:0]

	if len(batch) == 0 {
		return
	}

	// Group by CA
	groups := make(map[string][]*AggregatorReq)
	for _, req := range batch {
		caName := req.CAName
		if caName == "" {
			caName = "default"
		}
		groups[caName] = append(groups[caName], req)
	}

	// Batch issue per CA group
	var wg sync.WaitGroup
	for caName, items := range groups {
		wg.Add(1)
		go func(ca string, reqs []*AggregatorReq) {
			defer wg.Done()
			results := a.signer.SignBatch(reqs, ca)
			for i, r := range results {
				if i < len(reqs) && reqs[i].Result != nil {
					reqs[i].Result <- r
					close(reqs[i].Result)
				}
			}
			a.inFlight.Add(int64(-len(reqs)))
		}(caName, items)
	}
	wg.Wait()
}

// Close closes the aggregator and waits for all pending requests to complete.
func (a *CertAggregator) Close() {
	close(a.done)
}

var (
	ErrNoResult = &AggregatorError{"no result"}
	ErrTimeout  = &AggregatorError{"timeout"}
)

type AggregatorError struct{ msg string }

func (e *AggregatorError) Error() string { return e.msg }
