package ca

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// JobStatus represents the status of an async job.
type JobStatus string

const (
	JobPending    JobStatus = "pending"
	JobProcessing JobStatus = "processing"
	JobDone       JobStatus = "done"
	JobFailed     JobStatus = "failed"
)

// JobRequest represents a single async issuance job.
type JobRequest struct {
	Items []JobRequestItem `json:"requests"`
}

// JobRequestItem represents a single certificate issuance request.
type JobRequestItem struct {
	CN      string `json:"cn"`
	SAN     string `json:"san,omitempty"`
	Profile string `json:"profile,omitempty"`
	KeyType string `json:"key_type,omitempty"`
	CA      string `json:"ca,omitempty"`
}

// JobResultItem represents a single certificate issuance result.
type JobResultItem struct {
	Serial string `json:"serial,omitempty"`
	CN     string `json:"cn"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Job stores the complete state of an async job.
type Job struct {
	ID        string          `json:"id"`
	Status    JobStatus       `json:"status"`
	Progress  int             `json:"progress"`    // completed count
	Total     int             `json:"total"`       // total count
	CreatedAt time.Time       `json:"created_at"`
	Error     string          `json:"error,omitempty"`
	Results   []JobResultItem `json:"results,omitempty"`
	items     []JobRequestItem
}

// JobQueue is an async job queue.
type JobQueue struct {
	mu       sync.RWMutex
	jobs     map[string]*Job
	pending  chan *Job
	workers  int
	done     chan struct{}
	idGen    atomic.Int64
	ttl      time.Duration // job result retention time
	processor JobProcessor
}

// JobProcessor is the actual issuance interface.
type JobProcessor interface {
	Process(items []JobRequestItem) []JobResultItem
}

// NewJobQueue creates an async job queue and starts background workers.
func NewJobQueue(workers int, ttl time.Duration, processor JobProcessor) *JobQueue {
	if workers <= 0 { workers = 4 }
	if ttl <= 0 { ttl = 5 * time.Minute }

	q := &JobQueue{
		jobs:      make(map[string]*Job),
		pending:   make(chan *Job, 10000),
		workers:   workers,
		done:      make(chan struct{}),
		ttl:       ttl,
		processor: processor,
	}
	for i := 0; i < workers; i++ {
		go q.worker()
	}
	go q.cleanupLoop()
	return q
}

// Submit submits an async issuance job and returns the job ID.
func (q *JobQueue) Submit(items []JobRequestItem) string {
	id := q.nextID()
	job := &Job{
		ID:        id,
		Status:    JobPending,
		Total:     len(items),
		CreatedAt: time.Now(),
		items:     items,
		Results:   make([]JobResultItem, len(items)),
	}

	q.mu.Lock()
	q.jobs[id] = job
	q.mu.Unlock()

	q.pending <- job
	return id
}

// GetJob queries job status.
func (q *JobQueue) GetJob(id string) *Job {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.jobs[id]
}

// worker is a background goroutine that fetches jobs from the queue and issues them.
func (q *JobQueue) worker() {
	for {
		select {
		case job := <-q.pending:
			q.process(job)
		case <-q.done:
			return
		}
	}
}

func (q *JobQueue) process(job *Job) {
	q.mu.Lock()
	job.Status = JobProcessing
	q.mu.Unlock()

	results := q.processor.Process(job.items)

	q.mu.Lock()
	job.Results = results
	job.Progress = len(results)
	hasErr := false
	for _, r := range results {
		if r.Status == "ok" && r.Serial != "" {
			job.Progress++
		}
		if r.Error != "" {
			hasErr = true
		}
	}
	if hasErr {
		job.Status = JobFailed
	} else {
		job.Status = JobDone
	}
	q.mu.Unlock()

	slog.Info("async job completed", "id", job.ID, "total", job.Total, "done", job.Progress)
}

// cleanupLoop periodically cleans up expired jobs.
func (q *JobQueue) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			q.mu.Lock()
			cutoff := time.Now().Add(-q.ttl)
			for id, job := range q.jobs {
				if job.CreatedAt.Before(cutoff) && job.Status != JobPending && job.Status != JobProcessing {
					delete(q.jobs, id)
				}
			}
			q.mu.Unlock()
		case <-q.done:
			return
		}
	}
}

func (q *JobQueue) nextID() string {
	n := q.idGen.Add(1)
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("job-%s-%05d", hex.EncodeToString(b), n)
}

// Close closes the queue.
func (q *JobQueue) Close() { close(q.done) }
