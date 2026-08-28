// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/varwof/core/internal/ca"
	pki "github.com/varwof/types"
)

// Run executes the configured load test against the embedded server.
func (e *Env) Run(opts Options) (*Report, error) {
	rep := &Report{
		Mode:      opts.Mode,
		Scenario:  opts.Scenario,
		Duration:  opts.Duration.String(),
		Agents:    opts.Agents,
		Users:     opts.Users,
		TargetQPS: int(opts.QPS),
		Interval:  opts.Interval.String(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Duration)
	defer cancel()

	m := NewMetrics()
	go e.progress(opts, m, ctx)

	var rl *rateLimiter
	if opts.Mode == "stress" && opts.QPS > 0 {
		rl = newRateLimiter(opts.QPS)
	}

	var wg sync.WaitGroup
	for i := 0; i < opts.Agents; i++ {
		st := &agentState{id: i}
		if opts.Scenario == "aic" {
			// Pre-generate the agent keypair + CSR once per agent. In production
			// the agent generates its key locally and sends a CSR; generating it
			// here in setup removes the per-request server-side keygen from the
			// measured window (the server otherwise does ca.GenerateKey on every
			// request in convenience mode).
			csr, err := e.newAgentCSR(i)
			if err != nil {
				return nil, fmt.Errorf("pre-generate agent CSR %d: %w", i, err)
			}
			st.csrPEM = csr
		}
		wg.Add(1)
		go func(st *agentState) {
			defer wg.Done()
			switch opts.Scenario {
			case "aic":
				e.aicWorker(ctx, opts, st, m, rl)
			default:
				e.regularWorker(ctx, opts, st, m, rl)
			}
		}(st)
	}

	wg.Wait()

	tot := m.Snapshot()
	tot.DBSize = e.DBSize()
	if n, err := e.CountCerts(); err == nil {
		tot.CertCount = n
	}
	rep.Totals = tot
	return rep, nil
}

// agentState carries per-worker state (unique counters for CN generation) and,
// for the aic scenario, a pre-generated agent CSR so the server never has to
// generate keys inside the measured window.
type agentState struct {
	id     int
	seq    atomic.Int64
	csrPEM string
}

// newAgentCSR generates a fresh P-256 agent keypair and a DER CSR signed with
// it, returned as PEM. The server's AIC issue path uses only the CSR's public
// key (cert CN/agent-id come from the request), so the same CSR can back every
// request of one agent.
func (e *Env) newAgentCSR(id int) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", err
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: fmt.Sprintf("agent-%d", id), OrganizationalUnit: []string{"gateway:ops"}},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), nil
}

// regularWorker issues tls-client certificates. In stress mode it fires as
// fast as the server allows (paced only by the optional global rate limiter);
// in random mode it sleeps an exponentially distributed interval first.
func (e *Env) regularWorker(ctx context.Context, opts Options, st *agentState, m *Metrics, rl *rateLimiter) {
	httpc := e.client(st.id + 8)
	base := "http://" + e.Addr
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if opts.Mode == "random" {
			if !sleepRandom(ctx, opts.Interval) {
				return
			}
		}
		if rl != nil {
			if !rl.wait(ctx) {
				return
			}
		}
		idx := st.seq.Add(1)
		cn := fmt.Sprintf("sso-user-%d-%d", st.id, idx)
		body := fmt.Sprintf(
			`{"ca":"people","cn":%q,"profile":"tls-client","validity":30,"key_type":"ecdsa-p256"}`,
			cn)
		e.doIssue(ctx, httpc, base, body, m)
	}
}

// aicWorker issues agent-proxy (AIC) certificates signed by the worker's
// assigned user identity (fresh DelegationAuth evidence per request).
func (e *Env) aicWorker(ctx context.Context, opts Options, st *agentState, m *Metrics, rl *rateLimiter) {
	httpc := e.client(st.id + 8)
	base := "http://" + e.Addr
	user := &e.Users[st.id%len(e.Users)]
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		if opts.Mode == "random" {
			if !sleepRandom(ctx, opts.Interval) {
				return
			}
		}
		if rl != nil {
			if !rl.wait(ctx) {
				return
			}
		}
		idx := st.seq.Add(1)
		agentID := fmt.Sprintf("agent-%d-%d", st.id, idx)
		body, err := e.buildAICBody(user, agentID, st.csrPEM)
		if err != nil {
			m.Record(0, 0, false)
			continue
		}
		e.doIssue(ctx, httpc, base, string(body), m)
	}
}

// doIssue POSTs one issuance request and records the outcome.
func (e *Env) doIssue(ctx context.Context, httpc *http.Client, base, body string, m *Metrics) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/certs", bytes.NewBufferString(body))
	if err != nil {
		m.Record(0, 0, false)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.APIToken)

	resp, err := httpc.Do(req)
	dur := time.Since(start)
	if err != nil {
		m.Record(dur, 0, false)
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	m.Record(dur, resp.StatusCode, resp.StatusCode == http.StatusOK)
}

// buildAICBody constructs the agent-proxy request body with a freshly signed
// DelegationAuthTBS, byte-for-byte consistent with the production C3 flow
// (see internal/serve/api_ops_c3_test.go agentProxyC3Body). The agent key is
// supplied as a pre-generated CSR (csrPEM), so the server uses CSR mode and
// never generates a key inside the measured window.
func (e *Env) buildAICBody(user *TestUser, agentID, csrPEM string) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(user.Cert.PublicKey)
	if err != nil {
		return nil, err
	}
	keyHash := sha256.Sum256(pubBytes)
	puid := "varwof:" + user.CN + ":" + base64.RawURLEncoding.EncodeToString(keyHash[:])

	pu, err := pki.ParsePrincipalUid(puid)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ts := time.Now().UTC().Truncate(time.Second)

	caps := []ca.Capability{{SchemeId: "varwof-gateway-v1", CapabilityId: "gateway:read"}}
	tbs := &pki.DelegationAuthTBS{
		Version:          1,
		AgentId:          agentID,
		PrincipalUid:     pu,
		Reason:           pki.Reason{ReasonCode: "API_ISSUE", Description: "user-authorized AIC issuance"},
		Capabilities:     toPKICaps(caps),
		DelegationMode:   pki.DelegationAuthorized,
		RequestedLifetime: 3600,
		Timestamp:        ts,
		Nonce:            nonce,
	}
	tbsDER, err := asn1.Marshal(*tbs)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, user.Key, digest[:])
	if err != nil {
		return nil, err
	}

	req := map[string]any{
		"ca":                           "people",
		"cn":                           agentID,
		"profile":                      "agent-proxy",
		"subject":                      "/CN=" + agentID + "/OU=gateway:admin",
		"validity":                     1,
		"agent_id":                     agentID,
		"principal_uid":                puid,
		"csr_pem":                      csrPEM,
		"user_auth_signature":          base64.StdEncoding.EncodeToString(sig),
		"user_auth_signature_algo":     "ECDSA-SHA256",
		"user_auth_nonce":              base64.StdEncoding.EncodeToString(nonce),
		"user_auth_lifetime":           3600,
		"user_auth_timestamp":          ts.Format(time.RFC3339),
		"user_auth_reason_code":        "API_ISSUE",
		"user_auth_reason_description": "user-authorized AIC issuance",
		"delegation_mode":              0,
		"capabilities":                 grantsJSON(caps),
		"user_cert_pem":                user.CertPEM,
		"principal_authorization": map[string]any{
			"grants":            grantsJSON(caps),
			"delegation_policy": map[string]any{"allowed_mode": 0},
		},
	}
	return json.Marshal(req)
}

// toPKICaps converts ca.Capability to the types (DelegationAuthTBS) shape.
func toPKICaps(cs []ca.Capability) []pki.Capability {
	if len(cs) == 0 {
		return nil
	}
	out := make([]pki.Capability, 0, len(cs))
	for _, c := range cs {
		out = append(out, pki.Capability{SchemeId: c.SchemeId, CapabilityId: c.CapabilityId, Parameters: c.Parameters})
	}
	return out
}

// grantsJSON matches the empty-capability JSON body shape used by the server.
func grantsJSON(cs []ca.Capability) []map[string]any {
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		m := map[string]any{"scheme_id": c.SchemeId, "capability_id": c.CapabilityId}
		if len(c.Parameters) > 0 {
			m["parameters"] = c.Parameters
		}
		out = append(out, m)
	}
	return out
}

// sleepRandom waits an exponentially distributed interval with the given mean,
// aborting early when ctx is cancelled.
func sleepRandom(ctx context.Context, mean time.Duration) bool {
	var wait time.Duration
	if mean > 0 {
		u, err := rand.Int(rand.Reader, big.NewInt(1<<53))
		if err != nil {
			wait = mean
		} else {
			wait = time.Duration(-math.Log(math.Max(float64(u.Int64())/float64(1<<53), 1e-9)) * float64(mean))
		}
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// rateLimiter is a global token bucket enforcing a target QPS across workers.
type rateLimiter struct {
	mu     sync.Mutex
	next   time.Time
	perTok time.Duration
}

func newRateLimiter(qps float64) *rateLimiter {
	per := time.Duration(float64(time.Second) / qps)
	if per < time.Microsecond {
		per = time.Microsecond
	}
	return &rateLimiter{perTok: per}
}

// wait blocks until the next token is available, or returns false on ctx cancel.
func (r *rateLimiter) wait(ctx context.Context) bool {
	for {
		r.mu.Lock()
		now := time.Now()
		if now.After(r.next) {
			r.next = now.Add(r.perTok)
			r.mu.Unlock()
			return ctx.Err() == nil
		}
		next := r.next
		r.next = next.Add(r.perTok)
		r.mu.Unlock()
		t := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

// progress prints a live throughput line every 5 seconds until ctx ends.
func (e *Env) progress(opts Options, m *Metrics, ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !opts.Verbose {
				continue
			}
			t := m.Snapshot()
			fmt.Printf("  [%s] req=%d ok=%d qps=%.0f p50=%.1fms p99=%.1fms fail=%d\n",
				time.Since(m.Start()).Round(time.Second),
				t.Total, t.Success, t.IssuedRate, t.LatencyP50, t.LatencyP99, t.Failed)
		}
	}
}

// Start returns the metrics start time (exposed for progress reporting).
func (m *Metrics) Start() time.Time {
	return m.start
}