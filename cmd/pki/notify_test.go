package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/notifier"
)

func newTestDBForNotify(t *testing.T) *db.DB {
	t.Helper()
	dir := t.TempDir()
	d, err := db.Open(dir + "/test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func testConfig() *internal.Config {
	cfg := internal.DefaultConfig()
	cfg.Serve.Addr = ":0"
	cfg.Defaults.CA = "test-ca"
	return &cfg
}

func TestNotifyEventSendsPayload(t *testing.T) {
	var received struct {
		payload map[string]interface{}
		ok      bool
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p map[string]interface{}
		json.NewDecoder(r.Body).Decode(&p)
		received.payload = p
		received.ok = true
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Webhook.URL = ts.URL

	notifyEvent(cfg, nil, "test_event", "test-ca", "SERIAL", "test.example.com", "test message")

	if !received.ok {
		t.Fatal("webhook was not called")
	}
	if received.payload["event"] != "test_event" {
		t.Fatalf("expected test_event, got %v", received.payload["event"])
	}
	if received.payload["serial"] != "SERIAL" {
		t.Fatalf("expected SERIAL, got %v", received.payload["serial"])
	}
	if received.payload["message"] != "test message" {
		t.Fatalf("unexpected message: %v", received.payload["message"])
	}
	if received.payload["time"] == nil {
		t.Fatal("expected time field")
	}
}

func TestNotifyEventNoURL(t *testing.T) {
	cfg := testConfig()
	cfg.Webhook.URL = ""

	// Should not panic
	notifyEvent(cfg, nil, "event", "ca", "serial", "cn", "msg")
}

func TestNotifyEventDBSubscriptions(t *testing.T) {
	var callCount int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	d := newTestDBForNotify(t)
	db.CreateWebhookSub(d, ts.URL, "issue,revoke")
	db.CreateWebhookSub(d, ts.URL+"?disabled", "issue,revoke")
	cfg := testConfig()

	notifyEvent(cfg, d, "issue", "ca", "serial", "cn", "msg")

	if callCount < 1 {
		t.Fatal("expected at least 1 webhook call")
	}
}

func TestNotifyEventNon2xx(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Webhook.URL = ts.URL

	// Should not panic on non-2xx; retries with backoff
	notifyEvent(cfg, nil, "event", "ca", "serial", "cn", "msg")
	if calls != 3 {
		t.Fatalf("expected 3 calls (1 initial + 2 retries), got %d", calls)
	}
}

func TestCheckExpiryNoMetas(t *testing.T) {
	d := newTestDBForNotify(t)
	cfg := testConfig()

	// Should not panic when no CAs exist
	checkExpiry(cfg, d)
}

func TestCheckExpiryWithCA(t *testing.T) {
	calls := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	dir, _ := os.MkdirTemp("", "notify-test")
	defer os.RemoveAll(dir)

	d, err := db.Open(dir + "/pki.db")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	// Create a CA that expires tomorrow
	_, cert := newSigner(t)
	now := time.Now()
	d.InsertCAMeta(&db.CAMeta{
		Name:         "expiring-ca",
		CertDER:      cert.Raw,
		Subject:      cert.Subject.String(),
		NotBefore:    now.Add(-365 * 24 * time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyAlgorithm: "ecdsa-p256",
		Fingerprint:  "test",
	})

	cfg := testConfig()
	cfg.Webhook.URL = ts.URL

	checkExpiry(cfg, d)

	if calls == 0 {
		t.Fatal("expected at least one webhook call for expiring CA")
	}
}

func TestEventPayloadJSON(t *testing.T) {
	p := eventPayload{
		Event:   "issue",
		CAName:  "ca1",
		Serial:  "SERIAL",
		Common:  "cn",
		Message: "issued",
		Time:    "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var p2 eventPayload
	json.Unmarshal(data, &p2)
	if p2.Event != "issue" {
		t.Fatalf("expected issue, got %q", p2.Event)
	}
}

func newSigner(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func BenchmarkNotifyWebhook(b *testing.B) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := testConfig()
	cfg.Webhook.URL = ts.URL

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		notifyEvent(cfg, nil, "bench", "ca", fmt.Sprintf("serial-%d", i), "cn", "msg")
	}
}

func TestNotifySMTPNoopWhenNotConfigured(t *testing.T) {
	cfg := testConfig()
	// No SMTP config — should be no-op
	notifyEvent(cfg, nil, "test_event", "ca", "serial", "cn", "msg")
}

func TestMailerBuildMessage(t *testing.T) {
	msg := notifier.BuildMessage("alice@example.com", []string{"bob@example.com"}, "Test Subject", "Hello Bob")
	if !strings.Contains(msg, "From: alice@example.com") {
		t.Fatal("missing From")
	}
	if !strings.Contains(msg, "To: bob@example.com") {
		t.Fatal("missing To")
	}
	if !strings.Contains(msg, "Subject: Test Subject") {
		t.Fatal("missing Subject")
	}
	if !strings.Contains(msg, "Hello Bob") {
		t.Fatal("missing body")
	}
}

func TestMailerSMTPConnectionFailed(t *testing.T) {
	// Point to a non-listening port
	m := notifier.NewMailer(notifier.SMTPConfig{
		Host: "127.0.0.1",
		Port: 1,
		From: "test@example.com",
		To:   "test@example.com",
	})
	// Try with TLS (will fail quickly since nothing is listening on port 1)
	err := m.Send("test", "Subject", "Body")
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestMailerEventFilter(t *testing.T) {
	// Mailer with event filter should skip non-matching events
	m := notifier.NewMailer(notifier.SMTPConfig{
		Host:   "127.0.0.1",
		Port:   1,
		From:   "test@example.com",
		To:     "test@example.com",
		Events: "cert_issued,cert_revoked",
	})
	// This should return nil (filtered out) because "test" doesn't match
	err := m.Send("test", "Subject", "Body")
	if err != nil {
		t.Fatalf("expected no error for filtered event, got: %v", err)
	}

	// This should attempt connection (matching event)
	err = m.Send("cert_issued", "Subject", "Body")
	if err == nil {
		t.Fatal("expected connection error for matching event")
	}
}

func TestNotifySMTPEventFilterInConfig(t *testing.T) {
	cfg := testConfig()
	cfg.SMTP.Host = "127.0.0.1"
	cfg.SMTP.Port = 1
	cfg.SMTP.To = "admin@example.com"
	cfg.SMTP.Events = "cert_issued"

	// event not in filter — should be no-op (even though SMTP is configured)
	notifyEvent(cfg, nil, "cert_revoked", "ca", "serial", "cn", "msg")
}

func TestParseRecipients(t *testing.T) {
	r := notifier.ParseRecipients("a@x.com, b@y.com, ")
	if len(r) != 2 {
		t.Fatalf("expected 2 recipients, got %d: %v", len(r), r)
	}
	if r[0] != "a@x.com" || r[1] != "b@y.com" {
		t.Fatalf("unexpected recipients: %v", r)
	}

	r = notifier.ParseRecipients("")
	if len(r) != 0 {
		t.Fatalf("expected 0 recipients")
	}
}

// Minimal SMTP server for testing
type testSMTPServer struct {
	ln     net.Listener
	closed chan struct{}
	msgs   chan string
}

func startTestSMTPServer(t *testing.T) *testSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &testSMTPServer{ln: ln, closed: make(chan struct{}), msgs: make(chan string, 10)}
	go func() {
		defer close(s.closed)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Write([]byte("220 test ESMTP\r\n"))
				buf := make([]byte, 4096)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					line := string(buf[:n])
					if strings.HasPrefix(line, "DATA") {
						conn.Write([]byte("354 OK\r\n"))
						n, _ := conn.Read(buf)
						s.msgs <- string(buf[:n])
						conn.Write([]byte("250 OK\r\n"))
					} else if strings.HasPrefix(line, "QUIT") {
						conn.Write([]byte("221 Bye\r\n"))
						return
					} else {
						conn.Write([]byte("250 OK\r\n"))
					}
				}
			}()
		}
	}()
	return s
}

func (s *testSMTPServer) Addr() string {
	return s.ln.Addr().String()
}

func (s *testSMTPServer) Close() {
	s.ln.Close()
	<-s.closed
}

func TestMailerSendToRealServer(t *testing.T) {
	srv := startTestSMTPServer(t)
	defer srv.Close()

	host, portStr, _ := net.SplitHostPort(srv.Addr())
	port := 25
	fmt.Sscanf(portStr, "%d", &port)

	m := notifier.NewMailer(notifier.SMTPConfig{
		Host: host,
		Port: port,
		From: "test@example.com",
		To:   "admin@example.com",
		// No TLS, no auth — just plain SMTP
	})

	err := m.Send("test", "Test Subject", "Hello from PKI")
	if err != nil {
		t.Fatalf("send failed: %v", err)
	}

	select {
	case msg := <-srv.msgs:
		if !strings.Contains(msg, "Hello from PKI") {
			t.Fatalf("message body not found in: %s", msg)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for message")
	}
}
