package notifier

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTPServer is a minimal in-process SMTP server that supports STARTTLS,
// AUTH PLAIN, MAIL/RCPT/DATA. It lets tests exercise the full sendSTARTTLS
// success path without an external mail daemon.
type fakeSMTPServer struct {
	ln     net.Listener
	tlsCfg *tls.Config
	mu     sync.Mutex
	messages [][]string
}

func newFakeSMTPServer(t *testing.T) *fakeSMTPServer {
	t.Helper()
	cert := makeTestTLSCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTPServer{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}}}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func makeTestTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost", "127.0.0.1"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        tmpl,
	}
}

func (s *fakeSMTPServer) addr() string { return s.ln.Addr().String() }

func (s *fakeSMTPServer) recordSubject(subject string, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.messages = append(s.messages, []string{subject, body})
}

func (s *fakeSMTPServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer conn.Close()
	r := textproto.NewReader(bufio.NewReader(conn))
	w := textproto.NewWriter(bufio.NewWriter(conn))
	w.PrintfLine("220 localhost ESMTP fake")
	for {
		line, err := r.ReadLine()
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w.PrintfLine("250-localhost")
			w.PrintfLine("250-STARTTLS")
			w.PrintfLine("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "STARTTLS"):
			w.PrintfLine("220 2.0.0 Ready to start TLS")
			tlsConn := tls.Server(conn, s.tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			conn = tlsConn
			r = textproto.NewReader(bufio.NewReader(conn))
			w = textproto.NewWriter(bufio.NewWriter(conn))
		case strings.HasPrefix(cmd, "AUTH"):
			// AUTH PLAIN <base64> — accept anything
			w.PrintfLine("235 2.7.0 Authentication successful")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			w.PrintfLine("250 2.1.0 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			w.PrintfLine("250 2.1.5 OK")
		case strings.HasPrefix(cmd, "DATA"):
			w.PrintfLine("354 End data with <CR><LF>.<CR><LF>")
			var subject, body string
			block, err := r.ReadDotLines()
			if err != nil {
				return
			}
			for _, l := range block {
				if strings.HasPrefix(strings.ToLower(l), "subject:") {
					subject = strings.TrimSpace(l[len("subject:"):])
				}
				if l != "" {
					body += l + "\n"
				}
			}
			s.recordSubject(subject, body)
			w.PrintfLine("250 2.0.0 OK: queued")
		case strings.HasPrefix(cmd, "QUIT"):
			w.PrintfLine("221 2.0.0 Bye")
			return
		case cmd == "":
			// ignore blank lines
		default:
			w.PrintfLine("250 OK")
		}
	}
}

func (s *fakeSMTPServer) lastMessage() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.messages) == 0 {
		return "", ""
	}
	last := s.messages[len(s.messages)-1]
	return last[0], last[1]
}

func TestMailer_Send_STARTTLS_Success(t *testing.T) {
	server := newFakeSMTPServer(t)
	m := NewMailer(SMTPConfig{
		Host:              "127.0.0.1",
		Port:              serverPort(server),
		Username:          "user@test.com",
		Password:          "secret",
		From:              "from@test.com",
		To:                "to@test.com",
		TLS:               true,
		InsecureSkipVerify: true,
	})
	if err := m.Send("issue", "Certificate issued", "body text"); err != nil {
		t.Fatalf("send: %v", err)
	}
	subject, body := server.lastMessage()
	if !strings.Contains(subject, "Certificate issued") {
		t.Errorf("subject: %q", subject)
	}
	if !strings.Contains(body, "body text") {
		t.Errorf("body: %q", body)
	}
}

func TestMailer_Send_STARTTLS_NoAuth(t *testing.T) {
	server := newFakeSMTPServer(t)
	m := NewMailer(SMTPConfig{
		Host:               "127.0.0.1",
		Port:               serverPort(server),
		From:               "from@test.com",
		To:                 "to@test.com",
		TLS:                true,
		InsecureSkipVerify: true,
	})
	if err := m.Send("revoke", "Cert revoked", "bye"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if subject, _ := server.lastMessage(); !strings.Contains(subject, "Cert revoked") {
		t.Errorf("subject: %q", subject)
	}
}

func serverPort(s *fakeSMTPServer) int {
	_, portStr, err := net.SplitHostPort(s.addr())
	if err != nil {
		return 0
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}
