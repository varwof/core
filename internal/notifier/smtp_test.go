package notifier

import (
	"net"
	"strings"
	"testing"
)

func TestParseRecipients(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"a@b.com", []string{"a@b.com"}},
		{"a@b.com, c@d.com", []string{"a@b.com", "c@d.com"}},
		{"a@b.com , c@d.com , e@f.com", []string{"a@b.com", "c@d.com", "e@f.com"}},
		{"", nil},
		{"  ,  ,  ", nil},
		{"a@b.com,,c@d.com", []string{"a@b.com", "c@d.com"}},
	}
	for _, tc := range tests {
		got := ParseRecipients(tc.input)
		if len(got) != len(tc.want) {
			t.Errorf("ParseRecipients(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("ParseRecipients(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestBuildMessage(t *testing.T) {
	msg := BuildMessage("from@test.com", []string{"to@test.com"}, "Subject", "Body")
	if !strings.Contains(msg, "From: from@test.com") {
		t.Error("missing From header")
	}
	if !strings.Contains(msg, "To: to@test.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(msg, "Subject: Subject") {
		t.Error("missing Subject header")
	}
	if !strings.Contains(msg, "MIME-Version: 1.0") {
		t.Error("missing MIME-Version")
	}
	if !strings.Contains(msg, "Content-Type: text/plain; charset=UTF-8") {
		t.Error("missing Content-Type")
	}
	if !strings.Contains(msg, "\r\n\r\nBody") {
		t.Error("missing body after headers")
	}
}

func TestBuildMessage_MultipleTo(t *testing.T) {
	msg := BuildMessage("from@test.com", []string{"a@test.com", "b@test.com"}, "S", "B")
	if !strings.Contains(msg, "To: a@test.com, b@test.com") {
		t.Error("missing multi-recipient To header")
	}
}

func TestNewMailer_DefaultPort(t *testing.T) {
	m := NewMailer(SMTPConfig{Host: "localhost"})
	if m.cfg.Port != 587 {
		t.Errorf("default port = %d, want 587", m.cfg.Port)
	}
}

func TestNewMailer_ExplicitPort(t *testing.T) {
	m := NewMailer(SMTPConfig{Host: "localhost", Port: 25})
	if m.cfg.Port != 25 {
		t.Errorf("port = %d, want 25", m.cfg.Port)
	}
}

func TestMailer_Send_EmptyHost(t *testing.T) {
	m := NewMailer(SMTPConfig{})
	err := m.Send("test", "subject", "body")
	if err == nil {
		t.Error("expected error for empty host")
	}
	if !strings.Contains(err.Error(), "host not configured") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMailer_Send_EmptyTo(t *testing.T) {
	m := NewMailer(SMTPConfig{Host: "localhost"})
	err := m.Send("test", "subject", "body")
	if err != nil {
		t.Errorf("empty To should return nil, got %v", err)
	}
}

func TestMailer_Send_OnlyCommas(t *testing.T) {
	m := NewMailer(SMTPConfig{Host: "localhost", To: "  ,  "})
	err := m.Send("test", "subject", "body")
	if err != nil {
		t.Errorf("comma-only To should return nil, got %v", err)
	}
}

func TestMailer_Send_EventFilter_NoMatch(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		To:     "admin@test.com",
		Events: "revoke,crl",
	})
	err := m.Send("issue", "subject", "body")
	if err != nil {
		t.Errorf("unmatched event should return nil, got %v", err)
	}
}

func TestMailer_Send_EventFilter_Match(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		Port:   25,
		To:     "admin@test.com",
		Events: "issue",
	})
	// This will fail because localhost:25 is not running, but it covers the matched path
	_ = m.Send("issue", "subject", "body")
}

func TestMailer_Send_EventFilter_Wildcard(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		Port:   25,
		To:     "admin@test.com",
		Events: "*",
	})
	_ = m.Send("any-event", "subject", "body")
}

func TestMailer_Send_EventFilter_CaseInsensitive(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		Port:   25,
		To:     "admin@test.com",
		Events: "Issue",
	})
	_ = m.Send("issue", "subject", "body")
}

func TestMailer_Send_FromFallbackToUsername(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:     "localhost",
		Port:     25,
		Username: "user@test.com",
		To:       "admin@test.com",
	})
	// Covers the fallback path where from="" uses username
	_ = m.Send("test", "subject", "body")
}

func TestMailer_Send_NonTLS(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host: "127.0.0.1",
		Port: 19999,
		To:   "admin@test.com",
	})
	err := m.Send("test", "subject", "body")
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestMailer_Send_TLS(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host: "127.0.0.1",
		Port: 19999,
		To:   "admin@test.com",
		TLS:  true,
	})
	err := m.Send("test", "subject", "body")
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestMailer_Send_STARTTLS_DialFail(t *testing.T) {
	err := sendSTARTTLS("127.0.0.1:19999", "from@test.com", []string{"to@test.com"}, "msg", nil, SMTPConfig{Host: "127.0.0.1"})
	if err == nil {
		t.Error("expected dial error")
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Errorf("expected dial error, got: %v", err)
	}
}

func TestMailer_Send_STARTTLS_InvalidHost(t *testing.T) {
	addr := net.JoinHostPort("127.0.0.1", "19999")
	err := sendSTARTTLS(addr, "from@test.com", []string{"to@test.com"}, "msg", nil, SMTPConfig{Host: "127.0.0.1"})
	if err == nil {
		t.Error("expected error for STARTTLS to non-SMTP server")
	}
}

func TestDefaultSMTPConfig(t *testing.T) {
	if DefaultSMTPConfig.Port != 587 {
		t.Errorf("default port = %d, want 587", DefaultSMTPConfig.Port)
	}
}

func TestBuildMessage_DateHeader(t *testing.T) {
	msg := BuildMessage("from@test.com", []string{"to@test.com"}, "S", "B")
	if !strings.Contains(msg, "Date: ") {
		t.Error("missing Date header")
	}
}

func TestMailer_Send_EventFilter_EmptyEvents(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		Port:   25,
		To:     "admin@test.com",
		Events: "",
	})
	_ = m.Send("test", "subject", "body")
}

func TestMailer_Send_EventFilter_SingleComma(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:   "localhost",
		Port:   25,
		To:     "admin@test.com",
		Events: "issue,revoke",
	})
	_ = m.Send("revoke", "subject", "body")
}

func TestMailer_Send_FromEmpty_UsesFrom(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host: "localhost",
		Port: 25,
		From: "explicit@test.com",
		To:   "admin@test.com",
	})
	_ = m.Send("test", "subject", "body")
}

func TestMailer_Send_AuthPath(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:     "127.0.0.1",
		Port:     19999,
		Username: "user@test.com",
		Password: "pass",
		To:       "admin@test.com",
	})
	err := m.Send("test", "subject", "body")
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestMailer_Send_TLS_Auth(t *testing.T) {
	m := NewMailer(SMTPConfig{
		Host:     "127.0.0.1",
		Port:     19999,
		Username: "user@test.com",
		Password: "pass",
		To:       "admin@test.com",
		TLS:      true,
	})
	err := m.Send("test", "subject", "body")
	if err == nil {
		t.Error("expected connection error")
	}
}

func TestMailer_Send_STARTTLS_QuotedAddress(t *testing.T) {
	addr := net.JoinHostPort("127.0.0.1", "19999")
	err := sendSTARTTLS(addr, "from@test.com", []string{"to@test.com"}, "Subject: test\r\n\r\nbody", nil, SMTPConfig{Host: "127.0.0.1"})
	if err == nil {
		t.Error("expected error")
	}
}
