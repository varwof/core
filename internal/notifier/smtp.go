package notifier

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type SMTPConfig struct {
	Host              string `json:"host,omitempty"`
	Port              int    `json:"port,omitempty"`
	Username          string `json:"username,omitempty"`
	Password          string `json:"password,omitempty"`
	From              string `json:"from,omitempty"`
	To                string `json:"to,omitempty"`
	TLS               bool   `json:"tls,omitempty"`
	InsecureSkipVerify bool  `json:"insecure_skip_verify,omitempty"`
	Events            string `json:"events,omitempty"`
}

var DefaultSMTPConfig = SMTPConfig{
	Port: 587,
}

type Mailer struct {
	cfg SMTPConfig
}

func NewMailer(cfg SMTPConfig) *Mailer {
	if cfg.Port == 0 {
		cfg.Port = DefaultSMTPConfig.Port
	}
	return &Mailer{cfg: cfg}
}

func (m *Mailer) Send(event, subject, body string) error {
	if m.cfg.Host == "" {
		return fmt.Errorf("smtp host not configured")
	}
	if m.cfg.To == "" {
		return nil
	}
	toList := ParseRecipients(m.cfg.To)
	if len(toList) == 0 {
		return nil
	}

	if m.cfg.Events != "" {
		allowed := ParseRecipients(m.cfg.Events)
		var matched bool
		for _, a := range allowed {
			if strings.EqualFold(a, event) || a == "*" {
				matched = true
				break
			}
		}
		if !matched {
			return nil
		}
	}

	from := m.cfg.From
	if from == "" {
		from = m.cfg.Username
	}

	msg := BuildMessage(from, toList, subject, body)
	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprintf("%d", m.cfg.Port))

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	if m.cfg.TLS {
		return sendSTARTTLS(addr, from, toList, msg, auth, m.cfg)
	}
	return smtp.SendMail(addr, auth, from, toList, []byte(msg))
}

func sendSTARTTLS(addr, from string, to []string, msg string, auth smtp.Auth, cfg SMTPConfig) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	tlsCfg := &tls.Config{ServerName: cfg.Host, InsecureSkipVerify: cfg.InsecureSkipVerify}
	if err := client.StartTLS(tlsCfg); err != nil {
		return fmt.Errorf("starttls: %w", err)
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("mail from: %w", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt %s: %w", rcpt, err)
		}
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	_, err = w.Write([]byte(msg))
	if err != nil {
		w.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return client.Quit()
}

func BuildMessage(from string, to []string, subject, body string) string {
	header := make(map[string]string)
	header["From"] = from
	header["To"] = strings.Join(to, ", ")
	header["Subject"] = subject
	header["MIME-Version"] = "1.0"
	header["Content-Type"] = "text/plain; charset=UTF-8"
	header["Date"] = time.Now().Format(time.RFC1123Z)

	var buf strings.Builder
	for k, v := range header {
		buf.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	buf.WriteString("\r\n")
	buf.WriteString(body)
	return buf.String()
}

func ParseRecipients(s string) []string {
	parts := strings.Split(s, ",")
	var res []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			res = append(res, p)
		}
	}
	return res
}
