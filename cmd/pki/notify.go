package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/varwof/core/internal"
	"github.com/varwof/engine/db"
	"github.com/varwof/core/internal/notifier"
)

type eventPayload struct {
	Event   string `json:"event"`
	CAName  string `json:"ca_name,omitempty"`
	Serial  string `json:"serial,omitempty"`
	Common  string `json:"common_name,omitempty"`
	Message string `json:"message,omitempty"`
	Time    string `json:"time"`
}

func notifyEvent(cfg *internal.Config, database *db.DB, event, caName, serial, cn, msg string) {
	payload := eventPayload{
		Event:   event,
		CAName:  caName,
		Serial:  serial,
		Common:  cn,
		Message: msg,
		Time:    time.Now().UTC().Format(time.RFC3339),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("notify: marshal", "error", err)
		return
	}

	notifyWebhooks(cfg, database, data)
	notifySMTP(cfg, event, msg)
}

func notifyWebhooks(cfg *internal.Config, database *db.DB, data []byte) {
	webhookTimeout := 10 * time.Second
	if cfg.Webhook.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Webhook.Timeout); err == nil {
			webhookTimeout = d
		}
	}
	sendPayload := func(url string) {
		maxRetries := 2
		for attempt := 0; attempt <= maxRetries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
			if err != nil {
				slog.Warn("webhook: new request", "error", err)
				cancel()
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			cancel()
			if err != nil {
				if attempt < maxRetries {
					backoff := time.Duration(1<<(attempt+1)) * time.Second
					slog.Debug("webhook: retry", "url", url, "attempt", attempt+1, "backoff", backoff)
					time.Sleep(backoff)
					continue
				}
				slog.Warn("webhook: post failed after retries", "url", url, "error", err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 300 && attempt < maxRetries {
				backoff := time.Duration(1<<(attempt+1)) * time.Second
				slog.Debug("webhook: retry non-2xx", "url", url, "status", resp.StatusCode, "attempt", attempt+1)
				time.Sleep(backoff)
				continue
			}
			if resp.StatusCode >= 300 {
				slog.Warn("webhook: non-2xx after retries", "url", url, "status", resp.StatusCode)
			}
			break
		}
	}

	if cfg.Webhook.URL != "" {
		sendPayload(cfg.Webhook.URL)
	}

	if database != nil {
		subs, err := db.ListWebhookSubs(database)
		if err == nil {
			for _, sub := range subs {
				if sub.Enabled {
					sendPayload(sub.URL)
				}
			}
		}
	}
}

func notifySMTP(cfg *internal.Config, event, msg string) {
	sc := cfg.SMTP
	if sc.Host == "" || sc.To == "" {
		return
	}
	mailer := notifier.NewMailer(notifier.SMTPConfig{
		Host:              sc.Host,
		Port:              sc.Port,
		Username:          sc.Username,
		Password:          sc.Password,
		From:              sc.From,
		To:                sc.To,
		TLS:               internal.BoolOr(sc.TLS, false),
		InsecureSkipVerify: internal.BoolOr(sc.InsecureSkipVerify, false),
		Events:            sc.Events,
	})
	subject := fmt.Sprintf("[PKI] %s", event)
	if err := mailer.Send(event, subject, msg); err != nil {
		slog.Warn("smtp notify", "event", event, "error", err)
	}
}

func cmdNotify(cfg *internal.Config, args []string) error {
	if len(args) == 0 || args[0] == "help" {
		fmt.Println("Usage: pki notify test-smtp [--event cert_issued] [--message 'test']")
		fmt.Println("  test-smtp    Send a test email via SMTP config")
		return nil
	}
	switch args[0] {
	case "test-smtp":
		return cmdNotifyTestSMTP(cfg, args[1:])
	default:
		return fmt.Errorf("unknown notify subcommand: %s", args[0])
	}
}

func cmdNotifyTestSMTP(cfg *internal.Config, args []string) error {
	fs := flag.NewFlagSet("notify test-smtp", flag.ExitOnError)
	event := fs.String("event", "test", "event type")
	message := fs.String("message", "This is a test notification from PKI", "message body")
	fs.Parse(args)

	sc := cfg.SMTP
	if sc.Host == "" {
		return ef("cli.err_smtp_not_configured")
	}
	if sc.To == "" {
		return ef("cli.err_smtp_no_recipients")
	}

	mailer := notifier.NewMailer(notifier.SMTPConfig{
		Host:              sc.Host,
		Port:              sc.Port,
		Username:          sc.Username,
		Password:          sc.Password,
		From:              sc.From,
		To:                sc.To,
		TLS:               internal.BoolOr(sc.TLS, false),
		InsecureSkipVerify: internal.BoolOr(sc.InsecureSkipVerify, false),
		Events:            sc.Events,
	})
	subject := fmt.Sprintf("[PKI] Test: %s", *event)
	if err := mailer.Send(*event, subject, *message); err != nil {
		return fmt.Errorf("smtp send failed: %w", err)
	}
	fmt.Println("Test email sent successfully")
	return nil
}

func startExpiryWatcher(cfg *internal.Config, database *db.DB) {
	interval := 24 * time.Hour
	if cfg.Webhook.ExpiryCheckInterval != "" {
		if d, err := time.ParseDuration(cfg.Webhook.ExpiryCheckInterval); err == nil {
			interval = d
		}
	}
	go expiryLoop(cfg, database, time.NewTicker(interval).C)
}

func expiryLoop(cfg *internal.Config, database *db.DB, tickCh <-chan time.Time) {
	for range tickCh {
		checkExpiry(cfg, database)
	}
}

var (
	notifiedMu sync.Mutex
	notified   = make(map[string]bool) // key: "ca/serial/threshold"
)

func isNotified(key string) bool {
	notifiedMu.Lock()
	defer notifiedMu.Unlock()
	if notified[key] {
		return true
	}
	notified[key] = true
	return false
}

func checkExpiry(cfg *internal.Config, database *db.DB) {
	metas, err := database.ListCAMetas()
	if err != nil {
		slog.Warn("expiry: list ca_meta", "error", err)
		return
	}
	now := time.Now()
	thresholdDays := cfg.Webhook.ExpiryThresholds
	if len(thresholdDays) == 0 {
		thresholdDays = []int{30, 7, 1}
	}
	thresholds := make([]struct {
		days int
		msg  string
	}, len(thresholdDays))
	for i, d := range thresholdDays {
		thresholds[i] = struct {
			days int
			msg  string
		}{d, fmt.Sprintf("expires in %d days", d)}
	}
	for _, m := range metas {
		if m.NotAfter.IsZero() {
			continue
		}
		remaining := m.NotAfter.Sub(now)
		for _, t := range thresholds {
			bound := time.Duration(t.days) * 24 * time.Hour
			if remaining > bound {
				continue
			}
			key := fmt.Sprintf("ca/%s/%d", m.Name, t.days)
			if !isNotified(key) {
				notifyEvent(cfg, database, "ca_expiring", m.Name, "", m.Name,
					fmt.Sprintf("CA %s %s (%s)", m.Name, t.msg, m.NotAfter.Format("2006-01-02")))
			}
		}

		certs, err := database.ListCerts(m.Name)
		if err != nil {
			continue
		}
		for _, c := range certs {
			if c.Status != "V" {
				continue
			}
			remaining := c.NotAfter.Sub(now)
			for _, t := range thresholds {
				bound := time.Duration(t.days) * 24 * time.Hour
				if remaining > bound {
					continue
				}
				key := fmt.Sprintf("%s/%s/%d", m.Name, c.SerialNumber, t.days)
				if !isNotified(key) {
					notifyEvent(cfg, database, "cert_expiring", m.Name, c.SerialNumber, c.CommonName,
						fmt.Sprintf("cert %s/%s %s (%s)", m.Name, c.SerialNumber, t.msg, c.NotAfter.Format("2006-01-02")))
				}
			}
		}
	}
}
