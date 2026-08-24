// Package notifier defines the event notification interface for PKI events.
//
// The default implementation (SMTP mailer) is built into the core.
// Channel-specific implementations (Slack, DingTalk, Feishu, WeChat Work)
// have been extracted to the pki-webhook satellite project.
package notifier

// Notifier is the interface for sending event notifications.
// Implementations may deliver to email, chat, or any other channel.
type Notifier interface {
	// Send sends a notification for the given event.
	Send(event, subject, body string) error
}
