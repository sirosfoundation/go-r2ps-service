// Package audit provides structured audit logging for R2PS server events.
package audit

import (
	"log/slog"
	"time"
)

// EventType identifies the kind of auditable event.
type EventType string

const (
	EventKeyGenerate      EventType = "key_generate"
	EventKeySign          EventType = "key_sign"
	EventKeyAgree         EventType = "key_agree"
	EventKeyDelete        EventType = "key_delete"
	EventWKAIssued        EventType = "wka_issued"
	EventWIAIssued        EventType = "wia_issued"
	EventWIRevoked        EventType = "wi_revoked"
	EventWISuspended      EventType = "wi_suspended"
	Event2FARegistered    EventType = "2fa_registered"
	Event2FAAuthenticated EventType = "2fa_authenticated"
	Event2FAChanged       EventType = "2fa_changed"
	Event2FAFailed        EventType = "2fa_failed"
)

// Logger emits structured audit events.
type Logger struct {
	logger *slog.Logger
}

// New creates an audit logger backed by the given slog.Logger.
func New(logger *slog.Logger) *Logger {
	return &Logger{logger: logger}
}

// Log emits an audit event with the given attributes.
func (l *Logger) Log(event EventType, clientID, context string, attrs ...slog.Attr) {
	base := []slog.Attr{
		slog.String("audit_event", string(event)),
		slog.String("client_id", clientID),
		slog.String("context", context),
		slog.String("timestamp", time.Now().UTC().Format(time.RFC3339Nano)),
	}
	base = append(base, attrs...)

	args := make([]any, len(base))
	for i, a := range base {
		args[i] = a
	}
	l.logger.Info("AUDIT", args...)
}
