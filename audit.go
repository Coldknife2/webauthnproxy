package main

import (
	"io"
	"log/slog"
	"net/http"
)

// Audit writes security-relevant events as one JSON object per line (to standard output in the service).
// It never receives cookies, tickets, tokens or keys: callers pass names, addresses and reasons only.
type Audit struct{ log *slog.Logger }

// NewAudit returns a logger writing to w, or a no-op logger when enabled is false.
func NewAudit(w io.Writer, enabled bool) *Audit {
	if !enabled {
		return nil
	}
	return &Audit{log: slog.New(slog.NewJSONHandler(w, nil))}
}

// Event records an audit event; attrs are key/value pairs. Safe to call on a nil *Audit.
func (u *Audit) Event(event string, attrs ...any) {
	if u == nil {
		return
	}
	u.log.Info("audit", append([]any{"event", event}, attrs...)...)
}

// auditReq records an event with the client address and path of the request.
func (a *App) auditReq(r *http.Request, event string, attrs ...any) {
	if a.audit == nil {
		return
	}
	ip := a.clientIP(r)
	a.audit.Event(event, append([]any{"ip", ip.String(), "path", r.URL.Path}, attrs...)...)
}
