package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(p string, b []byte) error { return os.WriteFile(p, b, 0o600) }

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func requestWithCookie(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", cookieName+"="+tok)
	return r
}

// dir returns the store's data directory, so tests can reopen it.
func (s *Store) dir() string { return filepath.Dir(s.path) }

// mk opens a session for user on audience aud ("" = login host) and returns the cookie value.
func mk(a *App, user, aud string) string { return a.sessions.Create(user, aud, "", "", "") }

func mustSessions(t testing.TB, dir string, ttl, idle time.Duration, b Binding) *Sessions {
	t.Helper()
	s, err := NewSessions(dir, ttl, idle, b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
