package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// adminSetup starts the admin socket of an App with two passkeys for "remi" and one for "ana".
func adminSetup(t *testing.T) (*App, string, *bytes.Buffer) {
	t.Helper()
	a := testApp(t)
	var logs bytes.Buffer
	a.audit = NewAudit(&logs, true)
	for _, c := range []struct{ user, id string }{{"remi", "remi-phone-credential"}, {"remi", "remi-key-credential"}, {"ana", "ana-laptop-credential"}} {
		if err := a.store.AddCredential(a.store.GetOrNew(c.user), &webauthn.Credential{ID: []byte(c.id)}); err != nil {
			t.Fatal(err)
		}
	}
	dir, err := os.MkdirTemp("", "wap") // short path: unix sockets are limited to ~100 bytes
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	s, err := listenAdmin(dir, a.adminHandler())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return a, dir, &logs
}

func cli(dir string, args ...string) (string, error) {
	var out bytes.Buffer
	_, err := runCLI(args, dir, &out)
	return out.String(), err
}

func tagOf(id string) string { return credTag([]byte(id)) }

func TestAdminListPasskeys(t *testing.T) {
	_, dir, _ := adminSetup(t)
	out, err := cli(dir, "passkeys", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"remi-phone-credential", "remi-key-credential", "ana-laptop-credential"} {
		if !strings.Contains(out, tagOf(id)) {
			t.Errorf("list misses %s:\n%s", id, out)
		}
	}
	if !strings.Contains(out, "user=remi") || !strings.Contains(out, "user=ana") {
		t.Errorf("users missing:\n%s", out)
	}
	if strings.Contains(out, "remi-phone-credential") {
		t.Error("the full credential id must not be printed, only its short tag")
	}
}

func TestAdminRevokeEndsSessionsAndAudits(t *testing.T) {
	a, dir, logs := adminSetup(t)
	cookie := mk(a, "remi", "")
	out, err := cli(dir, "passkeys", "revoke", tagOf("remi-phone-credential")[:8]) // a prefix is enough
	if err != nil || !strings.Contains(out, "remi") {
		t.Fatalf("revoke: %q %v", out, err)
	}
	if n := len(a.store.ByName("remi").Credentials); n != 1 {
		t.Fatalf("remi has %d passkeys left, want 1", n)
	}
	// sessions are not tied to one passkey: the user's open sessions end with the revocation
	if _, ok := a.sessions.Lookup(cookie, "", ""); ok {
		t.Fatal("the old session is still valid")
	}
	if !strings.Contains(logs.String(), `"event":"credential_deleted"`) || !strings.Contains(logs.String(), `"via":"cli"`) {
		t.Errorf("no audit event: %s", logs.String())
	}
}

func TestAdminRevokeRefusals(t *testing.T) {
	a, dir, _ := adminSetup(t)
	cases := map[string][]string{
		"unknown id":         {"passkeys", "revoke", "zzzzzzzz"},
		"too short an id":    {"passkeys", "revoke", "cm"},
		"ambiguous prefix":   {"passkeys", "revoke", "cmVtaS"}, // "remi-…" credentials share their first characters
		"wrong usage":        {"passkeys", "revoke"},
		"unknown signout":    {"signout", "nobody"},
		"unknown subcommand": {"passkeys", "frobnicate"},
	}
	for name, args := range cases {
		if _, err := cli(dir, args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if a.store.CredentialCount() != 3 {
		t.Fatalf("a refused command removed a passkey (%d left)", a.store.CredentialCount())
	}
}

func TestAdminRefusesToDeleteTheLastPasskey(t *testing.T) {
	a := testApp(t)
	if err := a.store.AddCredential(a.store.GetOrNew("remi"), &webauthn.Credential{ID: []byte("only-one-credential")}); err != nil {
		t.Fatal(err)
	}
	dir, _ := os.MkdirTemp("", "wap")
	t.Cleanup(func() { os.RemoveAll(dir) })
	s, err := listenAdmin(dir, a.adminHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := cli(dir, "passkeys", "revoke", tagOf("only-one-credential")); err == nil || !strings.Contains(err.Error(), "last passkey") {
		t.Fatalf("last passkey deletable: %v", err)
	}
	if a.store.CredentialCount() != 1 {
		t.Fatal("last passkey was removed")
	}
}

func TestAdminSignOut(t *testing.T) {
	a, dir, logs := adminSetup(t)
	ana, remi := mk(a, "ana", ""), mk(a, "remi", "")
	if _, err := cli(dir, "signout", "ana"); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.sessions.Lookup(ana, "", ""); ok {
		t.Fatal("ana is still signed in")
	}
	if _, ok := a.sessions.Lookup(remi, "", ""); !ok {
		t.Fatal("another user was signed out")
	}
	if !strings.Contains(logs.String(), `"event":"sign_out"`) {
		t.Error("no audit event")
	}
}

func TestAdminSocketIsPrivateAndNotOnTheNetwork(t *testing.T) {
	a, dir, _ := adminSetup(t)
	st, err := os.Stat(filepath.Join(dir, adminSocket))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, want 0600", st.Mode().Perm())
	}
	remiSession := mk(a, "remi", "")
	// none of the HTTP handlers served to the network carries the admin routes
	a.cfg.Mode = "forward"
	a.cfg.TrustedProxies = mustTrust("192.0.2.0/24")
	for name, h := range map[string]http.Handler{"public": a.publicHandler(), "enroll": a.enrollHandler(), "tool": a.toolHandler()} {
		for _, req := range [][2]string{{"GET", "/passkeys"}, {"DELETE", "/passkeys/abcdefgh"}, {"POST", "/users/remi/signout"}} {
			w := do(h, req[0], req[1], nil)
			if w.Code == 200 {
				t.Errorf("%s handler served %s %s", name, req[0], req[1])
			}
		}
	}
	if a.store.CredentialCount() != 3 || !sessionAlive(a, remiSession) {
		t.Fatal("a network handler changed the data")
	}
}

func TestAdminWithoutServiceExplains(t *testing.T) {
	dir := t.TempDir()
	_, err := cli(dir, "passkeys", "list")
	if err == nil || !strings.Contains(err.Error(), "cannot reach the running service") {
		t.Fatalf("unhelpful error: %v", err)
	}
}

func TestAdminStaleSocketIsReplaced(t *testing.T) {
	dir, _ := os.MkdirTemp("", "wap")
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, adminSocket)) // a socket left by a previous run
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	a := testApp(t)
	s, err := listenAdmin(dir, a.adminHandler())
	if err != nil {
		t.Fatalf("a stale socket prevents start: %v", err)
	}
	s.Close()
}

// ---- health check

func TestHealthz(t *testing.T) {
	a := testApp(t)
	a.cfg.Upstream = nil
	srv := httptest.NewServer(a.publicHandler())
	defer srv.Close()
	t.Setenv("LISTEN", strings.TrimPrefix(srv.URL, "http://"))
	var out bytes.Buffer
	if handled, err := runCLI([]string{"healthcheck"}, t.TempDir(), &out); !handled || err != nil {
		t.Fatalf("healthcheck: %v %v", handled, err)
	}
	// no session needed, nothing in the answer but "ok"
	w := do(a.publicHandler(), "GET", "/_wap/healthz", nil)
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "ok" {
		t.Fatalf("healthz: %d %q", w.Code, w.Body.String())
	}
}

func TestHealthcheckFailsWhenDown(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	t.Setenv("LISTEN", addr)
	if _, err := runCLI([]string{"healthcheck"}, t.TempDir(), &bytes.Buffer{}); err == nil {
		t.Fatal("a stopped service reported healthy")
	}
}

func TestHealthcheckReportsUnhealthyStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 503) }))
	defer srv.Close()
	t.Setenv("LISTEN", strings.TrimPrefix(srv.URL, "http://"))
	if _, err := runCLI([]string{"healthcheck"}, t.TempDir(), &bytes.Buffer{}); err == nil {
		t.Fatal("503 reported healthy")
	}
}

func TestRunCLIIgnoresOrdinaryStart(t *testing.T) {
	if handled, _ := runCLI(nil, t.TempDir(), &bytes.Buffer{}); handled {
		t.Fatal("no argument must start the service")
	}
	if handled, _ := runCLI([]string{"--version"}, t.TempDir(), &bytes.Buffer{}); handled {
		t.Fatal("--version is handled elsewhere")
	}
}

func sessionAlive(a *App, cookie string) bool { _, ok := a.sessions.Lookup(cookie, "", ""); return ok }

func TestAdminSessions(t *testing.T) {
	a, dir, logs := adminSetup(t)
	one := a.sessions.Create("remi", "", "", "Mozilla/5.0 (X11; Linux) Firefox/141.0", "")
	two := a.sessions.Create("remi", "anysite.com", "", "", "")
	out, err := cli(dir, "sessions", "list")
	if err != nil || !strings.Contains(out, "user=remi") || !strings.Contains(out, "(login host)") ||
		!strings.Contains(out, "anysite.com") || !strings.Contains(out, "Firefox/141.0") {
		t.Fatalf("list: %q %v", out, err)
	}
	for _, secret := range []string{one, two} {
		if strings.Contains(out, secret) {
			t.Fatal("the listing printed a cookie value")
		}
	}
	se, _ := a.sessions.Lookup(one, "", "")
	if _, err := cli(dir, "sessions", "revoke", se.ID[:8]); err != nil {
		t.Fatal(err)
	}
	if sessionAlive(a, one) || !sessionAlive(a, two) {
		t.Fatal("revoke removed the wrong session")
	}
	if !strings.Contains(logs.String(), `"event":"session_revoked"`) {
		t.Error("no audit event")
	}
	for name, args := range map[string][]string{"unknown": {"sessions", "revoke", "zzzzzzzz"}, "too short": {"sessions", "revoke", "ab"}, "usage": {"sessions", "revoke"}} {
		if _, err := cli(dir, args...); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if !sessionAlive(a, two) {
		t.Fatal("a refused command revoked a session")
	}
}
