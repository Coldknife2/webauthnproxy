package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- reverse proxy: forwarded headers

func proxyTo(t *testing.T, trusted string) (*App, *http.Header) {
	t.Helper()
	got := &http.Header{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*got = r.Header.Clone()
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	a := testApp(t)
	a.cfg.Upstream, _ = url.Parse(up.URL)
	a.cfg.UserHeader = "X-Authenticated-User"
	if trusted != "" {
		a.cfg.TrustedProxies = mustTrust(trusted)
	}
	addUser(t, a)
	return a, got
}

func proxied(a *App, peer string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "http://app.example.com/page", nil)
	r.RemoteAddr = peer
	r.Header.Set("Cookie", cookieName+"="+a.sessions.New("remi", "", 0))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	return w
}

func TestProxyModeDropsForgedForwardedHeaders(t *testing.T) {
	a, got := proxyTo(t, "10.0.0.0/8")
	w := proxied(a, "203.0.113.7:5555", map[string]string{
		"X-Forwarded-For": "1.2.3.4", "X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https",
		"X-Real-Ip": "1.2.3.4", "Forwarded": "for=1.2.3.4;host=evil.example", "X-Authenticated-User": "admin",
	})
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if got.Get("X-Forwarded-For") != "203.0.113.7" {
		t.Errorf("upstream saw X-Forwarded-For %q, want only the real peer", got.Get("X-Forwarded-For"))
	}
	if got.Get("X-Forwarded-Host") != "app.example.com" || got.Get("X-Forwarded-Proto") != "http" {
		t.Errorf("forged host/proto reached the upstream: %q %q", got.Get("X-Forwarded-Host"), got.Get("X-Forwarded-Proto"))
	}
	if got.Get("X-Real-Ip") != "" || got.Get("Forwarded") != "" {
		t.Errorf("forged X-Real-Ip/Forwarded reached the upstream: %q %q", got.Get("X-Real-Ip"), got.Get("Forwarded"))
	}
	if got.Get("X-Authenticated-User") != "remi" {
		t.Errorf("identity header not overwritten: %q", got.Get("X-Authenticated-User"))
	}
}

func TestProxyModeKeepsATrustedProxysHeaders(t *testing.T) {
	a, got := proxyTo(t, "10.0.0.0/8")
	proxied(a, "10.0.0.2:5555", map[string]string{"X-Forwarded-For": "198.51.100.4", "X-Forwarded-Host": "public.example.com", "X-Forwarded-Proto": "https"})
	if got.Get("X-Forwarded-For") != "198.51.100.4, 10.0.0.2" || got.Get("X-Forwarded-Host") != "public.example.com" || got.Get("X-Forwarded-Proto") != "https" {
		t.Errorf("a trusted proxy's headers were not preserved: %v", *got)
	}
}

func TestSessionCookieNeverReachesTheUpstream(t *testing.T) {
	a, got := proxyTo(t, "")
	w := proxied(a, "203.0.113.7:1", map[string]string{"Cookie": cookieName + "=" + a.sessions.New("remi", "", 0) + "; theme=dark"})
	if w.Code != 200 || strings.Contains(got.Get("Cookie"), cookieName) || got.Get("Cookie") != "theme=dark" {
		t.Errorf("upstream cookie header: %q", got.Get("Cookie"))
	}
}

// ---- session key rotation

func TestKeyRotationKeepsSessionsAlive(t *testing.T) {
	oldKey := []byte("old-key-0123456789abcdef0123456789")
	newKey := []byte("new-key-0123456789abcdef0123456789")
	before := NewSessions(oldKey, nil, time.Hour, 0)
	cookie := before.New("remi", "anysite.com", 3)
	ticket := before.NewTicket("remi", "anysite.com", 3)

	during := NewSessions(newKey, [][]byte{oldKey}, time.Hour, 0) // rotation window: new key signs, old key still verifies
	if u, aud, gen, err := during.Verify(cookie); err != nil || u != "remi" || aud != "anysite.com" || gen != 3 {
		t.Fatalf("a session signed with the previous key was refused during rotation: %v", err)
	}
	// rotation means a restart, and tickets do not survive a restart (single use is kept in memory); sessions do
	if _, _, _, _, _, err := during.VerifyTicket(ticket); err == nil {
		t.Fatal("a ticket from before the restart was accepted")
	}
	fresh := during.New("remi", "anysite.com", 3)

	after := NewSessions(newKey, nil, time.Hour, 0) // previous key removed
	if _, _, _, err := after.Verify(fresh); err != nil {
		t.Fatalf("tokens issued during rotation must be signed with the new key: %v", err)
	}
	if _, _, _, err := after.Verify(cookie); err == nil {
		t.Fatal("a token signed with a removed key is still accepted")
	}
	if _, _, _, err := NewSessions(oldKey, nil, time.Hour, 0).Verify(fresh); err == nil {
		t.Fatal("the old key accepted a token signed with the new one")
	}
}

func TestRotationDoesNotWeakenForgeryChecks(t *testing.T) {
	cur, prev := []byte("cur-key-0123456789abcdef0123456789"), []byte("prev-key-0123456789abcdef012345678")
	s := NewSessions(cur, [][]byte{prev}, time.Hour, 0)
	stranger := NewSessions([]byte("stranger-key-0123456789abcdef01234"), nil, time.Hour, 0)
	if _, _, _, err := s.Verify(stranger.New("remi", "", 0)); err == nil {
		t.Error("token signed with an unknown key accepted")
	}
	// altering a field of a validly signed token breaks the signature under every accepted key
	p := strings.Split(NewSessions(prev, nil, time.Hour, 0).New("remi", "", 0), ".")
	p[0] = b64.EncodeToString([]byte("admin"))
	if _, _, _, err := s.Verify(strings.Join(p, ".")); err == nil {
		t.Error("tampered token accepted")
	}
}

func TestLoadSecretsReadsThePreviousKeyFile(t *testing.T) {
	dir := t.TempDir()
	cur1, prev, err := loadSecrets(dir, nil, nil)
	if err != nil || len(prev) != 0 || len(cur1) != 32 {
		t.Fatalf("first start: %v %d %d", err, len(cur1), len(prev))
	}
	// documented rotation: move the key aside and restart
	if err := os.Rename(filepath.Join(dir, "session.key"), filepath.Join(dir, "session.key.previous")); err != nil {
		t.Fatal(err)
	}
	cur2, prev, err := loadSecrets(dir, nil, [][]byte{[]byte("env-previous-0123456789abcdef012345")})
	if err != nil || bytes.Equal(cur2, cur1) || len(prev) != 2 || !bytes.Equal(prev[1], cur1) {
		t.Fatalf("after rotation: current changed=%v previous=%d err=%v", !bytes.Equal(cur2, cur1), len(prev), err)
	}
}

func TestPreviousSecretMustBeLongEnough(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	t.Setenv("SESSION_SECRET_PREVIOUS", "short")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("a short previous key was accepted")
	}
}

// ---- idle timeout (stateless)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func idleSessions(idle time.Duration) (*Sessions, *clock) {
	c := &clock{time.Unix(2_000_000_000, 0)}
	s := NewSessions([]byte("idle-key-0123456789abcdef0123456789"), nil, 12*time.Hour, idle)
	s.now = c.now
	return s, c
}

func TestIdleTimeoutAndRenewal(t *testing.T) {
	s, c := idleSessions(time.Hour)
	tok := s.New("remi", "", 0)
	se, err := s.VerifySession(tok)
	if err != nil || s.NeedsRenewal(se) {
		t.Fatalf("fresh session: %v needsRenewal=%v", err, s.NeedsRenewal(se))
	}
	c.t = c.t.Add(20 * time.Minute) // more than a quarter of the idle timeout
	se, err = s.VerifySession(tok)
	if err != nil || !s.NeedsRenewal(se) {
		t.Fatalf("after 20 min: %v needsRenewal=%v", err, s.NeedsRenewal(se))
	}
	renewed := s.Renew(se)
	c.t = c.t.Add(50 * time.Minute) // 70 min after login: the original went idle, the renewed one (50 min old) did not
	if _, err := s.VerifySession(tok); err == nil || err.Error() != "idle" {
		t.Fatalf("the original session should be idle: %v", err)
	}
	re, err := s.VerifySession(renewed)
	if err != nil {
		t.Fatalf("the renewed session was refused: %v", err)
	}
	if !re.Exp.Equal(se.Exp) {
		t.Errorf("renewal moved the absolute expiry: %v -> %v", se.Exp, re.Exp)
	}
	c.t = se.Exp.Add(time.Second) // the absolute limit still applies
	if _, err := s.VerifySession(s.Renew(re)); err == nil {
		t.Error("a session was valid beyond its absolute expiry")
	}
}

func TestIdleTimeoutOffByDefault(t *testing.T) {
	s, c := idleSessions(0)
	tok := s.New("remi", "", 0)
	c.t = c.t.Add(11 * time.Hour)
	se, err := s.VerifySession(tok)
	if err != nil || s.NeedsRenewal(se) {
		t.Fatalf("without an idle timeout nothing expires early and nothing is renewed: %v", err)
	}
}

func TestLastActivityCannotBeForged(t *testing.T) {
	s, c := idleSessions(time.Hour)
	tok := s.New("remi", "", 0)
	c.t = c.t.Add(3 * time.Hour)
	p := strings.Split(tok, ".")
	p[4] = "2000000000" // rewrite "last seen" to pretend recent activity
	if _, err := s.VerifySession(strings.Join(p, ".")); err == nil {
		t.Fatal("a rewritten last-activity time was accepted")
	}
}

func TestProxyModeRefreshesTheCookieOnlyWhenNeeded(t *testing.T) {
	a, _ := proxyTo(t, "")
	s, c := idleSessions(time.Hour)
	a.sessions = s
	tok := s.New("remi", "", 0)
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://app.example.com/page", nil)
		r.Header.Set("Cookie", cookieName+"="+tok)
		w := httptest.NewRecorder()
		a.publicHandler().ServeHTTP(w, r)
		return w
	}
	if w := call(); w.Code != 200 || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("a recent session must not get a new cookie: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	c.t = c.t.Add(30 * time.Minute)
	w := call()
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Set-Cookie"), cookieName+"=") {
		t.Fatalf("an aging session must be renewed: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	c.t = c.t.Add(2 * time.Hour)
	if w := call(); w.Code != 401 {
		t.Fatalf("an idle session must be refused (the browser gets the login redirect, an API 401): %d", w.Code)
	}
}

func TestForwardModeRenewsTheSiteCookieOn200(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	s, c := idleSessions(time.Hour)
	a.sessions = s
	tok := s.New("remi", "anysite.com", 0)
	c.t = c.t.Add(30 * time.Minute)
	w := verifyReq(a, "anysite.com", "/page", tok)
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Set-Cookie"), cookieName+"=") || strings.Contains(w.Header().Get("Set-Cookie"), "Domain=") {
		t.Fatalf("verify must hand back a host-only renewed cookie: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
}

func TestIdleTimeoutConfig(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	t.Setenv("SESSION_TTL", "1h")
	for _, bad := range []string{"2h", "1h", "-5m", "soon"} {
		t.Setenv("SESSION_IDLE_TIMEOUT", bad)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("SESSION_IDLE_TIMEOUT=%s accepted", bad)
		}
	}
	t.Setenv("SESSION_IDLE_TIMEOUT", "15m")
	if c, err := LoadConfig(); err != nil || c.IdleTimeout != 15*time.Minute {
		t.Fatalf("valid idle timeout refused: %v", err)
	}
}

// ---- audit log

func auditLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		m := map[string]any{}
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("audit line is not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func events(lines []map[string]any) (names []string) {
	for _, m := range lines {
		names = append(names, m["event"].(string))
	}
	return
}

func TestAuditLogRecordsSecurityEventsWithoutSecrets(t *testing.T) {
	var buf bytes.Buffer
	a := forwardApp(t)
	a.audit = NewAudit(&buf, true)
	a.ipLimit = NewLimiter(RateSpec{1, time.Minute})
	addUser(t, a)

	login := a.sessions.New("remi", "", 0)
	// ticket issued, redeemed, replayed
	r := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://anysite.com/p"), nil)
	r.Header.Set("Cookie", cookieName+"="+login)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	cb, _ := url.Parse(w.Header().Get("Location"))
	ticket := cb.Query().Get("ticket")
	verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, "")
	verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, "")
	// untrusted caller, unlisted host, failed login, rate limit, sign-out
	bad := httptest.NewRequest("GET", "/_wap/verify", nil)
	bad.RemoteAddr = "203.0.113.9:1"
	a.publicHandler().ServeHTTP(httptest.NewRecorder(), bad)
	verifyReq(a, "evil.example", "/", "")
	post(a.publicHandler(), "/_wap/login/finish?cid=unknown", "198.51.100.5:1", nil)
	post(a.publicHandler(), "/_wap/login/finish?cid=unknown", "198.51.100.5:1", nil) // second request exceeds 1/min
	postLogout(a, login)

	lines := auditLines(t, &buf)
	got := strings.Join(events(lines), ",")
	for _, want := range []string{"ticket_issued", "site_login", "ticket_rejected", "untrusted_proxy", "host_denied", "login_failure", "rate_limited", "sign_out"} {
		if !strings.Contains(got, want) {
			t.Errorf("event %q missing from %s", want, got)
		}
	}
	for _, m := range lines {
		if m["msg"] != "audit" || m["time"] == nil {
			t.Errorf("unexpected line shape: %v", m)
		}
		if m["event"] == "ticket_rejected" && m["reason"] != "replay" {
			t.Errorf("replay recorded with reason %v", m["reason"])
		}
	}
	for _, secret := range []string{login, ticket, string(a.sessions.keys[0]), cookieName + "="} {
		if strings.Contains(buf.String(), secret) {
			t.Fatalf("the audit log leaked a secret: %q", secret)
		}
	}
}

func TestAuditLogRecordsImportsAndCanBeDisabled(t *testing.T) {
	dir, data := t.TempDir(), t.TempDir()
	store, _ := OpenStore(data)
	var buf bytes.Buffer
	_ = writeFile(dir+"/a.json", importJSON(t, "remi", "example.com", flagsUPUVAT))
	_ = writeFile(dir+"/b.json", []byte("not json"))
	importDir(store, dir, "example.com", true, NewAudit(&buf, true))
	got := strings.Join(events(auditLines(t, &buf)), ",")
	if !strings.Contains(got, "enroll_success") || !strings.Contains(got, "enroll_failure") {
		t.Errorf("import events missing: %s", got)
	}
	var off bytes.Buffer
	NewAudit(&off, false).Event("login_success") // nil logger: must not panic
	if off.Len() != 0 {
		t.Error("a disabled audit log wrote something")
	}
}
