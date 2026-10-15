package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	r.Header.Set("Cookie", cookieName+"="+mk(a, "remi", ""))
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
	w := proxied(a, "203.0.113.7:1", map[string]string{"Cookie": cookieName + "=" + mk(a, "remi", "") + "; theme=dark"})
	if w.Code != 200 || strings.Contains(got.Get("Cookie"), cookieName) || got.Get("Cookie") != "theme=dark" {
		t.Errorf("upstream cookie header: %q", got.Get("Cookie"))
	}
}

// ---- idle timeout (exact, server side)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func idleSessions(t *testing.T, idle time.Duration) (*Sessions, *clock) {
	t.Helper()
	c := &clock{time.Unix(2_000_000_000, 0)}
	s := mustSessions(t, "", 12*time.Hour, idle, Binding{})
	s.now = c.now
	return s, c
}

func TestIdleTimeoutIsExactAndActivityKeepsTheSessionAlive(t *testing.T) {
	s, c := idleSessions(t, time.Hour)
	tok := s.Create("remi", "", "", "", "")
	for i := 0; i < 5; i++ { // five visits 50 minutes apart: far beyond the idle timeout in total, never idle in between
		c.t = c.t.Add(50 * time.Minute)
		if _, ok := s.Lookup(tok, "", ""); !ok {
			t.Fatalf("visit %d: an active session was refused", i)
		}
	}
	c.t = c.t.Add(61 * time.Minute)
	if _, ok := s.Lookup(tok, "", ""); ok {
		t.Fatal("a session idle for longer than the timeout was accepted")
	}
	// the absolute limit still applies to a busy session
	tok = s.Create("remi", "", "", "", "")
	for i := 0; i < 30; i++ {
		c.t = c.t.Add(30 * time.Minute)
		s.Lookup(tok, "", "")
	}
	if _, ok := s.Lookup(tok, "", ""); ok {
		t.Fatal("a session was valid beyond SESSION_TTL")
	}
}

func TestIdleTimeoutOffByDefault(t *testing.T) {
	s, c := idleSessions(t, 0)
	tok := s.Create("remi", "", "", "", "")
	c.t = c.t.Add(11 * time.Hour)
	if _, ok := s.Lookup(tok, "", ""); !ok {
		t.Fatal("without an idle timeout nothing expires early")
	}
}

func TestIdleSessionNeedsNoCookieRenewal(t *testing.T) {
	// the browser's cookie never changes: activity is recorded on the server, so Traefik needs no extra option
	a := forwardApp(t)
	addUser(t, a)
	s, c := idleSessions(t, time.Hour)
	a.sessions = s
	tok := s.Create("remi", "anysite.com", "", "", "")
	c.t = c.t.Add(40 * time.Minute)
	w := verifyReq(a, "anysite.com", "/page", tok)
	if w.Code != 200 || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("verify must not touch the cookie: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	c.t = c.t.Add(40 * time.Minute) // 80 minutes after login, 40 after the last visit
	if w := verifyReq(a, "anysite.com", "/page", tok); w.Code != 200 {
		t.Fatalf("the visit 40 minutes ago must have kept the session alive: %d", w.Code)
	}
	c.t = c.t.Add(2 * time.Hour)
	if w := verifyReq(a, "anysite.com", "/page", tok); w.Code != 302 {
		t.Fatalf("an idle session must send the browser to the login: %d", w.Code)
	}
}

func TestProxyModeIdleSession(t *testing.T) {
	a, _ := proxyTo(t, "")
	s, c := idleSessions(t, time.Hour)
	a.sessions = s
	tok := s.Create("remi", "", "", "", "")
	call := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://app.example.com/page", nil)
		r.Header.Set("Cookie", cookieName+"="+tok)
		w := httptest.NewRecorder()
		a.publicHandler().ServeHTTP(w, r)
		return w
	}
	if w := call(); w.Code != 200 || w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("recent session: %d %q", w.Code, w.Header().Get("Set-Cookie"))
	}
	c.t = c.t.Add(2 * time.Hour)
	if w := call(); w.Code != 401 {
		t.Fatalf("an idle session must be refused: %d", w.Code)
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

	login := mk(a, "remi", "")
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
		if m["event"] == "ticket_rejected" && m["reason"] != "unknown, expired or already used" {
			t.Errorf("replay recorded with reason %v", m["reason"])
		}
	}
	for _, secret := range []string{login, ticket, cookieName + "="} {
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
