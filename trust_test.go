package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func reqFrom(peer string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = peer
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestParseTrustedProxies(t *testing.T) {
	got, err := ParseTrustedProxies("10.0.0.0/8, 127.0.0.1 ,::1,fd00::/8")
	if err != nil || len(got) != 4 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0.1/abc"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, _ := ParseTrustedProxies(""); len(p) != 0 {
		t.Error("empty must mean: nobody is trusted")
	}
}

func TestClientIP(t *testing.T) {
	a := &App{cfg: &Config{TrustedProxies: mustTrust("10.0.0.0/8,127.0.0.1")}}
	cases := []struct {
		name, peer string
		xff        string
		want       string
	}{
		{"direct client, nothing forwarded", "203.0.113.7:4000", "", "203.0.113.7"},
		{"forged header from an untrusted peer is ignored", "203.0.113.7:4000", "1.1.1.1", "203.0.113.7"},
		{"trusted proxy reports the client", "10.0.0.2:5000", "198.51.100.4", "198.51.100.4"},
		{"a client-supplied prefix cannot override the proxy's entry", "10.0.0.2:5000", "6.6.6.6, 198.51.100.4", "198.51.100.4"},
		{"inner trusted hops are skipped", "10.0.0.2:5000", "198.51.100.4, 10.0.0.9", "198.51.100.4"},
		{"malformed header: fall back to the peer", "10.0.0.2:5000", "garbage", "10.0.0.2"},
		{"only trusted hops: the peer", "10.0.0.2:5000", "10.0.0.9", "10.0.0.2"},
		{"IPv4-mapped IPv6 peer", "[::ffff:127.0.0.1]:80", "198.51.100.4", "198.51.100.4"},
	}
	for _, c := range cases {
		hdr := map[string]string{}
		if c.xff != "" {
			hdr["X-Forwarded-For"] = c.xff
		}
		if got := a.clientIP(reqFrom(c.peer, hdr)); got.String() != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

func TestSchemeAndSecureCookieIgnoreForgedProto(t *testing.T) {
	a := &App{cfg: &Config{TrustedProxies: mustTrust("10.0.0.0/8"), CookieSecure: "auto"}}
	forged := reqFrom("203.0.113.7:1", map[string]string{"X-Forwarded-Proto": "https"})
	if a.scheme(forged) != "http" || a.secureSite(forged) {
		t.Error("an untrusted client must not be able to claim HTTPS")
	}
	real := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-Proto": "https"})
	if a.scheme(real) != "https" || !a.secureSite(real) {
		t.Error("a trusted proxy's X-Forwarded-Proto must be honored")
	}
	if p := reqFrom("10.0.0.2:1", map[string]string{"X-Forwarded-Proto": "javascript"}); a.scheme(p) != "http" {
		t.Error("unexpected scheme value accepted")
	}
	a.cfg.CookieSecure = "true"
	if !a.secureSite(reqFrom("203.0.113.7:1", nil)) {
		t.Error("COOKIE_SECURE=true must always set Secure")
	}
	a.cfg.CookieSecure = "false"
	if a.secureSite(real) {
		t.Error("COOKIE_SECURE=false must never set Secure")
	}
}

func TestVerifyRefusesAnUntrustedCaller(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	cookie := mk(a, "remi", "anysite.com")
	forged := func(peer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/_wap/verify", nil)
		r.RemoteAddr = peer
		r.Header.Set("X-Forwarded-Host", "anysite.com")
		r.Header.Set("X-Forwarded-Uri", "/")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("Cookie", cookieName+"="+cookie)
		w := httptest.NewRecorder()
		a.publicHandler().ServeHTTP(w, r)
		return w
	}
	if w := forged("203.0.113.9:4444"); w.Code != 403 || w.Header().Get("X-Authenticated-User") != "" {
		t.Fatalf("a caller outside TRUSTED_PROXIES got %d %v", w.Code, w.Header())
	}
	if w := forged("192.0.2.1:4444"); w.Code != 200 {
		t.Fatalf("the declared proxy got %d", w.Code)
	}
}

func TestForwardModeRequiresTrustedProxies(t *testing.T) {
	t.Setenv("MODE", "forward")
	t.Setenv("LOGIN_URL", "https://auth.example.com/_wap/login")
	t.Setenv("ALLOWED_HOSTS", "anysite.com")
	t.Setenv("RP_ID", "example.com")
	t.Setenv("RP_ORIGINS", "https://auth.example.com")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("forward mode started without TRUSTED_PROXIES")
	}
	t.Setenv("TRUSTED_PROXIES", "172.18.0.0/16")
	if c, err := LoadConfig(); err != nil || !c.trusts(netip.MustParseAddr("172.18.0.5")) || c.trusts(netip.MustParseAddr("172.19.0.5")) {
		t.Fatalf("TRUSTED_PROXIES not applied: %v", err)
	}
}
