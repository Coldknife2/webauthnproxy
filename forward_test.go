package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestHostAllowed(t *testing.T) {
	c := &Config{CookieDomain: "example.com", AllowedHosts: []string{"anysite.com", "*.other.org", "dev.local:8000"}}
	for host, want := range map[string]bool{
		"anysite.com": true, "anysite.com:8443": true, "ANYSITE.com": true,
		"www.anysite.com": false, "evilanysite.com": false,
		"a.other.org": true, "a.b.other.org": true, "other.org": false, "xother.org": false,
		"dev.local:8000": true, "dev.local:9000": false, "dev.local": false,
		"example.com": true, "app.example.com:443": true, "notexample.com": false,
		"": false,
	} {
		if got := c.HostAllowed(host); got != want {
			t.Errorf("HostAllowed(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestSafeNextAllowedHosts(t *testing.T) {
	lu, _ := url.Parse("https://auth.com/_wap/login")
	a := &App{cfg: &Config{Mode: "forward", LoginURL: lu, AllowedHosts: []string{"anysite.com"}}}
	if got := a.safeNext("https://anysite.com/x?y=1"); got != "https://anysite.com/x?y=1" {
		t.Errorf("allowed host refused: %q", got)
	}
	for _, bad := range []string{"https://evil.com/", "https://anysite.com.evil.com/", "javascript:alert(1)", "//anysite.com/"} {
		if got := a.safeNext(bad); got != "/" {
			t.Errorf("safeNext(%q) = %q, want /", bad, got)
		}
	}
	if got := a.loginTarget("https://anysite.com/x"); !strings.HasPrefix(got, "/_wap/sso?next=") {
		t.Errorf("loginTarget = %q", got)
	}
}

func forwardApp(t testing.TB) *App {
	t.Helper()
	a := testApp(t)
	lu, _ := url.Parse("https://auth.com/_wap/login")
	a.cfg = &Config{Mode: "forward", LoginURL: lu, AllowedHosts: []string{"anysite.com", "other.org"},
		SessionTTL: time.Hour, UserHeader: "X-Authenticated-User"}
	return a
}

func verifyReq(a *App, host, uri, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/_wap/verify", nil)
	r.Header.Set("X-Forwarded-Host", host)
	r.Header.Set("X-Forwarded-Uri", uri)
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("Accept", "text/html")
	if cookie != "" {
		r.Header.Set("Cookie", cookieName+"="+cookie)
	}
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	return w
}

func TestForwardCrossDomainFlow(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)

	// 1. anonymous visitor of a listed site -> sent to the login host's sso endpoint
	w := verifyReq(a, "anysite.com", "/page?x=1", "")
	loc := w.Header().Get("Location")
	if w.Code != 302 || !strings.HasPrefix(loc, "https://auth.com/_wap/sso?next=") {
		t.Fatalf("anonymous: %d %s", w.Code, loc)
	}
	if next, _ := url.Parse(loc); next.Query().Get("next") != "https://anysite.com/page?x=1" {
		t.Fatalf("next = %q", next.Query().Get("next"))
	}

	// 2. a site that is not in the list is refused outright
	if w := verifyReq(a, "evil.com", "/", ""); w.Code != 403 {
		t.Fatalf("unlisted host: %d", w.Code)
	}

	// 3. signed in on the login host: sso hands the user over with a ticket for that host only
	loginCookie := a.sessions.New("remi", "", 0)
	r := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://anysite.com/page?x=1"), nil)
	r.Header.Set("Cookie", cookieName+"="+loginCookie)
	sw := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(sw, r)
	cb, _ := url.Parse(sw.Header().Get("Location"))
	if sw.Code != 302 || cb.Host != "anysite.com" || cb.Path != "/_wap/callback" || cb.Query().Get("next") != "/page?x=1" {
		t.Fatalf("sso: %d %s", sw.Code, sw.Header().Get("Location"))
	}

	// 4. the callback (seen by Traefik as an ordinary request to the site) sets a host-bound cookie
	cw := verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, "")
	if cw.Code != 302 || cw.Header().Get("Location") != "https://anysite.com/page?x=1" {
		t.Fatalf("callback: %d %s", cw.Code, cw.Header().Get("Location"))
	}
	var siteCookie *http.Cookie
	for _, c := range cw.Result().Cookies() {
		if c.Name == cookieName {
			siteCookie = c
		}
	}
	if siteCookie == nil || siteCookie.Domain != "" || !siteCookie.HttpOnly || !siteCookie.Secure {
		t.Fatalf("cookie: %+v", siteCookie)
	}

	// 5. a ticket works once
	if w := verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, ""); w.Code != 403 {
		t.Fatalf("ticket replay: %d", w.Code)
	}
	// ...and only for the host it was issued for
	r2 := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://other.org/"), nil)
	r2.Header.Set("Cookie", cookieName+"="+loginCookie)
	w2 := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w2, r2)
	cb2, _ := url.Parse(w2.Header().Get("Location"))
	if w := verifyReq(a, "anysite.com", "/_wap/callback?ticket="+url.QueryEscape(cb2.Query().Get("ticket")), ""); w.Code != 403 {
		t.Fatalf("ticket for another host accepted: %d", w.Code)
	}

	// 6. the site cookie opens its own site only
	if w := verifyReq(a, "anysite.com", "/page", siteCookie.Value); w.Code != 200 || w.Header().Get("X-Authenticated-User") != "remi" {
		t.Fatalf("site cookie on its site: %d %v", w.Code, w.Header())
	}
	if w := verifyReq(a, "other.org", "/page", siteCookie.Value); w.Code != 302 {
		t.Fatalf("site cookie replayed on another site: %d", w.Code)
	}
	// the login-host cookie does not open a site outside COOKIE_DOMAIN
	if w := verifyReq(a, "anysite.com", "/page", loginCookie); w.Code != 302 {
		t.Fatalf("login cookie accepted on a site: %d", w.Code)
	}

	// 7. logout on the site clears its cookie
	lw := verifyReq(a, "anysite.com", "/_wap/logout", siteCookie.Value)
	if lw.Code != 302 || !strings.Contains(lw.Header().Get("Set-Cookie"), "Max-Age=0") && !strings.Contains(lw.Header().Get("Set-Cookie"), "Max-Age=-1") {
		t.Fatalf("logout: %d %v", lw.Code, lw.Header())
	}
}

func TestForwardNonBrowserGets401AndDeletedUserLosesAccess(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	r := httptest.NewRequest("GET", "/_wap/verify", nil)
	r.Header.Set("X-Forwarded-Host", "anysite.com")
	r.Header.Set("X-Forwarded-Uri", "/api")
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("non-browser anonymous: %d", w.Code)
	}
	site := a.sessions.New("remi", "anysite.com", 0)
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 200 {
		t.Fatalf("valid: %d", w.Code)
	}
	u := a.store.ByName("remi")
	_ = a.store.AddCredential(a.store.GetOrNew("other"), &webauthn.Credential{ID: []byte("c2")}) // keep one user
	_ = a.store.DeleteCredential(u.ID, []byte("c1"))
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 302 {
		t.Fatalf("deleted user still has access: %d", w.Code)
	}
}

func TestSharedCookieDomainStillWorks(t *testing.T) {
	a := forwardApp(t)
	a.cfg.CookieDomain = "example.com"
	addUser(t, a)
	shared := a.sessions.New("remi", "", 0)
	if w := verifyReq(a, "app.example.com", "/", shared); w.Code != 200 {
		t.Fatalf("shared cookie inside the cookie domain: %d", w.Code)
	}
	// sso skips the ticket exchange for a site inside the cookie domain
	r := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://app.example.com/x"), nil)
	r.Header.Set("Cookie", cookieName+"="+shared)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	if w.Header().Get("Location") != "https://app.example.com/x" {
		t.Fatalf("sso inside cookie domain: %s", w.Header().Get("Location"))
	}
}
