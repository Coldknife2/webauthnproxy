package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func postLogout(a *App, cookie string, query ...string) *httptest.ResponseRecorder {
	target := "/_wap/logout"
	if len(query) > 0 {
		target += "?" + query[0]
	}
	r := httptest.NewRequest("POST", target, nil)
	r.Header.Set("Cookie", cookieName+"="+cookie)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	return w
}

// login opens a login-host session and, through the ticket exchange, a session on anysite.com. It returns both cookies.
func loginAndSite(t *testing.T, a *App) (login, site string) {
	t.Helper()
	login = mk(a, "remi", "")
	r := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://anysite.com/p"), nil)
	r.Header.Set("Cookie", cookieName+"="+login)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	cb, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != 302 {
		t.Fatalf("sso: %d %s", w.Code, w.Header().Get("Location"))
	}
	cw := verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, "")
	for _, c := range cw.Result().Cookies() {
		if c.Name == cookieName {
			site = c.Value
		}
	}
	if site == "" {
		t.Fatalf("callback set no cookie: %d", cw.Code)
	}
	return login, site
}

func TestLogoutEndsThisBrowserOnly(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	login, site := loginAndSite(t, a)
	otherDevice := mk(a, "remi", "")
	otherSite := mk(a, "remi", "anysite.com")
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 200 {
		t.Fatalf("before logout: %d", w.Code)
	}

	if w := postLogout(a, login); w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 302 {
		t.Fatalf("the site session opened from this login survived the logout: %d", w.Code)
	}
	if _, ok := a.currentUser(requestWithCookie(login)); ok {
		t.Fatal("login cookie still valid after logout")
	}
	// another device is not signed out by a logout elsewhere
	if _, ok := a.currentUser(requestWithCookie(otherDevice)); !ok {
		t.Fatal("logout signed out another device")
	}
	if w := verifyReq(a, "anysite.com", "/", otherSite); w.Code != 200 {
		t.Fatalf("another device's site session was revoked: %d", w.Code)
	}
}

func TestLogoutOfAllDevices(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	login, site := loginAndSite(t, a)
	otherDevice := mk(a, "remi", "")
	_ = a.store.AddCredential(a.store.GetOrNew("ana"), &webauthn.Credential{ID: []byte("ana-c")})
	other := mk(a, "ana", "")
	if w := postLogout(a, login, "all=1"); w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	for name, c := range map[string]string{"login": login, "device 2": otherDevice} {
		if _, ok := a.currentUser(requestWithCookie(c)); ok {
			t.Errorf("%s still signed in", name)
		}
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code == 200 {
		t.Error("site session survived the sign-out of all devices")
	}
	if _, ok := a.sessions.Lookup(other, "", ""); !ok {
		t.Error("another user was signed out")
	}
}

func TestSiteLogoutRevokesOnlyOnPost(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	login, site := loginAndSite(t, a)

	call := func(method string) int {
		r := httptest.NewRequest("GET", "/_wap/verify", nil)
		r.Header.Set("X-Forwarded-Host", "anysite.com")
		r.Header.Set("X-Forwarded-Uri", "/_wap/logout")
		r.Header.Set("X-Forwarded-Method", method)
		r.Header.Set("Cookie", cookieName+"="+site)
		w := httptest.NewRecorder()
		a.publicHandler().ServeHTTP(w, r)
		return w.Code
	}
	if c := call("GET"); c != 302 {
		t.Fatalf("GET logout: %d", c)
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 200 {
		t.Fatal("a GET (CSRF-able) must not sign the user out")
	}
	if c := call("POST"); c != 302 {
		t.Fatalf("POST logout: %d", c)
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code == 200 {
		t.Fatal("POST logout did not revoke the session")
	}
	if _, ok := a.currentUser(requestWithCookie(login)); ok {
		t.Fatal("signing out of a site left the login session open")
	}
}

func TestTicketIssuedBeforeLogoutIsRefused(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	login := mk(a, "remi", "")
	r := httptest.NewRequest("GET", "/_wap/sso?next="+url.QueryEscape("https://anysite.com/p"), nil)
	r.Header.Set("Cookie", cookieName+"="+login)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	cb, _ := url.Parse(w.Header().Get("Location"))
	postLogout(a, login, "all=1") // the user signs out before the browser reaches the site
	if w := verifyReq(a, "anysite.com", "/_wap/callback?"+cb.RawQuery, ""); w.Code != 403 {
		t.Fatalf("a ticket from a session that has ended was accepted: %d", w.Code)
	}
}

func TestDeletedUserLosesTheirSessions(t *testing.T) {
	a := testApp(t)
	cookie := addUser(t, a)
	if _, ok := a.sessionFor(requestWithCookie(cookie)); !ok {
		t.Fatal("setup")
	}
	if err := a.store.DeleteCredential(a.store.ByName("remi").ID, []byte("c1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.sessionFor(requestWithCookie(cookie)); ok {
		t.Fatal("a session of a user that no longer exists is still accepted")
	}
}

func TestForgedAndModifiedCookiesAreRefused(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	good := mk(a, "remi", "anysite.com")
	for name, c := range map[string]string{
		"a user name":         "remi",
		"a guessed value":     strings.Repeat("A", 43),
		"modified last char":  good[:len(good)-1] + "B",
		"modified first char": "B" + good[1:],
		"old signed format":   "cmVtaQ.YW55c2l0ZS5jb20.2000000000.0.2000000000.c2ln",
		"another site's":      mk(a, "remi", "other.org"),
	} {
		if c == good {
			continue
		}
		if w := verifyReq(a, "anysite.com", "/", c); w.Code == 200 {
			t.Errorf("%s accepted", name)
		}
	}
	if w := verifyReq(a, "anysite.com", "/", good); w.Code != 200 {
		t.Fatalf("the genuine cookie was refused: %d", w.Code)
	}
}

func TestSessionSecretIsIgnoredNotRequired(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	t.Setenv("SESSION_SECRET", "too-short-secret")
	t.Setenv("SESSION_SECRET_PREVIOUS", "x")
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("a leftover SESSION_SECRET stops the start: %v", err)
	}
}

func TestSessionBindConfig(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	t.Setenv("SESSION_BIND", "ua, ip")
	if c, err := LoadConfig(); err != nil || !c.SessionBind.UA || !c.SessionBind.IP {
		t.Fatalf("ua,ip: %v %+v", err, c)
	}
	t.Setenv("SESSION_BIND", "device")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("unknown binding accepted")
	}
}
