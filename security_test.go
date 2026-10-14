package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func postLogout(a *App, cookie string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/_wap/logout", nil)
	r.Header.Set("Cookie", cookieName+"="+cookie)
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	return w
}

func TestLogoutRevokesEverySession(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	login := a.sessions.New("remi", "", 0)
	site := a.sessions.New("remi", "anysite.com", 0) // a site cookie issued earlier, e.g. on another device
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 200 {
		t.Fatalf("before logout: %d", w.Code)
	}

	if w := postLogout(a, login); w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	// both the login cookie and the previously issued site cookie are dead, even though neither expired
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 302 {
		t.Fatalf("copied site cookie still valid after logout: %d", w.Code)
	}
	if _, ok := a.currentUser(requestWithCookie(login)); ok {
		t.Fatal("login cookie still valid after logout")
	}
	// signing in again yields a working session under the new generation
	gen, _ := a.store.Gen("remi")
	if gen != 1 {
		t.Fatalf("generation = %d, want 1", gen)
	}
	if w := verifyReq(a, "anysite.com", "/", a.sessions.New("remi", "anysite.com", gen)); w.Code != 200 {
		t.Fatalf("fresh session: %d", w.Code)
	}
}

func TestRevocationSurvivesRestart(t *testing.T) {
	a := testApp(t)
	addUser(t, a)
	if err := a.store.Revoke("remi"); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenStore(a.store.dir())
	if err != nil {
		t.Fatal(err)
	}
	if gen, ok := reopened.Gen("remi"); !ok || gen != 1 {
		t.Fatalf("generation after reload = %d (%v), want 1", gen, ok)
	}
}

func TestSiteLogoutRevokesOnlyOnPost(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	site := a.sessions.New("remi", "anysite.com", 0)

	get := func(method string) int {
		r := httptest.NewRequest("GET", "/_wap/verify", nil)
		r.Header.Set("X-Forwarded-Host", "anysite.com")
		r.Header.Set("X-Forwarded-Uri", "/_wap/logout")
		r.Header.Set("X-Forwarded-Method", method)
		r.Header.Set("Cookie", cookieName+"="+site)
		w := httptest.NewRecorder()
		a.publicHandler().ServeHTTP(w, r)
		return w.Code
	}
	if c := get("GET"); c != 302 {
		t.Fatalf("GET logout: %d", c)
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code != 200 {
		t.Fatal("a GET (CSRF-able) must not sign the user out everywhere")
	}
	if c := get("POST"); c != 302 {
		t.Fatalf("POST logout: %d", c)
	}
	if w := verifyReq(a, "anysite.com", "/", site); w.Code == 200 {
		t.Fatal("POST logout did not revoke the session")
	}
}

func TestTicketIssuedBeforeLogoutIsRefused(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	ticket := a.sessions.NewTicket("remi", "anysite.com", 0)
	if err := a.store.Revoke("remi"); err != nil {
		t.Fatal(err)
	}
	if w := verifyReq(a, "anysite.com", "/_wap/callback?ticket="+url.QueryEscape(ticket), ""); w.Code != 403 {
		t.Fatalf("stale ticket accepted: %d", w.Code)
	}
}

func TestTokenTamperingIsDetected(t *testing.T) {
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), nil, time.Hour, 0)
	tok := s.New("remi", "", 0)
	parts := strings.Split(tok, ".")
	forged := append([]string{b64.EncodeToString([]byte("admin"))}, parts[1:]...) // other user, same signature
	if _, _, _, err := s.Verify(strings.Join(forged, ".")); err == nil {
		t.Fatal("forged user accepted")
	}
	parts[3] = "9" // other generation, same signature
	if _, _, _, err := s.Verify(strings.Join(parts, ".")); err == nil {
		t.Fatal("forged generation accepted")
	}
}

func TestSessionSecretMinimumLength(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	t.Setenv("SESSION_SECRET", "too-short-secret")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("short SESSION_SECRET accepted")
	}
	t.Setenv("SESSION_SECRET", strings.Repeat("x", 32))
	if _, err := LoadConfig(); err != nil {
		t.Fatalf("32-character secret refused: %v", err)
	}
}
