package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testApp(t testing.TB) *App {
	t.Helper()
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &App{
		cfg:      &Config{Mode: "proxy", SessionTTL: time.Hour},
		store:    store,
		sessions: &Sessions{secret: []byte("0123456789abcdef"), ttl: time.Hour},
		login:    NewCeremonies[webauthn.SessionData](),
		enroll:   NewCeremonies[enrollState](),
	}
}

func do(h http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader("{}"))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestEnrollBootstrap(t *testing.T) {
	a := testApp(t)
	h := a.enrollHandler()
	// empty database: reads are open, writes need the bootstrap token
	if w := do(h, "GET", "/api/users", nil); w.Code != 200 {
		t.Fatalf("read during bootstrap: %d", w.Code)
	}
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap"}); w.Code != 403 {
		t.Fatalf("without token: %d", w.Code)
	}
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": "faux"}); w.Code != 403 {
		t.Fatalf("wrong token: %d", w.Code)
	}
	ok := map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": a.bootstrapToken()}
	if w := do(h, "POST", "/api/register/begin", ok); w.Code == 403 {
		t.Fatalf("valid token refused")
	}
}

func addUser(t testing.TB, a *App) string {
	t.Helper()
	u := a.store.GetOrNew("remi")
	if err := a.store.AddCredential(u, &webauthn.Credential{ID: []byte("c1")}); err != nil {
		t.Fatal(err)
	}
	return a.sessions.New("remi", "")
}

func TestEnrollRequiresSessionOnceUsersExist(t *testing.T) {
	a := testApp(t)
	tok := addUser(t, a)
	h := a.enrollHandler()

	// the bootstrap token no longer works
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": a.bootstrapToken()}); w.Code != 401 {
		t.Fatalf("bootstrap still active: %d", w.Code)
	}
	if w := do(h, "GET", "/api/users", nil); w.Code != 401 {
		t.Fatalf("API without session: %d", w.Code)
	}
	w := do(h, "GET", "/", map[string]string{"Accept": "text/html"})
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/_wap/login") {
		t.Fatalf("page without session: %d %s", w.Code, w.Header().Get("Location"))
	}
	// with a session
	cookie := map[string]string{"Cookie": cookieName + "=" + tok}
	if w := do(h, "GET", "/api/users", cookie); w.Code != 200 {
		t.Fatalf("API with session: %d", w.Code)
	}
	// CSRF: a write without the custom header is refused even with a session
	if w := do(h, "POST", "/api/register/begin", cookie); w.Code != 403 {
		t.Fatalf("CSRF: %d", w.Code)
	}
	// the last passkey cannot be deleted
	cookie["X-Requested-With"] = "wap"
	u := a.store.ByName("remi")
	del := "/api/credentials?user=" + b64s(u.ID) + "&id=" + b64s([]byte("c1"))
	if w := do(h, "DELETE", del, cookie); w.Code != 409 {
		t.Fatalf("deleting the last passkey: %d", w.Code)
	}
}

func TestToolServedWithStrictCSP(t *testing.T) {
	a := testApp(t)
	a.cfg.RPID = "example.com"
	h := a.toolHandler()
	if w := do(h, "GET", "/", nil); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "rpid=example.com") {
		t.Fatalf("rpid redirect: %d %s", w.Code, w.Header().Get("Location"))
	}
	w := do(h, "GET", "/?rpid=example.com", nil)
	csp := w.Header().Get("Content-Security-Policy")
	if w.Code != 200 || !strings.Contains(csp, "script-src 'sha256-") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("unexpected CSP: %d %q", w.Code, csp)
	}
	if w := do(h, "POST", "/", nil); w.Code == 200 {
		t.Fatal("the tool must not accept any write")
	}
}
