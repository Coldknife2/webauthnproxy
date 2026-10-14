package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func testApp(t *testing.T) *App {
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
	// base vide : lecture libre, écriture seulement avec le jeton d'amorçage
	if w := do(h, "GET", "/api/users", nil); w.Code != 200 {
		t.Fatalf("lecture en amorçage: %d", w.Code)
	}
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap"}); w.Code != 403 {
		t.Fatalf("sans jeton: %d", w.Code)
	}
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": "faux"}); w.Code != 403 {
		t.Fatalf("mauvais jeton: %d", w.Code)
	}
	ok := map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": a.bootstrapToken()}
	if w := do(h, "POST", "/api/register/begin", ok); w.Code == 403 {
		t.Fatalf("bon jeton refusé")
	}
}

func addUser(t *testing.T, a *App) string {
	t.Helper()
	u := a.store.GetOrNew("remi")
	if err := a.store.AddCredential(u, &webauthn.Credential{ID: []byte("c1")}); err != nil {
		t.Fatal(err)
	}
	return a.sessions.New("remi")
}

func TestEnrollRequiresSessionOnceUsersExist(t *testing.T) {
	a := testApp(t)
	tok := addUser(t, a)
	h := a.enrollHandler()

	// le jeton d'amorçage ne fonctionne plus
	if w := do(h, "POST", "/api/register/begin", map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": a.bootstrapToken()}); w.Code != 401 {
		t.Fatalf("amorçage encore actif: %d", w.Code)
	}
	if w := do(h, "GET", "/api/users", nil); w.Code != 401 {
		t.Fatalf("API sans session: %d", w.Code)
	}
	w := do(h, "GET", "/", map[string]string{"Accept": "text/html"})
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "/_wap/login") {
		t.Fatalf("page sans session: %d %s", w.Code, w.Header().Get("Location"))
	}
	// avec session
	cookie := map[string]string{"Cookie": cookieName + "=" + tok}
	if w := do(h, "GET", "/api/users", cookie); w.Code != 200 {
		t.Fatalf("API avec session: %d", w.Code)
	}
	// CSRF : une écriture sans l'en-tête custom est refusée même avec session
	if w := do(h, "POST", "/api/register/begin", cookie); w.Code != 403 {
		t.Fatalf("CSRF: %d", w.Code)
	}
	// la dernière passkey ne peut pas être supprimée
	cookie["X-Requested-With"] = "wap"
	u := a.store.ByName("remi")
	del := "/api/credentials?user=" + b64s(u.ID) + "&id=" + b64s([]byte("c1"))
	if w := do(h, "DELETE", del, cookie); w.Code != 409 {
		t.Fatalf("suppression de la dernière passkey: %d", w.Code)
	}
}

func TestToolServedWithStrictCSP(t *testing.T) {
	a := testApp(t)
	a.cfg.RPID = "example.com"
	h := a.toolHandler()
	if w := do(h, "GET", "/", nil); w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "rpid=example.com") {
		t.Fatalf("redirection rpid: %d %s", w.Code, w.Header().Get("Location"))
	}
	w := do(h, "GET", "/?rpid=example.com", nil)
	csp := w.Header().Get("Content-Security-Policy")
	if w.Code != 200 || !strings.Contains(csp, "script-src 'sha256-") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP inattendue: %d %q", w.Code, csp)
	}
	if w := do(h, "POST", "/", nil); w.Code == 200 {
		t.Fatal("l'outil ne doit accepter aucune écriture")
	}
}
