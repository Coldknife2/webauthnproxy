package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io/fs"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

const prefix = "/_wap"

type enrollState struct {
	Session webauthn.SessionData
	User    *User
}

type App struct {
	cfg      *Config
	store    *Store
	wa       *webauthn.WebAuthn
	sessions *Sessions
	login    *Ceremonies[webauthn.SessionData]
	enroll   *Ceremonies[enrollState]

	bootMu sync.Mutex
	boot   string // enrollment bootstrap token (empty database)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (a *App) staticPage(name string) http.HandlerFunc {
	sub, _ := fs.Sub(webFS, "web")
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'")
		http.ServeFileFS(w, r, sub, name)
	}
}

func isSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// ---------------------------------------------------------------- public (proxy)

func (a *App) publicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+prefix+"/login", a.staticPage("login.html"))
	mux.HandleFunc("GET "+prefix+"/app.js", a.staticPage("app.js"))
	mux.HandleFunc("GET "+prefix+"/login.js", a.staticPage("login.js"))
	mux.HandleFunc("GET "+prefix+"/i18n.js", a.staticPage("i18n.js"))
	mux.HandleFunc("POST "+prefix+"/login/begin", a.loginBegin)
	mux.HandleFunc("POST "+prefix+"/login/finish", a.loginFinish)
	mux.HandleFunc("POST "+prefix+"/logout", a.logout)
	if a.cfg.Mode == "forward" {
		mux.HandleFunc(prefix+"/verify", a.verify)
		mux.HandleFunc("GET /{$}", a.home)
	} else {
		mux.Handle("/", a.requireAuth(a.reverseProxy()))
	}
	return mux
}

func (a *App) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: cookieName, Value: value, Path: "/", Domain: a.cfg.CookieDomain,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
		Secure: isSecure(r) || (a.cfg.LoginURL != nil && a.cfg.LoginURL.Scheme == "https"),
	}
}

// verify is Traefik's forwardAuth endpoint: 2xx = allowed, otherwise the response is returned to the client.
func (a *App) verify(w http.ResponseWriter, r *http.Request) {
	name, ok := a.currentUser(r)
	if ok {
		w.Header().Set(a.cfg.UserHeader, name)
		w.WriteHeader(http.StatusOK)
		return
	}
	method := r.Header.Get("X-Forwarded-Method")
	if (method == "" || method == http.MethodGet) && strings.Contains(r.Header.Get("Accept"), "text/html") {
		orig := r.Header.Get("X-Forwarded-Proto") + "://" + r.Header.Get("X-Forwarded-Host") + r.Header.Get("X-Forwarded-Uri")
		http.Redirect(w, r, a.cfg.LoginURL.String()+"?next="+url.QueryEscape(orig), http.StatusFound)
		return
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// home is the authentication host's landing page in forward mode.
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	name, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, prefix+"/login", http.StatusFound)
		return
	}
	signedIn, signOut := "Signed in as", "Sign out"
	if r.URL.Query().Get("lang") == "fr" {
		signedIn, signOut = "Connecté en tant que", "Se déconnecter"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>Session</title><body style="font-family:system-ui;text-align:center;margin-top:20vh"><p>%s <b>%s</b></p><form method=post action="%s/logout"><button>%s</button></form>`,
		signedIn, html.EscapeString(name), prefix, signOut)
}

// safeNext only allows local paths and, in forward mode, URLs within the cookie domain.
func (a *App) safeNext(next string) string {
	if next == "" {
		return "/"
	}
	if strings.HasPrefix(next, "/") {
		if strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
			return "/"
		}
		return next
	}
	u, err := url.Parse(next)
	if err != nil || a.cfg.Mode != "forward" || (u.Scheme != "http" && u.Scheme != "https") {
		return "/"
	}
	h := strings.ToLower(u.Hostname())
	if h == a.cfg.CookieDomain || strings.HasSuffix(h, "."+a.cfg.CookieDomain) {
		return next
	}
	return "/"
}

func (a *App) currentUser(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	name, err := a.sessions.Verify(c.Value)
	if err != nil || a.store.ByName(name) == nil { // deleted user => invalid session
		return "", false
	}
	return name, true
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name, ok := a.currentUser(r)
		if !ok {
			if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, prefix+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// The user name is passed in a header; any client-supplied value is overwritten.
		r.Header.Set(a.cfg.UserHeader, name)
		next.ServeHTTP(w, r)
	})
}

func (a *App) reverseProxy() http.Handler {
	rp := httputil.NewSingleHostReverseProxy(a.cfg.Upstream)
	director := rp.Director
	rp.Director = func(r *http.Request) {
		host := r.Host
		director(r)
		if a.cfg.PreserveHost {
			r.Host = host
		} else {
			r.Host = a.cfg.Upstream.Host
		}
		r.Header.Set("X-Forwarded-Host", host)
		if r.Header.Get("X-Forwarded-Proto") == "" {
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}
		// The session cookie must not leak to the upstream.
		cookies := r.Cookies()
		r.Header.Del("Cookie")
		for _, c := range cookies {
			if c.Name != cookieName {
				r.AddCookie(c)
			}
		}
	}
	return rp
}

func (a *App) loginBegin(w http.ResponseWriter, r *http.Request) {
	opts, sd, err := a.wa.BeginDiscoverableLogin()
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cid": a.login.Put(*sd), "options": opts})
}

func (a *App) loginFinish(w http.ResponseWriter, r *http.Request) {
	sd, ok := a.login.Take(r.URL.Query().Get("cid"))
	if !ok {
		jsonErr(w, 400, "ceremony expired, please start again")
		return
	}
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		if u := a.store.ByID(userHandle); u != nil {
			return u, nil
		}
		return nil, errors.New("unknown user")
	}
	user, cred, err := a.wa.FinishPasskeyLogin(handler, sd, r)
	if err != nil {
		jsonErr(w, 401, "passkey rejected")
		return
	}
	u := user.(*User)
	_ = a.store.UpdateCredential(u.ID, cred)
	http.SetCookie(w, a.cookie(r, a.sessions.New(u.Name), int(a.cfg.SessionTTL.Seconds())))
	writeJSON(w, 200, map[string]string{"next": a.safeNext(r.URL.Query().Get("next"))})
}

// ---------------------------------------------------------------- automatic enrollment

// enrollHandler serves automatic enrollment. It is protected by the existing passkeys
// (session obtained through this same port's login page). While no passkey exists, a
// bootstrap token printed in the logs at startup authorizes creating the first one.
func (a *App) enrollHandler() http.Handler {
	mux := http.NewServeMux()
	// Login (open): same endpoints as the public proxy.
	mux.HandleFunc("GET "+prefix+"/login", a.staticPage("login.html"))
	mux.HandleFunc("GET "+prefix+"/app.js", a.staticPage("app.js"))
	mux.HandleFunc("GET "+prefix+"/login.js", a.staticPage("login.js"))
	mux.HandleFunc("GET "+prefix+"/i18n.js", a.staticPage("i18n.js"))
	mux.HandleFunc("POST "+prefix+"/login/begin", a.loginBegin)
	mux.HandleFunc("POST "+prefix+"/login/finish", a.loginFinish)
	mux.HandleFunc("POST "+prefix+"/logout", a.logout)
	// Page and API (protected).
	mux.HandleFunc("GET "+prefix+"/enroll.js", a.staticPage("enroll.js"))
	mux.Handle("GET /{$}", a.enrollGuard(a.staticPage("enroll.html")))
	mux.Handle("GET /api/state", a.enrollGuard(http.HandlerFunc(a.apiState)))
	mux.Handle("GET /api/users", a.enrollGuard(http.HandlerFunc(a.apiUsers)))
	mux.Handle("POST /api/register/begin", a.enrollGuard(http.HandlerFunc(a.registerBegin)))
	mux.Handle("POST /api/register/finish", a.enrollGuard(http.HandlerFunc(a.registerFinish)))
	mux.Handle("DELETE /api/credentials", a.enrollGuard(http.HandlerFunc(a.deleteCredential)))
	return mux
}

// bootstrapToken returns the bootstrap token (created and logged on demand) while the database is empty.
func (a *App) bootstrapToken() string {
	a.bootMu.Lock()
	defer a.bootMu.Unlock()
	if a.boot == "" {
		b := make([]byte, 18)
		_, _ = rand.Read(b)
		a.boot = b64.EncodeToString(b)
		log.Printf("No passkey registered. Enrollment bootstrap token: %s", a.boot)
	}
	return a.boot
}

func (a *App) enrollGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, authed := a.currentUser(r)
		bootstrap := !authed && a.store.CredentialCount() == 0
		if !authed && !bootstrap {
			if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, prefix+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			// Anti-CSRF: a custom header forces a CORS preflight, which we never answer.
			if r.Header.Get("X-Requested-With") != "wap" {
				http.Error(w, "request refused", http.StatusForbidden)
				return
			}
			if bootstrap && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Bootstrap-Token")), []byte(a.bootstrapToken())) != 1 {
				http.Error(w, "invalid bootstrap token (see the container logs)", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, a.cookie(r, "", -1))
	http.Redirect(w, r, prefix+"/login", http.StatusSeeOther)
}

func (a *App) apiState(w http.ResponseWriter, r *http.Request) {
	name, authed := a.currentUser(r)
	boot := !authed && a.store.CredentialCount() == 0
	if boot {
		a.bootstrapToken() // make sure the token is printed in the logs
	}
	writeJSON(w, 200, map[string]any{"bootstrap": boot, "user": name})
}

// ---------------------------------------------------------------- outil statique

// toolHandler serves web/tool.html only (no API, no state, no writes): it can be exposed
// publicly, since creating a passkey grants no access until the produced JSON file has been
// imported by hand into DATA_DIR/import.
func (a *App) toolHandler() http.Handler {
	page, _ := fs.ReadFile(webFS, "web/tool.html")
	csp := toolCSP(page)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("rpid") == "" {
			http.Redirect(w, r, "/?rpid="+url.QueryEscape(a.cfg.RPID), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_, _ = w.Write(page)
	})
	return mux
}

var inlineRe = regexp.MustCompile(`(?s)<(script|style)>(.*?)</(?:script|style)>`)

// toolCSP only allows the page's own inline script and style, by hash.
func toolCSP(page []byte) string {
	src := map[string]string{"script": "", "style": ""}
	for _, m := range inlineRe.FindAllSubmatch(page, -1) {
		h := sha256.Sum256(m[2])
		src[string(m[1])] += " 'sha256-" + base64.StdEncoding.EncodeToString(h[:]) + "'"
	}
	return "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src" +
		src["script"] + "; style-src" + src["style"]
}

func b64s(b []byte) string { return b64.EncodeToString(b) }

func (a *App) apiUsers(w http.ResponseWriter, r *http.Request) {
	type cred struct {
		ID string `json:"id"`
	}
	type user struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		Creds []cred `json:"credentials"`
	}
	out := []user{}
	for _, u := range a.store.List() {
		x := user{ID: b64s(u.ID), Name: u.Name, Creds: []cred{}}
		for _, c := range u.Credentials {
			x.Creds = append(x.Creds, cred{ID: b64s(c.ID)})
		}
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}

func (a *App) registerBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		jsonErr(w, 400, "invalid name (1 to 64 characters)")
		return
	}
	user := a.store.GetOrNew(name)
	opts, sd, err := a.wa.BeginRegistration(user, webauthn.WithExclusions(excludeList(user)))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cid": a.enroll.Put(enrollState{*sd, user}), "options": opts})
}

func (a *App) registerFinish(w http.ResponseWriter, r *http.Request) {
	st, ok := a.enroll.Take(r.URL.Query().Get("cid"))
	if !ok {
		jsonErr(w, 400, "ceremony expired, please start again")
		return
	}
	cred, err := a.wa.FinishRegistration(st.User, st.Session, r)
	if err != nil {
		jsonErr(w, 400, "enrollment refused: "+err.Error())
		return
	}
	if err := a.store.AddCredential(st.User, cred); err != nil {
		if errors.Is(err, ErrDuplicate) {
			jsonErr(w, 409, err.Error())
			return
		}
		jsonErr(w, 500, "cannot write: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}

func (a *App) deleteCredential(w http.ResponseWriter, r *http.Request) {
	uid, err1 := b64.DecodeString(r.URL.Query().Get("user"))
	cid, err2 := b64.DecodeString(r.URL.Query().Get("id"))
	if err1 != nil || err2 != nil {
		jsonErr(w, 400, "invalid parameters")
		return
	}
	if a.store.CredentialCount() <= 1 {
		jsonErr(w, 409, "cannot delete the last passkey (this would lock you out)")
		return
	}
	if err := a.store.DeleteCredential(uid, cid); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]string{"ok": "true"})
}
