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
	"strconv"
	"strings"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

const prefix = "/_wap"

type enrollState struct {
	Session webauthn.SessionData
	User    *User
	Label   string
}

type App struct {
	cfg      *Config
	store    *Store
	wa       *webauthn.WebAuthn
	sessions *Sessions
	login    *Ceremonies[webauthn.SessionData]
	enroll   *Ceremonies[enrollState]

	audit       *Audit   // nil = audit log disabled
	ipLimit     *Limiter // login and enrollment requests per client address
	globalLimit *Limiter // login and enrollment requests in total

	invOnce sync.Once
	invites *Invites // one-time invitations to add a passkey (created through the admin socket)

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

// limited applies the per-client and global rate limits to a login or enrollment route (429 when exceeded).
func (a *App) limited(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := a.clientIP(r)
		scope := "client"
		ok, retry := a.ipLimit.Allow(rateKey(ip))
		if ok {
			if ok, retry = a.globalLimit.Allow(""); !ok {
				scope = "global"
			}
		}
		if !ok {
			secs := int(retry.Seconds()) + 1
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			a.auditReq(r, "rate_limited", "scope", scope)
			jsonErr(w, http.StatusTooManyRequests, "too many requests, retry in "+strconv.Itoa(secs)+" s")
			return
		}
		next(w, r)
	})
}

// ---------------------------------------------------------------- public (proxy)

func (a *App) publicHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+prefix+"/login", a.staticPage("login.html"))
	mux.HandleFunc("GET "+prefix+"/app.js", a.staticPage("app.js"))
	mux.HandleFunc("GET "+prefix+"/login.js", a.staticPage("login.js"))
	mux.HandleFunc("GET "+prefix+"/i18n.js", a.staticPage("i18n.js"))
	mux.Handle("POST "+prefix+"/login/begin", a.limited(a.loginBegin))
	mux.Handle("POST "+prefix+"/login/finish", a.limited(a.loginFinish))
	mux.HandleFunc("POST "+prefix+"/logout", a.logout)
	a.sessionsAPI(mux)
	a.inviteAPI(mux)
	mux.HandleFunc("GET "+prefix+"/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	if a.cfg.Mode == "forward" {
		mux.HandleFunc(prefix+"/verify", a.verify)
		mux.HandleFunc("GET "+prefix+"/sso", a.sso)
		mux.HandleFunc("GET /{$}", a.home)
	} else {
		mux.Handle("/", a.requireAuth(a.reverseProxy()))
	}
	return mux
}

// cookie builds the login host's session cookie (shared on COOKIE_DOMAIN when configured).
func (a *App) cookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: cookieName, Value: value, Path: "/", Domain: a.cfg.CookieDomain,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
		Secure: a.secureLogin(r),
	}
}

// hostCookie builds a host-only cookie for a protected site (issued through the ticket exchange).
func (a *App) hostCookie(r *http.Request, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name: cookieName, Value: value, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Secure: a.secureSite(r),
	}
}

func (a *App) ssoURL() string {
	return a.cfg.LoginURL.Scheme + "://" + a.cfg.LoginURL.Host + prefix + "/sso"
}

// verify is Traefik's forwardAuth endpoint: 2xx = allowed, otherwise the response is returned to the client.
// Traefik passes the original request in X-Forwarded-* headers, and the original cookies. Those headers are only
// believed when the caller is a declared proxy (TRUSTED_PROXIES): anyone else could forge the host, scheme and URI.
func (a *App) verify(w http.ResponseWriter, r *http.Request) {
	if !a.fromTrusted(r) {
		a.auditReq(r, "untrusted_proxy", "peer", r.RemoteAddr)
		http.Error(w, "caller is not a trusted proxy", http.StatusForbidden)
		return
	}
	host := strings.ToLower(r.Header.Get("X-Forwarded-Host"))
	if !a.cfg.HostAllowed(host) {
		a.auditReq(r, "host_denied", "site", host)
		http.Error(w, "host not allowed", http.StatusForbidden)
		return
	}
	proto := a.scheme(r)
	uri := r.Header.Get("X-Forwarded-Uri")
	if strings.HasPrefix(uri, prefix+"/") { // control paths only; ordinary requests skip URL parsing
		if p, err := url.Parse(uri); err == nil {
			switch p.Path {
			case prefix + "/callback": // the login host sent the user back with a ticket
				a.callback(w, r, host, p.Query())
				return
			case prefix + "/logout": // POST: sign this browser out (the login session and its sites); any other method: only forget this site's cookie
				if r.Header.Get("X-Forwarded-Method") == http.MethodPost {
					if se, ok := a.sessionFor(r); ok && (se.Aud == host || (se.Aud == "" && a.cfg.InCookieDomain(host))) {
						a.revoke(r, se, "site", host)
					}
				}
				http.SetCookie(w, a.hostCookie(r, "", -1))
				http.SetCookie(w, a.cookie(r, "", -1))
				http.Redirect(w, r, a.cfg.LoginURL.String(), http.StatusFound)
				return
			}
		}
	}
	// A cookie is valid for this site if it was issued for this very host, or if it is the shared
	// login-host cookie and the site lies within COOKIE_DOMAIN.
	if se, ok := a.sessionFor(r); ok && (se.Aud == host || (se.Aud == "" && a.cfg.InCookieDomain(host))) {
		w.Header().Set(a.cfg.UserHeader, se.User)
		w.WriteHeader(http.StatusOK)
		return
	}
	method := r.Header.Get("X-Forwarded-Method")
	if (method == "" || method == http.MethodGet) && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, a.ssoURL()+"?next="+url.QueryEscape(proto+"://"+host+uri), http.StatusFound)
		return
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

// callback exchanges a ticket for a host-only session cookie, then sends the user to the page they asked for.
func (a *App) callback(w http.ResponseWriter, r *http.Request, host string, q url.Values) {
	user, parent, why := a.sessions.ConsumeTicket(q.Get("ticket"), host)
	if why == "" && !a.store.Has(user) {
		why = "user no longer exists"
	}
	if why == "" && !a.sessions.Alive(parent) {
		why = "login session ended" // signed out between the ticket's issue and its use
	}
	if why != "" {
		a.auditReq(r, "ticket_rejected", "site", host, "reason", why)
		http.Error(w, "invalid or expired ticket", http.StatusForbidden)
		return
	}
	next := q.Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, `/\`) {
		next = "/"
	}
	proto := a.scheme(r)
	a.auditReq(r, "site_login", "user", user, "site", host)
	http.SetCookie(w, a.hostCookie(r, a.sessions.Create(user, host, parent, r.UserAgent(), a.bindIP(r)), int(a.cfg.SessionTTL.Seconds())))
	// Absolute URL: Traefik resolves a relative Location against the auth service's own address.
	http.Redirect(w, r, proto+"://"+host+next, http.StatusFound)
}

// sso runs on the login host: a signed-in user is handed over to the requested site (directly when the
// site shares the cookie domain, otherwise with a ticket); anyone else is sent to the login page first.
func (a *App) sso(w http.ResponseWriter, r *http.Request) {
	next := a.safeNext(r.URL.Query().Get("next"))
	if strings.HasPrefix(next, "/") {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	se, ok := a.sessionFor(r)
	if !ok || se.Aud != "" {
		http.Redirect(w, r, prefix+"/login?next="+url.QueryEscape(next), http.StatusFound)
		return
	}
	name := se.User
	u, _ := url.Parse(next) // safeNext guarantees a valid absolute URL
	if a.cfg.InCookieDomain(u.Host) {
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
	a.auditReq(r, "ticket_issued", "user", name, "site", strings.ToLower(u.Host))
	cb := u.Scheme + "://" + u.Host + prefix + "/callback?ticket=" + url.QueryEscape(a.sessions.NewTicket(name, strings.ToLower(u.Host), se.Handle())) +
		"&next=" + url.QueryEscape(u.RequestURI())
	http.Redirect(w, r, cb, http.StatusFound)
}

// home is the authentication host's landing page in forward mode.
func (a *App) home(w http.ResponseWriter, r *http.Request) {
	name, ok := a.currentUser(r)
	if !ok {
		http.Redirect(w, r, prefix+"/login", http.StatusFound)
		return
	}
	signedIn, signOut, signOutAll, mine := "Signed in as", "Sign out", "Sign out of all devices", "My sessions"
	if r.URL.Query().Get("lang") == "fr" {
		signedIn, signOut, signOutAll, mine = "Connecté en tant que", "Se déconnecter", "Se déconnecter de tous les appareils", "Mes sessions"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>Session</title><body style="font-family:system-ui;text-align:center;margin-top:20vh"><p>%s <b>%s</b></p><form method=post action="%s/logout"><button>%s</button></form><form method=post action="%s/logout?all=1"><button>%s</button></form><p><a href="%s/sessions">%s</a></p>`,
		signedIn, html.EscapeString(name), prefix, signOut, prefix, signOutAll, prefix, mine)
}

// safeNext only allows local paths and, in forward mode, absolute URLs of allowed hosts.
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
	if err != nil || a.cfg.Mode != "forward" || (u.Scheme != "http" && u.Scheme != "https") || !a.cfg.HostAllowed(u.Host) {
		return "/"
	}
	return next
}

// loginTarget is where the login page sends the browser once signed in: local paths as is, allowed
// sites through the sso endpoint (which hands the session over).
func (a *App) loginTarget(next string) string {
	n := a.safeNext(next)
	if strings.HasPrefix(n, "/") {
		return n
	}
	return prefix + "/sso?next=" + url.QueryEscape(n)
}

// sessionFor returns the session carried by the request's cookie: it must exist, be neither expired nor idle,
// match the binding (SESSION_BIND), and belong to a user that still exists.
func (a *App) sessionFor(r *http.Request) (Session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return Session{}, false
	}
	se, ok := a.sessions.Lookup(c.Value, r.UserAgent(), a.bindIP(r))
	if !ok || !a.store.Has(se.User) {
		return Session{}, false
	}
	return se, true
}

// bindIP is the client address used for SESSION_BIND=ip; it is only computed when that option is on.
func (a *App) bindIP(r *http.Request) string {
	if !a.sessions.bind.IP {
		return ""
	}
	return a.clientIP(r).String()
}

// currentUser returns the user of a login-host session (audience "").
func (a *App) currentUser(r *http.Request) (string, bool) {
	se, ok := a.sessionFor(r)
	return se.User, ok && se.Aud == ""
}

// revoke signs a browser out: the session, the login session it came from and the sites opened from it.
func (a *App) revoke(r *http.Request, se Session, via, site string) {
	n := a.sessions.RevokeTree(se)
	a.auditReq(r, "sign_out", "user", se.User, "scope", "this browser", "sessions", n, "via", via, "site", site)
}

// revokeAll signs a user out of every device.
func (a *App) revokeAll(r *http.Request, user, via string) {
	n := a.sessions.RevokeUser(user)
	a.auditReq(r, "sign_out", "user", user, "scope", "all sessions", "sessions", n, "via", via)
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		se, ok := a.sessionFor(r)
		if !ok || se.Aud != "" {
			if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
				http.Redirect(w, r, prefix+"/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		// The user name is passed in a header; any client-supplied value is overwritten.
		r.Header.Set(a.cfg.UserHeader, se.User)
		next.ServeHTTP(w, r)
	})
}

// forwardedHeaders are the headers describing the original request, which only a trusted proxy may set.
var forwardedHeaders = []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Port", "X-Forwarded-Server", "X-Real-Ip", "Forwarded"}

func (a *App) reverseProxy() http.Handler {
	rp := httputil.NewSingleHostReverseProxy(a.cfg.Upstream)
	director := rp.Director
	rp.Director = func(r *http.Request) {
		host, trusted, proto := r.Host, a.fromTrusted(r), a.scheme(r)
		director(r)
		if a.cfg.PreserveHost {
			r.Host = host
		} else {
			r.Host = a.cfg.Upstream.Host
		}
		if !trusted {
			// A client can send any X-Forwarded-*: drop them and describe the connection we actually saw.
			// (The reverse proxy then adds the peer address to an empty X-Forwarded-For.)
			for _, h := range forwardedHeaders {
				r.Header.Del(h)
			}
		}
		if r.Header.Get("X-Forwarded-Host") == "" {
			r.Header.Set("X-Forwarded-Host", host)
		}
		if r.Header.Get("X-Forwarded-Proto") == "" {
			r.Header.Set("X-Forwarded-Proto", proto)
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
		a.auditReq(r, "login_failure", "reason", "ceremony expired or unknown")
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
		a.auditReq(r, "login_failure", "reason", "passkey rejected")
		jsonErr(w, 401, "passkey rejected")
		return
	}
	u := user.(*User)
	_ = a.store.UpdateCredential(u.ID, cred)
	a.auditReq(r, "login_success", "user", u.Name, "credential", credTag(cred.ID))
	tok := a.sessions.Create(u.Name, "", "", r.UserAgent(), a.bindIP(r))
	if old, ok := a.sessionFor(r); ok && old.Aud == "" && old.User == u.Name {
		a.sessions.Replace(old, tok) // signing in again in the same browser supersedes the previous login session
	}
	http.SetCookie(w, a.cookie(r, tok, int(a.cfg.SessionTTL.Seconds())))
	writeJSON(w, 200, map[string]string{"next": a.loginTarget(r.URL.Query().Get("next"))})
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
	mux.Handle("POST "+prefix+"/login/begin", a.limited(a.loginBegin))
	mux.Handle("POST "+prefix+"/login/finish", a.limited(a.loginFinish))
	mux.HandleFunc("POST "+prefix+"/logout", a.logout)
	// Page and API (protected).
	mux.HandleFunc("GET "+prefix+"/enroll.js", a.staticPage("enroll.js"))
	mux.Handle("GET /{$}", a.enrollGuard(a.staticPage("enroll.html")))
	mux.Handle("GET /api/state", a.enrollGuard(http.HandlerFunc(a.apiState)))
	mux.Handle("GET /api/users", a.enrollGuard(http.HandlerFunc(a.apiUsers)))
	mux.Handle("POST /api/register/begin", a.limited(a.enrollGuard(http.HandlerFunc(a.registerBegin)).ServeHTTP))
	mux.Handle("POST /api/register/finish", a.limited(a.enrollGuard(http.HandlerFunc(a.registerFinish)).ServeHTTP))
	mux.Handle("DELETE /api/credentials", a.limited(a.enrollGuard(http.HandlerFunc(a.deleteCredential)).ServeHTTP))
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
				a.auditReq(r, "enroll_failure", "reason", "invalid bootstrap token")
				http.Error(w, "invalid bootstrap token (see the container logs)", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// logout signs the user out everywhere: the cookie is cleared and every session and ticket issued so far
// (other devices, other protected sites, a copied cookie) is revoked.
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if se, ok := a.sessionFor(r); ok && se.Aud == "" {
		if r.URL.Query().Get("all") == "1" || r.FormValue("all") == "1" {
			a.revokeAll(r, se.User, "login host")
		} else {
			a.revoke(r, se, "login host", "")
		}
	}
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

// credTag is a short, non-secret identifier of a credential for logs and the admin tools.
func credTag(id []byte) string {
	s := b64s(id)
	if len(s) > 12 {
		s = s[:12]
	}
	return s
}

func (a *App) apiUsers(w http.ResponseWriter, r *http.Request) {
	type cred struct {
		ID      string `json:"id"`
		Label   string `json:"label,omitempty"`
		Created int64  `json:"created,omitempty"`
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
			m := u.Meta[b64s(c.ID)]
			x.Creds = append(x.Creds, cred{ID: b64s(c.ID), Label: m.Label, Created: m.Created})
		}
		out = append(out, x)
	}
	writeJSON(w, 200, out)
}

func (a *App) registerBegin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name  string `json:"name"`
		Label string `json:"label"`
	}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 64 {
		jsonErr(w, 400, "invalid name (1 to 64 characters)")
		return
	}
	label, err := CleanLabel(in.Label)
	if err != nil {
		jsonErr(w, 400, err.Error())
		return
	}
	user := a.store.GetOrNew(name)
	opts, sd, err := a.wa.BeginRegistration(user, webauthn.WithExclusions(excludeList(user)))
	if err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"cid": a.enroll.Put(enrollState{*sd, user, label}), "options": opts})
}

func (a *App) registerFinish(w http.ResponseWriter, r *http.Request) {
	st, ok := a.enroll.Take(r.URL.Query().Get("cid"))
	if !ok {
		jsonErr(w, 400, "ceremony expired, please start again")
		return
	}
	cred, err := a.wa.FinishRegistration(st.User, st.Session, r)
	if err != nil {
		a.auditReq(r, "enroll_failure", "user", st.User.Name, "reason", "registration refused")
		jsonErr(w, 400, "enrollment refused: "+err.Error())
		return
	}
	if err := a.store.AddCredentialLabeled(st.User, cred, st.Label); err != nil {
		if errors.Is(err, ErrDuplicate) {
			a.auditReq(r, "enroll_failure", "user", st.User.Name, "reason", "duplicate credential")
			jsonErr(w, 409, err.Error())
			return
		}
		jsonErr(w, 500, "cannot write: "+err.Error())
		return
	}
	a.auditReq(r, "enroll_success", "user", st.User.Name, "credential", credTag(cred.ID), "via", "web")
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
	who := ""
	if u := a.store.ByID(uid); u != nil {
		who = u.Name
	}
	if err := a.store.DeleteCredential(uid, cid); err != nil {
		jsonErr(w, 500, err.Error())
		return
	}
	if who != "" && !a.store.Has(who) { // its last passkey is gone: end the user's sessions
		a.sessions.RevokeUser(who)
	}
	a.auditReq(r, "credential_deleted", "user", who, "credential", credTag(cid), "via", "web")
	writeJSON(w, 200, map[string]string{"ok": "true"})
}
