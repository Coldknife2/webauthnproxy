package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// ---------------------------------------------------------------- "my sessions" page

// mySessions serves the page and API where a signed-in user sees their own sessions and ends some of them.
// A user can only see and end their own sessions.
func (a *App) sessionsAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET "+prefix+"/sessions.js", a.staticPage("sessions.js"))
	mux.HandleFunc("GET "+prefix+"/sessions", func(w http.ResponseWriter, r *http.Request) {
		if se, ok := a.sessionFor(r); !ok || se.Aud != "" {
			http.Redirect(w, r, prefix+"/login?next="+url.QueryEscape(prefix+"/sessions"), http.StatusFound)
			return
		}
		a.staticPage("sessions.html")(w, r)
	})
	mux.HandleFunc("GET "+prefix+"/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		se, ok := a.sessionFor(r)
		if !ok || se.Aud != "" {
			jsonErr(w, 401, "authentication required")
			return
		}
		type row struct {
			ID       string `json:"id"`
			Site     string `json:"site,omitempty"`
			Created  int64  `json:"created"`
			LastSeen int64  `json:"lastSeen"`
			Expires  int64  `json:"expires"`
			UA       string `json:"userAgent,omitempty"`
			Current  bool   `json:"current"`
		}
		out := []row{}
		for _, x := range a.sessions.ListUser(se.User) {
			out = append(out, row{x.ID, x.Aud, x.Created.Unix(), x.Seen.Unix(), x.Exp.Unix(), x.UA, x.ID == se.ID})
		}
		writeJSON(w, 200, map[string]any{"user": se.User, "sessions": out})
	})
	mux.HandleFunc("DELETE "+prefix+"/api/sessions", func(w http.ResponseWriter, r *http.Request) {
		se, ok := a.sessionFor(r)
		if !ok || se.Aud != "" {
			jsonErr(w, 401, "authentication required")
			return
		}
		if r.Header.Get("X-Requested-With") != "wap" { // anti-CSRF, as for the enrolment API
			jsonErr(w, 403, "request refused")
			return
		}
		if r.URL.Query().Get("others") == "1" {
			n := a.sessions.RevokeOthers(se)
			a.auditReq(r, "sign_out", "user", se.User, "scope", "other sessions", "sessions", n, "via", "sessions page")
			writeJSON(w, 200, map[string]any{"ok": true, "sessions": n})
			return
		}
		id := r.URL.Query().Get("id")
		if id == "" || !a.sessions.RevokeOwn(id, se.User) {
			jsonErr(w, 404, "no such session")
			return
		}
		a.auditReq(r, "session_revoked", "user", se.User, "session", id, "via", "sessions page")
		writeJSON(w, 200, map[string]string{"ok": "true"})
	})
}

// ---------------------------------------------------------------- one-time invitation to add a passkey

func (a *App) invitations() *Invites {
	a.invOnce.Do(func() {
		if a.invites == nil {
			a.invites = NewInvites()
		}
	})
	return a.invites
}

// publicBase is the origin printed in invitation links: the login host in forward mode, otherwise the first RP_ORIGINS entry.
func (a *App) publicBase() string {
	if a.cfg.LoginURL != nil {
		return a.cfg.LoginURL.Scheme + "://" + a.cfg.LoginURL.Host
	}
	if len(a.cfg.RPOrigins) > 0 {
		return a.cfg.RPOrigins[0]
	}
	return ""
}

// inviteGuard checks the invitation code (header X-Invite-Code) and the anti-CSRF header, and hands the invitation on.
func (a *App) inviteGuard(w http.ResponseWriter, r *http.Request) (code string, inv invite, ok bool) {
	if r.Header.Get("X-Requested-With") != "wap" {
		jsonErr(w, 403, "request refused")
		return "", invite{}, false
	}
	code = r.Header.Get("X-Invite-Code")
	inv, ok = a.invitations().Peek(code)
	if !ok {
		a.auditReq(r, "enroll_failure", "via", "invite", "reason", "invalid or expired invitation")
		jsonErr(w, 403, "this invitation is invalid, expired or already used")
		return "", invite{}, false
	}
	return code, inv, true
}

func (a *App) inviteAPI(mux *http.ServeMux) {
	mux.HandleFunc("GET "+prefix+"/add", a.staticPage("add.html"))
	mux.HandleFunc("GET "+prefix+"/add.js", a.staticPage("add.js"))
	mux.Handle("POST "+prefix+"/add/begin", a.limited(func(w http.ResponseWriter, r *http.Request) {
		_, inv, ok := a.inviteGuard(w, r)
		if !ok {
			return
		}
		var in struct {
			Label string `json:"label"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in)
		label := inv.label
		if label == "" {
			var err error
			if label, err = CleanLabel(in.Label); err != nil {
				jsonErr(w, 400, err.Error())
				return
			}
		}
		user := a.store.GetOrNew(inv.user)
		opts, sd, err := a.wa.BeginRegistration(user, webauthn.WithExclusions(excludeList(user)))
		if err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		writeJSON(w, 200, map[string]any{"user": inv.user, "cid": a.enroll.Put(enrollState{*sd, user, label}), "options": opts})
	}))
	mux.Handle("POST "+prefix+"/add/finish", a.limited(func(w http.ResponseWriter, r *http.Request) {
		code, inv, ok := a.inviteGuard(w, r)
		if !ok {
			return
		}
		st, ok := a.enroll.Take(r.URL.Query().Get("cid"))
		if !ok || st.User.Name != inv.user { // the ceremony must be the one started for this invitation's user
			jsonErr(w, 400, "ceremony expired, please start again")
			return
		}
		cred, err := a.wa.FinishRegistration(st.User, st.Session, r)
		if err != nil {
			a.auditReq(r, "enroll_failure", "user", inv.user, "via", "invite", "reason", "registration refused")
			jsonErr(w, 400, "registration refused: "+err.Error())
			return
		}
		if !a.invitations().Consume(code) { // used by someone else while the ceremony ran
			jsonErr(w, 403, "this invitation is invalid, expired or already used")
			return
		}
		if err := a.store.AddCredentialLabeled(st.User, cred, st.Label); err != nil {
			jsonErr(w, 409, err.Error())
			return
		}
		a.auditReq(r, "enroll_success", "user", inv.user, "credential", credTag(cred.ID), "via", "invite")
		writeJSON(w, 200, map[string]string{"ok": "true"})
	}))
}

// createInvite is called by the admin socket.
func (a *App) createInvite(user, label string) (url string, exp time.Time, err error) {
	user = strings.TrimSpace(user)
	if user == "" || len(user) > 64 {
		return "", time.Time{}, errInvalidUser
	}
	label, err = CleanLabel(label)
	if err != nil {
		return "", time.Time{}, err
	}
	code, exp, err := a.invitations().Create(user, label)
	if err != nil {
		return "", time.Time{}, err
	}
	a.audit.Event("invite_created", "user", user, "via", "cli", "expires", exp.Unix())
	return a.publicBase() + prefix + "/add#" + code, exp, nil
}

var errInvalidUser = errors.New("invalid user name (1 to 64 characters)")
