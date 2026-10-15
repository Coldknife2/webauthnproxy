package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

func call(a *App, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	a.publicHandler().ServeHTTP(w, r)
	return w
}

func withCookie(c string, extra ...string) map[string]string {
	h := map[string]string{"Cookie": cookieName + "=" + c}
	for i := 0; i+1 < len(extra); i += 2 {
		h[extra[i]] = extra[i+1]
	}
	return h
}

// ---- "my sessions" page

func TestSessionsPageListsOnlyMySessions(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	_ = a.store.AddCredential(a.store.GetOrNew("ana"), &webauthn.Credential{ID: []byte("ana-c")})
	mine := a.sessions.Create("remi", "", "", "Firefox/141", "")
	a.sessions.Create("remi", "anysite.com", "", "", "")
	a.sessions.Create("ana", "", "", "", "")

	if w := call(a, "GET", "/_wap/api/sessions", nil, ""); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	w := call(a, "GET", "/_wap/api/sessions", withCookie(mine), "")
	var out struct {
		User     string
		Sessions []struct {
			ID, Site, UserAgent string
			Current             bool
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.User != "remi" {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if len(out.Sessions) != 3 { // addUser's login session, the one above and the site session; none of ana's
		t.Fatalf("%d sessions listed, want remi's three", len(out.Sessions))
	}
	cur := 0
	for _, s := range out.Sessions {
		if s.Current {
			cur++
			if s.UserAgent != "Firefox/141" {
				t.Errorf("current session = %+v", s)
			}
		}
	}
	if cur != 1 {
		t.Fatalf("%d sessions flagged current", cur)
	}
	if strings.Contains(w.Body.String(), mine) {
		t.Fatal("the listing contains a cookie value")
	}
	// the page needs a login-host session; a site session is not enough
	site := a.sessions.Create("remi", "anysite.com", "", "", "")
	if w := call(a, "GET", "/_wap/api/sessions", withCookie(site), ""); w.Code != 401 {
		t.Fatalf("a site session reached the sessions API: %d", w.Code)
	}
	if w := call(a, "GET", "/_wap/sessions", map[string]string{"Accept": "text/html"}, ""); w.Code != 302 {
		t.Fatalf("anonymous page: %d", w.Code)
	}
	if w := call(a, "GET", "/_wap/sessions", withCookie(mine), ""); w.Code != 200 || !strings.Contains(w.Body.String(), "sessions.js") {
		t.Fatalf("page: %d", w.Code)
	}
}

func TestSessionsPageRevocation(t *testing.T) {
	a := forwardApp(t)
	addUser(t, a)
	_ = a.store.AddCredential(a.store.GetOrNew("ana"), &webauthn.Credential{ID: []byte("ana-c")})
	mine := a.sessions.Create("remi", "", "", "", "")
	other := a.sessions.Create("remi", "", "", "", "")
	thirdParty := a.sessions.Create("ana", "", "", "", "")
	ose, _ := a.sessions.Lookup(other, "", "")
	tse, _ := a.sessions.Lookup(thirdParty, "", "")
	csrf := "X-Requested-With"

	if w := call(a, "DELETE", "/_wap/api/sessions?id="+ose.ID, withCookie(mine), ""); w.Code != 403 {
		t.Fatalf("without the CSRF header: %d", w.Code)
	}
	if w := call(a, "DELETE", "/_wap/api/sessions?id="+ose.ID, map[string]string{csrf: "wap"}, ""); w.Code != 401 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if !sessionAlive(a, other) {
		t.Fatal("a refused request revoked a session")
	}
	// somebody else's session id: refused, and indistinguishable from a missing one
	if w := call(a, "DELETE", "/_wap/api/sessions?id="+tse.ID, withCookie(mine, csrf, "wap"), ""); w.Code != 404 {
		t.Fatalf("revoking another user's session: %d", w.Code)
	}
	if !sessionAlive(a, thirdParty) {
		t.Fatal("a user ended another user's session")
	}
	if w := call(a, "DELETE", "/_wap/api/sessions?id=nope", withCookie(mine, csrf, "wap"), ""); w.Code != 404 {
		t.Fatalf("unknown id: %d", w.Code)
	}
	if w := call(a, "DELETE", "/_wap/api/sessions?id="+ose.ID, withCookie(mine, csrf, "wap"), ""); w.Code != 200 {
		t.Fatalf("own session: %d", w.Code)
	}
	if sessionAlive(a, other) || !sessionAlive(a, mine) {
		t.Fatal("wrong session revoked")
	}
	// end all the others
	again := a.sessions.Create("remi", "", "", "", "")
	if w := call(a, "DELETE", "/_wap/api/sessions?others=1", withCookie(mine, csrf, "wap"), ""); w.Code != 200 {
		t.Fatalf("others: %d", w.Code)
	}
	if sessionAlive(a, again) || !sessionAlive(a, mine) || !sessionAlive(a, thirdParty) {
		t.Fatal("'end all other sessions' reached the wrong sessions")
	}
}

// ---- invitations: add a passkey from another device with a one-time link

func inviteApp(t *testing.T) *App {
	t.Helper()
	a := forwardApp(t)
	a.cfg.RPOrigins = []string{"https://example.com"}
	addUser(t, a)
	return a
}

func TestInviteLinkAndCodeAreNotLeaked(t *testing.T) {
	a := inviteApp(t)
	link, exp, err := a.createInvite("remi", "phone")
	if err != nil {
		t.Fatal(err)
	}
	// forward mode: the link points at the login host, and the code is in the fragment (never sent to a server)
	if !strings.HasPrefix(link, "https://auth.com/_wap/add#") || len(strings.TrimPrefix(link, "https://auth.com/_wap/add#")) < 20 {
		t.Fatalf("link = %q", link)
	}
	if d := time.Until(exp); d > inviteTTL || d < inviteTTL-time.Minute {
		t.Fatalf("expires in %v", d)
	}
}

func TestInviteBeginRefusals(t *testing.T) {
	a := inviteApp(t)
	link, _, _ := a.createInvite("remi", "")
	code := link[strings.Index(link, "#")+1:]
	good := map[string]string{"X-Requested-With": "wap", "X-Invite-Code": code}
	for name, h := range map[string]map[string]string{
		"no header at all":    nil,
		"no code":             {"X-Requested-With": "wap"},
		"no CSRF header":      {"X-Invite-Code": code},
		"wrong code":          {"X-Requested-With": "wap", "X-Invite-Code": code[:len(code)-1] + "x"},
		"the user name":       {"X-Requested-With": "wap", "X-Invite-Code": "remi"},
		"a session cookie":    {"X-Requested-With": "wap", "X-Invite-Code": mk(a, "remi", "")},
		"the code in a query": {"X-Requested-With": "wap"},
	} {
		target := "/_wap/add/begin"
		if name == "the code in a query" {
			target += "?code=" + code
		}
		if w := call(a, "POST", target, h, "{}"); w.Code == 200 {
			t.Errorf("%s accepted", name)
		}
	}
	w := call(a, "POST", "/_wap/add/begin", good, `{"label":"laptop"}`)
	var out struct {
		User    string
		Cid     string
		Options map[string]any
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.User != "remi" || out.Cid == "" || out.Options["publicKey"] == nil {
		t.Fatalf("valid invitation: %d %s", w.Code, w.Body)
	}
	// the invitation is for a user: a name in the request body is ignored
	w = call(a, "POST", "/_wap/add/begin", good, `{"name":"admin"}`)
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.User != "remi" {
		t.Fatalf("the body chose the user: %s", w.Body)
	}
}

func TestInviteExpiryAndSingleUse(t *testing.T) {
	a := inviteApp(t)
	c := &clock{time.Unix(2_000_000_000, 0)}
	a.invitations().now = c.now
	link, _, _ := a.createInvite("remi", "")
	code := link[strings.Index(link, "#")+1:]
	h := map[string]string{"X-Requested-With": "wap", "X-Invite-Code": code}
	if w := call(a, "POST", "/_wap/add/begin", h, "{}"); w.Code != 200 {
		t.Fatalf("fresh: %d", w.Code)
	}
	c.t = c.t.Add(inviteTTL + time.Second)
	if w := call(a, "POST", "/_wap/add/begin", h, "{}"); w.Code != 403 {
		t.Fatalf("expired invitation accepted: %d", w.Code)
	}
	// consumed once
	c.t = time.Unix(2_000_000_000, 0)
	link, _, _ = a.createInvite("remi", "")
	code = link[strings.Index(link, "#")+1:]
	if !a.invitations().Consume(code) || a.invitations().Consume(code) {
		t.Fatal("an invitation can be consumed twice")
	}
	h["X-Invite-Code"] = code
	if w := call(a, "POST", "/_wap/add/begin", h, "{}"); w.Code != 403 {
		t.Fatalf("used invitation accepted: %d", w.Code)
	}
}

func TestInviteFinishRefusals(t *testing.T) {
	a := inviteApp(t)
	link, _, _ := a.createInvite("remi", "")
	code := link[strings.Index(link, "#")+1:]
	good := map[string]string{"X-Requested-With": "wap", "X-Invite-Code": code}
	// an unknown ceremony, a missing code, and a ceremony started by the enrolment page (another flow) are all refused
	if w := call(a, "POST", "/_wap/add/finish?cid=unknown", good, "{}"); w.Code != 400 {
		t.Fatalf("unknown ceremony: %d", w.Code)
	}
	if w := call(a, "POST", "/_wap/add/finish?cid=x", map[string]string{"X-Requested-With": "wap"}, "{}"); w.Code != 403 {
		t.Fatalf("no code: %d", w.Code)
	}
	cid := a.enroll.Put(enrollState{User: a.store.GetOrNew("ana")}) // a ceremony for another user
	if w := call(a, "POST", "/_wap/add/finish?cid="+cid, good, "{}"); w.Code != 400 {
		t.Fatalf("ceremony of another user: %d", w.Code)
	}
	if a.store.CredentialCount() != 1 {
		t.Fatal("a refused request added a passkey")
	}
	// too many pending invitations
	for i := 0; i < maxInvites+1; i++ {
		if _, _, err := a.createInvite("remi", ""); err != nil {
			return
		}
	}
	t.Fatal("the number of pending invitations is not bounded")
}

func TestInvitesAreRateLimited(t *testing.T) {
	a := inviteApp(t)
	a.ipLimit = NewLimiter(RateSpec{3, time.Minute})
	codes := 0
	for i := 0; i < 6; i++ {
		w := call(a, "POST", "/_wap/add/begin", map[string]string{"X-Requested-With": "wap", "X-Invite-Code": "guess"}, "{}")
		if w.Code == http.StatusTooManyRequests {
			codes++
		}
	}
	if codes == 0 {
		t.Fatal("guessing invitation codes is not rate limited")
	}
}

func TestInviteForANewUserAndAdminCommand(t *testing.T) {
	a, dir, logs := adminSetup(t)
	a.cfg.RPOrigins = []string{"https://app.example.com"}
	out, err := cli(dir, "passkeys", "add", "ana", "work", "laptop")
	if err != nil || !strings.Contains(out, "https://app.example.com/_wap/add#") || !strings.Contains(out, "single use") {
		t.Fatalf("add: %q %v", out, err)
	}
	if !strings.Contains(logs.String(), `"event":"invite_created"`) {
		t.Error("no audit event")
	}
	if strings.Contains(logs.String(), out[strings.Index(out, "#")+1:strings.Index(out, "#")+12]) {
		t.Error("the invitation code reached the audit log")
	}
	for name, args := range map[string][]string{"no user": {"passkeys", "add"}, "bad label": {"passkeys", "add", "ana", "bad\nlabel"}} {
		if _, err := cli(dir, args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// ---- labels through the admin command and the import path

func TestAdminLabelsAndListing(t *testing.T) {
	a, dir, logs := adminSetup(t)
	tag := tagOf("remi-phone-credential")
	if out, err := cli(dir, "passkeys", "label", tag, "my", "phone"); err != nil || !strings.Contains(out, "label set") {
		t.Fatalf("label: %q %v", out, err)
	}
	out, _ := cli(dir, "passkeys", "list")
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, tag) {
			line = l
		}
	}
	if !strings.Contains(line, "label=my phone") || !strings.Contains(line, "added=") || strings.Contains(line, "added=-") {
		t.Fatalf("list line = %q", line)
	}
	if !strings.Contains(logs.String(), `"event":"passkey_labeled"`) {
		t.Error("no audit event")
	}
	for name, args := range map[string][]string{"unknown id": {"passkeys", "label", "zzzzzzzz", "x"}, "control character": {"passkeys", "label", tag, "a\nb"}, "too long": {"passkeys", "label", tag, strings.Repeat("a", 41)}} {
		if _, err := cli(dir, args...); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if a.store.CredentialCount() != 3 {
		t.Fatal("labelling changed the passkeys")
	}
}

func TestImportReadsAndChecksTheLabel(t *testing.T) {
	good := importWithLabel(t, "remi", "phone")
	data := t.TempDir()
	store, _ := OpenStore(data)
	dir := t.TempDir()
	_ = writeFile(dir+"/a.json", good)
	_ = writeFile(dir+"/b.json", importWithLabel(t, "ana", "bad\\nlabel"))
	importDir(store, dir, "example.com", true, nil)
	u := store.ByName("remi")
	if u == nil {
		t.Fatal("labelled file not imported")
	}
	for _, m := range u.Meta {
		if m.Label != "phone" || m.Created == 0 {
			t.Fatalf("meta = %+v", m)
		}
	}
	if store.ByName("ana") != nil || !fileExists(dir+"/b.json.rejected") {
		t.Fatal("a file with an invalid label was imported")
	}
}

func importWithLabel(t *testing.T, name, label string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(importJSON(t, name, "example.com", flagsUPUVAT), &m); err != nil {
		t.Fatal(err)
	}
	m["label"] = strings.ReplaceAll(label, `\n`, "\n")
	b, _ := json.Marshal(m)
	return b
}
