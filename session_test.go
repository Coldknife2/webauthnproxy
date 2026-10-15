package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionCreateAndLookup(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	tok := s.Create("remi", "app.example.com", "", "Mozilla/5.0 test", "")
	se, ok := s.Lookup(tok, "", "")
	if !ok || se.User != "remi" || se.Aud != "app.example.com" || se.UA != "Mozilla/5.0 test" {
		t.Fatalf("got %+v %v", se, ok)
	}
	if _, ok := s.Lookup(s.Create("remi", "", "", "", ""), "", ""); !ok {
		t.Fatal("login-host session refused")
	}
}

func TestSessionRejects(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	tok := s.Create("remi", "", "", "", "")
	for name, bad := range map[string]string{
		"empty":              "",
		"modified token":     tok[:len(tok)-1] + "A",
		"appended character": tok + "x",
		"random token":       s.newToken(),
		"a user name":        "remi",
		"a ticket":           s.NewTicket("remi", "", ""),
	} {
		if bad == tok {
			continue
		}
		if _, ok := s.Lookup(bad, "", ""); ok {
			t.Errorf("%s accepted", name)
		}
	}
	// a session from another server (other table) is unknown here
	other := mustSessions(t, "", time.Hour, 0, Binding{})
	if _, ok := other.Lookup(tok, "", ""); ok {
		t.Error("a token issued by another server was accepted")
	}
	// expiry
	c := &clock{time.Unix(2_000_000_000, 0)}
	s.now = c.now
	tok = s.Create("remi", "", "", "", "")
	c.t = c.t.Add(2 * time.Hour)
	if _, ok := s.Lookup(tok, "", ""); ok {
		t.Error("expired session accepted")
	}
}

func TestSessionTokensAreRandomAndOnlyHashesAreStored(t *testing.T) {
	dir := t.TempDir()
	s := mustSessions(t, dir, time.Hour, 0, Binding{})
	seen := map[string]bool{}
	var tok string
	for i := 0; i < 200; i++ {
		tok = s.Create("remi", "", "", "", "")
		if len(tok) != 43 || seen[tok] {
			t.Fatalf("token %q: length %d or repeated", tok, len(tok))
		}
		seen[tok] = true
	}
	b, err := os.ReadFile(filepath.Join(dir, "sessions.json"))
	if err != nil {
		t.Fatal(err)
	}
	for tk := range seen {
		if strings.Contains(string(b), tk) {
			t.Fatal("sessions.json contains a usable cookie value")
		}
	}
	// a copy of the file does not give a cookie: the stored value is the hash, which is not a valid token
	var some string
	for _, se := range s.List() {
		some = b64.EncodeToString(se.hash[:])
		break
	}
	if _, ok := s.Lookup(some, "", ""); ok {
		t.Fatal("the stored hash works as a cookie")
	}
	if st, _ := os.Stat(filepath.Join(dir, "sessions.json")); st.Mode().Perm() != 0o600 {
		t.Fatalf("sessions.json mode %v", st.Mode().Perm())
	}
}

func TestSessionsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	s := mustSessions(t, dir, time.Hour, 0, Binding{})
	tok := s.Create("remi", "anysite.com", "", "", "")
	gone := s.Create("ana", "", "", "", "")
	s.RevokeUser("ana")

	again := mustSessions(t, dir, time.Hour, 0, Binding{})
	if se, ok := again.Lookup(tok, "", ""); !ok || se.User != "remi" {
		t.Fatal("a session did not survive the restart")
	}
	if _, ok := again.Lookup(gone, "", ""); ok {
		t.Fatal("a revoked session came back after the restart")
	}
}

func TestExpiredSessionsAreNotReloaded(t *testing.T) {
	dir := t.TempDir()
	c := &clock{time.Now()}
	s := mustSessions(t, dir, time.Hour, 0, Binding{})
	s.now = c.now
	tok := s.Create("remi", "", "", "", "")
	idleOne := s.Create("remi", "", "", "", "")
	_ = idleOne
	// the server is down for 2 hours; on start, sessions beyond their lifetime are dropped
	later := mustSessions(t, dir, time.Hour, 0, Binding{})
	later.now = func() time.Time { return c.t.Add(2 * time.Hour) }
	later.prune()
	if _, ok := later.Lookup(tok, "", ""); ok {
		t.Fatal("an expired session is still accepted")
	}
	if n := len(later.List()); n != 0 {
		t.Fatalf("%d expired sessions listed", n)
	}
	// and an idle one is dropped when loaded
	idle := mustSessions(t, dir, 5*time.Hour, 20*time.Minute, Binding{})
	idle.now = func() time.Time { return time.Now() }
	tok = idle.Create("remi", "", "", "", "")
	idle.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, ok := idle.Lookup(tok, "", ""); ok {
		t.Fatal("an idle session is still accepted")
	}
}

func TestCorruptSessionFileStopsStart(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "sessions.json"), []byte("{not json"), 0o600)
	if _, err := NewSessions(dir, time.Hour, 0, Binding{}); err == nil {
		t.Fatal("a corrupt sessions.json was silently ignored")
	}
}

func TestBinding(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{UA: true, IP: true})
	tok := s.Create("remi", "", "", "Firefox", "192.0.2.1")
	if _, ok := s.Lookup(tok, "Firefox", "192.0.2.1"); !ok {
		t.Fatal("same browser and address refused")
	}
	if _, ok := s.Lookup(tok, "Chrome", "192.0.2.1"); ok {
		t.Error("another User-Agent accepted")
	}
	if _, ok := s.Lookup(tok, "Firefox", "203.0.113.5"); ok {
		t.Error("another address accepted")
	}
	free := mustSessions(t, "", time.Hour, 0, Binding{})
	tok = free.Create("remi", "", "", "Firefox", "192.0.2.1")
	if _, ok := free.Lookup(tok, "Chrome", "203.0.113.5"); !ok {
		t.Error("without SESSION_BIND nothing is checked")
	}
}

func TestRevocationScopes(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	login := s.Create("remi", "", "", "", "")
	lse, _ := s.Lookup(login, "", "")
	siteA := s.Create("remi", "a.example", lse.Handle(), "", "")
	siteB := s.Create("remi", "b.example", lse.Handle(), "", "")
	otherLogin := s.Create("remi", "", "", "", "") // another device
	otherSite := s.Create("remi", "a.example", "", "", "")
	stranger := s.Create("ana", "", "", "", "")

	asea, _ := s.Lookup(siteA, "", "")
	s.RevokeTree(asea) // sign out from a site: the login session and its other sites go too
	for name, tok := range map[string]string{"login": login, "site A": siteA, "site B": siteB} {
		if _, ok := s.Lookup(tok, "", ""); ok {
			t.Errorf("%s survived the sign-out of this browser", name)
		}
	}
	for name, tok := range map[string]string{"another device": otherLogin, "unrelated site session": otherSite, "another user": stranger} {
		if _, ok := s.Lookup(tok, "", ""); !ok {
			t.Errorf("%s was signed out by mistake", name)
		}
	}
	if n := s.RevokeUser("remi"); n != 2 {
		t.Errorf("RevokeUser removed %d sessions, want 2", n)
	}
	if _, ok := s.Lookup(stranger, "", ""); !ok {
		t.Error("RevokeUser reached another user")
	}
}

func TestRevokeByID(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	a := s.Create("remi", "", "", "", "")
	b := s.Create("remi", "", "", "", "")
	sa, _ := s.Lookup(a, "", "")
	if _, err := s.RevokeID("zzzzzzz"); err == nil {
		t.Error("unknown id accepted")
	}
	if _, err := s.RevokeID(""); err == nil {
		t.Error("empty id matched several sessions and was accepted")
	}
	if _, err := s.RevokeID(sa.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(a, "", ""); ok {
		t.Error("revoked session still valid")
	}
	if _, ok := s.Lookup(b, "", ""); !ok {
		t.Error("the other session was revoked")
	}
}

func TestSessionTableIsBounded(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	for i := 0; i < maxSessions+50; i++ {
		s.Create("remi", "", "", "", "")
	}
	if n := len(s.List()); n > maxSessions {
		t.Fatalf("%d sessions kept, limit %d", n, maxSessions)
	}
}

func TestCeremonyOneShot(t *testing.T) {
	c := NewCeremonies[string]()
	id := c.Put("x")
	if v, ok := c.Take(id); !ok || v != "x" {
		t.Fatal("first read failed")
	}
	if _, ok := c.Take(id); ok {
		t.Fatal("ceremony is reusable")
	}
}

// ---- tickets

func TestTicketIsSingleUseAndBoundToItsSite(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	tk := s.NewTicket("remi", "app.example.com", "parent")
	if u, p, why := s.ConsumeTicket(tk, "app.example.com"); why != "" || u != "remi" || p != "parent" {
		t.Fatalf("first use: %q %q %q", u, p, why)
	}
	if _, _, why := s.ConsumeTicket(tk, "app.example.com"); why == "" {
		t.Fatal("ticket reused")
	}
	// presented on another site: refused, and burnt (an attacker gets no second try on the right site)
	tk = s.NewTicket("remi", "app.example.com", "")
	if _, _, why := s.ConsumeTicket(tk, "evil.example"); why == "" {
		t.Fatal("ticket accepted on another site")
	}
	if _, _, why := s.ConsumeTicket(tk, "app.example.com"); why == "" {
		t.Fatal("a ticket refused once stayed usable")
	}
	// a session cookie is not a ticket and a ticket is not a session cookie
	if _, _, why := s.ConsumeTicket(s.Create("remi", "app.example.com", "", "", ""), "app.example.com"); why == "" {
		t.Error("session accepted as ticket")
	}
	if _, ok := s.Lookup(s.NewTicket("remi", "app.example.com", ""), "", ""); ok {
		t.Error("ticket accepted as session")
	}
}

func TestTicketExpires(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	c := &clock{time.Unix(2_000_000_000, 0)}
	s.now = c.now
	tk := s.NewTicket("remi", "app.example.com", "")
	c.t = c.t.Add(ticketTTL + time.Second)
	if _, _, why := s.ConsumeTicket(tk, "app.example.com"); why != "expired" {
		t.Fatalf("expired ticket: %q", why)
	}
}

func TestTicketTableIsBounded(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	for i := 0; i < maxTickets+100; i++ {
		s.NewTicket("remi", "app.example.com", "")
	}
	s.mu.RLock()
	n := len(s.tickets)
	s.mu.RUnlock()
	if n > maxTickets {
		t.Fatalf("%d tickets kept", n)
	}
}

func TestSignInAgainReplacesTheOldLoginAndKeepsItsSites(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	old := s.Create("remi", "", "", "", "")
	ose, _ := s.Lookup(old, "", "")
	site := s.Create("remi", "a.example", ose.Handle(), "", "")
	fresh := s.Create("remi", "", "", "", "")
	s.Replace(ose, fresh)
	if _, ok := s.Lookup(old, "", ""); ok {
		t.Fatal("the superseded login session is still valid")
	}
	if _, ok := s.Lookup(site, "", ""); !ok {
		t.Fatal("the site session was lost when signing in again")
	}
	fse, _ := s.Lookup(fresh, "", "")
	s.RevokeTree(fse) // signing out of the new login now reaches the site opened under the old one
	if _, ok := s.Lookup(site, "", ""); ok {
		t.Fatal("the site session escaped the sign-out of this browser")
	}
}

func TestPerUserSessionCapDropsTheLeastRecentlyUsed(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	s.maxPerUser = 3
	c := &clock{time.Unix(2_000_000_000, 0)}
	s.now = c.now
	var toks []string
	for i := 0; i < 3; i++ {
		toks = append(toks, s.Create("remi", "", "", "", ""))
		c.t = c.t.Add(time.Second)
	}
	other := s.Create("ana", "", "", "", "")
	s.Lookup(toks[0], "", "") // the oldest session was used just now: the second one is now the least recently used
	c.t = c.t.Add(time.Second)
	fourth := s.Create("remi", "", "", "", "")
	if _, ok := s.Lookup(toks[1], "", ""); ok {
		t.Error("the least recently used session was kept")
	}
	for name, tok := range map[string]string{"used one": toks[0], "third": toks[2], "new": fourth, "another user's": other} {
		if _, ok := s.Lookup(tok, "", ""); !ok {
			t.Errorf("%s session was dropped", name)
		}
	}
	if n := len(s.ListUser("remi")); n != 3 {
		t.Fatalf("remi has %d sessions, want the cap of 3", n)
	}
	// a flood of sign-ins keeps the cap and never touches another user
	for i := 0; i < 100; i++ {
		c.t = c.t.Add(time.Second)
		s.Create("remi", "", "", "", "")
	}
	if n := len(s.ListUser("remi")); n != 3 || len(s.ListUser("ana")) != 1 {
		t.Fatalf("after a flood: remi %d, ana %d", n, len(s.ListUser("ana")))
	}
	s.maxPerUser = 0 // no limit
	for i := 0; i < 10; i++ {
		s.Create("remi", "", "", "", "")
	}
	if n := len(s.ListUser("remi")); n != 13 {
		t.Fatalf("with the cap off remi has %d sessions, want 13", n)
	}
}

func TestSessionMaxPerUserConfig(t *testing.T) {
	t.Setenv("UPSTREAM", "http://localhost:3000")
	t.Setenv("RP_ID", "localhost")
	t.Setenv("RP_ORIGINS", "http://localhost:8080")
	if c, err := LoadConfig(); err != nil || c.SessionMaxPerUser != defaultMaxPerUser {
		t.Fatalf("default: %v %+v", err, c)
	}
	t.Setenv("SESSION_MAX_PER_USER", "7")
	if c, err := LoadConfig(); err != nil || c.SessionMaxPerUser != 7 {
		t.Fatalf("7: %v", err)
	}
	for _, bad := range []string{"-1", "many", "1.5"} {
		t.Setenv("SESSION_MAX_PER_USER", bad)
		if _, err := LoadConfig(); err == nil {
			t.Errorf("SESSION_MAX_PER_USER=%s accepted", bad)
		}
	}
}

func TestRevokeOthersKeepsThisBrowser(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	login := s.Create("remi", "", "", "", "")
	lse, _ := s.Lookup(login, "", "")
	site := s.Create("remi", "a.example", lse.Handle(), "", "")
	otherLogin := s.Create("remi", "", "", "", "")
	stranger := s.Create("ana", "", "", "", "")
	if n := s.RevokeOthers(lse); n != 1 {
		t.Errorf("RevokeOthers removed %d, want 1", n)
	}
	for name, tok := range map[string]string{"this login": login, "its site": site, "another user": stranger} {
		if _, ok := s.Lookup(tok, "", ""); !ok {
			t.Errorf("%s was ended", name)
		}
	}
	if _, ok := s.Lookup(otherLogin, "", ""); ok {
		t.Error("another session of the user survived")
	}
}

func TestRevokeOwnRefusesOtherUsers(t *testing.T) {
	s := mustSessions(t, "", time.Hour, 0, Binding{})
	mine := s.Create("remi", "", "", "", "")
	theirs := s.Create("ana", "", "", "", "")
	tse, _ := s.Lookup(theirs, "", "")
	if s.RevokeOwn(tse.ID, "remi") {
		t.Fatal("a user revoked somebody else's session")
	}
	if _, ok := s.Lookup(theirs, "", ""); !ok {
		t.Fatal("the other session was ended")
	}
	mse, _ := s.Lookup(mine, "", "")
	if !s.RevokeOwn(mse.ID, "remi") {
		t.Fatal("own session not revoked")
	}
}
