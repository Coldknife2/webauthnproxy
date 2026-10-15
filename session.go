package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const cookieName = "wap_session"

var b64 = base64.RawURLEncoding

// Server-side sessions.
//
// A cookie holds a random 256-bit token. The server keeps only its SHA-256 and the session's data
// (user, audience, expiry, last activity, optional User-Agent/IP binding), so a copy of the database does not
// give access, a session can be listed and revoked on its own, and idle timeout and revocation are exact.
// Sessions are written to DATA_DIR/sessions.json (mode 0600) and survive a restart; last-activity times are
// flushed every flushEvery, so a crash can only lose a little precision on them.
//
// Login tickets (cross-domain) are random values held in memory and consumed on first presentation: single use
// is exact within the process, and a ticket never survives a restart.

const (
	ticketTTL   = 60 * time.Second
	maxSessions = 20000
	maxTickets  = 10000
	flushEvery  = 30 * time.Second
)

type hash32 = [sha256.Size]byte

func tokenHash(token string) hash32 { return sha256.Sum256([]byte(token)) }

// shortID is the non-secret identifier of a session shown by the admin commands and written to the audit log.
func shortID(h hash32) string { return b64.EncodeToString(h[:6]) }

func uaDisplay(ua string) string {
	if len(ua) > 120 {
		ua = ua[:120]
	}
	return ua
}

func bindHash(v string) string {
	if v == "" {
		return ""
	}
	h := sha256.Sum256([]byte(v))
	return b64.EncodeToString(h[:12])
}

type sess struct {
	user, aud, parent  string // parent: hash (base64) of the login session this site session was opened from
	created, exp       time.Time
	seen               atomic.Int64 // last activity, unix seconds
	ua, uaHash, ipHash string
}

// Session is a copy of a stored session.
type Session struct {
	ID        string
	User, Aud string
	Created   time.Time
	Exp, Seen time.Time
	UA        string
	hash      hash32
}

type ticket struct {
	user, aud, parent string
	exp               time.Time
}

// Binding says which request properties a session is tied to (SESSION_BIND).
type Binding struct{ UA, IP bool }

type Sessions struct {
	mu        sync.RWMutex
	m         map[hash32]*sess
	tickets   map[hash32]ticket
	ttl       time.Duration
	idle      time.Duration // 0 = no idle timeout
	bind      Binding
	now       func() time.Time
	path      string // "" = memory only (tests)
	dirty     atomic.Bool
	stopFlush chan struct{}
}

// NewSessions returns an empty session table. With a data directory the table is loaded from, and saved to,
// DATA_DIR/sessions.json.
func NewSessions(dir string, ttl, idle time.Duration, bind Binding) (*Sessions, error) {
	s := &Sessions{m: map[hash32]*sess{}, tickets: map[hash32]ticket{}, ttl: ttl, idle: idle, bind: bind, now: time.Now}
	if dir == "" {
		return s, nil
	}
	s.path = filepath.Join(dir, "sessions.json")
	return s, s.load()
}

type diskSession struct {
	H       string `json:"h"`
	User    string `json:"user"`
	Aud     string `json:"aud,omitempty"`
	Parent  string `json:"parent,omitempty"`
	Created int64  `json:"created"`
	Exp     int64  `json:"exp"`
	Seen    int64  `json:"seen"`
	UA      string `json:"ua,omitempty"`
	UAHash  string `json:"uah,omitempty"`
	IPHash  string `json:"iph,omitempty"`
}

func (s *Sessions) load() error {
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rows []diskSession
	if err := json.Unmarshal(b, &rows); err != nil {
		return errors.New("sessions.json: " + err.Error())
	}
	now := s.now()
	for _, r := range rows {
		raw, err := b64.DecodeString(r.H)
		if err != nil || len(raw) != sha256.Size {
			continue
		}
		x := &sess{user: r.User, aud: r.Aud, parent: r.Parent, created: time.Unix(r.Created, 0), exp: time.Unix(r.Exp, 0), ua: r.UA, uaHash: r.UAHash, ipHash: r.IPHash}
		x.seen.Store(r.Seen)
		if s.dead(x, now) {
			continue
		}
		var h hash32
		copy(h[:], raw)
		s.m[h] = x
	}
	return nil
}

// dead reports whether a session is expired or idle.
func (s *Sessions) dead(x *sess, now time.Time) bool {
	if !now.Before(x.exp) {
		return true
	}
	return s.idle > 0 && now.Sub(time.Unix(x.seen.Load(), 0)) > s.idle
}

// save writes the table atomically. Callers hold no lock.
func (s *Sessions) save() error {
	if s.path == "" {
		return nil
	}
	s.mu.RLock()
	rows := make([]diskSession, 0, len(s.m))
	for h, x := range s.m {
		rows = append(rows, diskSession{H: b64.EncodeToString(h[:]), User: x.user, Aud: x.aud, Parent: x.parent,
			Created: x.created.Unix(), Exp: x.exp.Unix(), Seen: x.seen.Load(), UA: x.ua, UAHash: x.uaHash, IPHash: x.ipHash})
	}
	s.mu.RUnlock()
	sort.Slice(rows, func(i, j int) bool { return rows[i].H < rows[j].H })
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	s.dirty.Store(false)
	return os.Rename(tmp, s.path)
}

// Run flushes last-activity times periodically and prunes dead sessions until Stop is called.
func (s *Sessions) Run() {
	s.stopFlush = make(chan struct{})
	go func() {
		t := time.NewTicker(flushEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				s.prune()
				if s.dirty.Load() {
					_ = s.save()
				}
			case <-s.stopFlush:
				return
			}
		}
	}()
}

// Stop ends Run and writes the table one last time.
func (s *Sessions) Stop() {
	if s.stopFlush != nil {
		close(s.stopFlush)
	}
	_ = s.save()
}

func (s *Sessions) prune() {
	now := s.now()
	s.mu.Lock()
	for h, x := range s.m {
		if s.dead(x, now) {
			delete(s.m, h)
			s.dirty.Store(true)
		}
	}
	for h, t := range s.tickets {
		if !now.Before(t.exp) {
			delete(s.tickets, h)
		}
	}
	s.mu.Unlock()
}

func (s *Sessions) newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b64.EncodeToString(b)
}

// Create opens a session for user on audience aud ("" = the login host or a shared cookie domain) and returns the
// cookie value. parent is the session this one was opened from (cross-domain), or "".
func (s *Sessions) Create(user, aud, parent, ua, ip string) (token string) {
	token = s.newToken()
	now := s.now()
	x := &sess{user: user, aud: aud, parent: parent, created: now, exp: now.Add(s.ttl), ua: uaDisplay(ua)}
	x.seen.Store(now.Unix())
	if s.bind.UA {
		x.uaHash = bindHash(ua)
	}
	if s.bind.IP {
		x.ipHash = bindHash(ip)
	}
	s.mu.Lock()
	if len(s.m) >= maxSessions { // memory bound: drop the sessions closest to expiry
		var oldest hash32
		var oe time.Time
		first := true
		for h, v := range s.m {
			if first || v.exp.Before(oe) {
				oldest, oe, first = h, v.exp, false
			}
		}
		delete(s.m, oldest)
	}
	s.m[tokenHash(token)] = x
	s.mu.Unlock()
	_ = s.save()
	return token
}

// Lookup returns the session of a cookie value if it exists, has not expired or been idle too long, and matches the
// request's binding. It records the activity. Every failure looks the same to the caller.
func (s *Sessions) Lookup(token, ua, ip string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	h := tokenHash(token)
	now := s.now()
	s.mu.RLock()
	x := s.m[h]
	s.mu.RUnlock()
	if x == nil || s.dead(x, now) {
		return Session{}, false
	}
	if x.uaHash != "" && subtle.ConstantTimeCompare([]byte(x.uaHash), []byte(bindHash(ua))) != 1 {
		return Session{}, false
	}
	if x.ipHash != "" && subtle.ConstantTimeCompare([]byte(x.ipHash), []byte(bindHash(ip))) != 1 {
		return Session{}, false
	}
	if now.Unix() != x.seen.Load() {
		x.seen.Store(now.Unix())
		s.dirty.Store(true)
	}
	return Session{ID: shortID(h), User: x.user, Aud: x.aud, Created: x.created, Exp: x.exp, Seen: now, UA: x.ua, hash: h}, true
}

// Handle is the value to pass as parent when opening sessions from this one.
func (se Session) Handle() string { return b64.EncodeToString(se.hash[:]) }

// Alive reports whether the session with this handle still exists.
func (s *Sessions) Alive(handle string) bool {
	raw, err := b64.DecodeString(handle)
	if err != nil || len(raw) != sha256.Size {
		return false
	}
	var h hash32
	copy(h[:], raw)
	s.mu.RLock()
	x := s.m[h]
	s.mu.RUnlock()
	return x != nil && !s.dead(x, s.now())
}

// List returns the live sessions, newest first.
func (s *Sessions) List() []Session {
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Session{}
	for h, x := range s.m {
		if s.dead(x, now) {
			continue
		}
		out = append(out, Session{ID: shortID(h), User: x.user, Aud: x.aud, Created: x.created, Exp: x.exp, Seen: time.Unix(x.seen.Load(), 0), UA: x.ua, hash: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

// removeLocked deletes every session satisfying match and reports how many went.
func (s *Sessions) removeWhere(match func(h hash32, x *sess) bool) int {
	n := 0
	s.mu.Lock()
	for h, x := range s.m {
		if match(h, x) {
			delete(s.m, h)
			n++
		}
	}
	s.mu.Unlock()
	if n > 0 {
		_ = s.save()
	}
	return n
}

// RevokeTree ends a session together with the site sessions that were opened from it, or, given a site
// session, the login session it came from and that session's other sites: "sign out of this browser".
func (s *Sessions) RevokeTree(se Session) int {
	root := se.Handle()
	s.mu.RLock()
	if x := s.m[se.hash]; x != nil && x.parent != "" {
		root = x.parent
	}
	s.mu.RUnlock()
	return s.removeWhere(func(h hash32, x *sess) bool {
		return b64.EncodeToString(h[:]) == root || x.parent == root || h == se.hash
	})
}

// Replace ends a login session that has just been superseded by a new sign-in in the same browser (newToken is the
// cookie value of the new session) and hands the site sessions opened from it over to the new one, so they stay
// reachable by "sign out of this browser".
func (s *Sessions) Replace(old Session, newToken string) {
	nh := b64.EncodeToString(func() []byte { h := tokenHash(newToken); return h[:] }())
	oh := old.Handle()
	s.mu.Lock()
	delete(s.m, old.hash)
	for _, x := range s.m {
		if x.parent == oh {
			x.parent = nh
		}
	}
	s.mu.Unlock()
	_ = s.save()
}

// RevokeUser ends every session of a user ("sign out everywhere").
func (s *Sessions) RevokeUser(user string) int {
	return s.removeWhere(func(_ hash32, x *sess) bool { return x.user == user })
}

// RevokeID ends the session whose short identifier starts with id. It returns the sessions removed, or an error
// when the id matches nothing or several sessions.
func (s *Sessions) RevokeID(id string) (Session, error) {
	var found []Session
	for _, se := range s.List() {
		if strings.HasPrefix(se.ID, id) {
			found = append(found, se)
		}
	}
	switch len(found) {
	case 0:
		return Session{}, errors.New("no session with that id")
	case 1:
		s.removeWhere(func(h hash32, _ *sess) bool { return h == found[0].hash })
		return found[0], nil
	}
	return Session{}, errors.New("several sessions match, give more characters")
}

// ---- tickets

// NewTicket returns a single-use ticket granting a session on host aud, valid for ticketTTL.
func (s *Sessions) NewTicket(user, aud, parent string) string {
	tok := s.newToken()
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tickets) >= maxTickets {
		for h, t := range s.tickets {
			if !now.Before(t.exp) {
				delete(s.tickets, h)
			}
		}
		for h := range s.tickets { // still full: tickets live 60 s, drop an arbitrary one rather than grow
			if len(s.tickets) < maxTickets {
				break
			}
			delete(s.tickets, h)
		}
	}
	s.tickets[tokenHash(tok)] = ticket{user, aud, parent, now.Add(ticketTTL)}
	return tok
}

// ConsumeTicket removes the ticket on first presentation, whatever the outcome, and returns it when it was
// valid and issued for aud. A second presentation, a presentation on another site and an expired ticket all fail.
func (s *Sessions) ConsumeTicket(tok, aud string) (user, parent string, reason string) {
	h := tokenHash(tok)
	s.mu.Lock()
	t, ok := s.tickets[h]
	delete(s.tickets, h)
	s.mu.Unlock()
	switch {
	case !ok:
		return "", "", "unknown, expired or already used"
	case !s.now().Before(t.exp):
		return "", "", "expired"
	case t.aud != aud:
		return "", "", "issued for another site"
	}
	return t.user, t.parent, ""
}

// Ceremonies keeps WebAuthn ceremony data in memory (single use, short TTL).
type Ceremonies[T any] struct {
	mu sync.Mutex
	m  map[string]ceremony[T]
}

type ceremony[T any] struct {
	v   T
	exp time.Time
}

// maxCeremonies bounds the memory used by unfinished ceremonies.
const maxCeremonies = 10000

func NewCeremonies[T any]() *Ceremonies[T] { return &Ceremonies[T]{m: map[string]ceremony[T]{}} }

func (c *Ceremonies[T]) Put(v T) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	id := b64.EncodeToString(b)
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for k, x := range c.m {
		if now.After(x.exp) {
			delete(c.m, k)
		}
	}
	if len(c.m) >= maxCeremonies { // memory bound if rate limiting is disabled: drop the one closest to expiry
		var oldest string
		var oe time.Time
		for k, x := range c.m {
			if oldest == "" || x.exp.Before(oe) {
				oldest, oe = k, x.exp
			}
		}
		delete(c.m, oldest)
	}
	c.m[id] = ceremony[T]{v, now.Add(5 * time.Minute)}
	return id
}

// Take retrieves and consumes the ceremony.
func (c *Ceremonies[T]) Take(id string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	x, ok := c.m[id]
	delete(c.m, id)
	if !ok || time.Now().After(x.exp) {
		var zero T
		return zero, false
	}
	return x.v, true
}
