package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookieName = "wap_session"

// Sessions issues stateless HMAC-signed tokens: session cookies and login tickets.
// A session is bound to an audience: "" for the login host (or a shared cookie domain), or the
// host of a protected site for the per-host cookies issued through the ticket exchange.
//
// keys[0] signs everything new; the other keys only verify, so the signing key can be rotated
// without signing everybody out (keep the previous key at least SESSION_TTL).
type Sessions struct {
	keys  [][]byte
	pools []*sync.Pool // reusable HMAC hashers, one pool per key
	ttl   time.Duration
	idle  time.Duration // 0 = no idle timeout
	now   func() time.Time
	boot  string // identifies this process; written into tickets (see NewTicket)
}

// NewSessions returns a Sessions signing with current and also accepting the previous keys.
func NewSessions(current []byte, previous [][]byte, ttl, idle time.Duration) *Sessions {
	s := &Sessions{ttl: ttl, idle: idle, now: time.Now}
	b := make([]byte, bootLen)
	_, _ = rand.Read(b)
	s.boot = b64.EncodeToString(b)
	for _, k := range append([][]byte{current}, previous...) {
		s.keys = append(s.keys, k)
		s.pools = append(s.pools, &sync.Pool{})
	}
	return s
}

// bootLen is the size in bytes of the per-process identifier written into every ticket.
const bootLen = 9

// ticketTTL is how long a login ticket stays valid; it is also single-use.
const ticketTTL = 60 * time.Second

// loadSecrets returns the signing key and the previous keys still accepted for verification.
// The signing key is SESSION_SECRET, or a random key kept in DATA_DIR/session.key. Previous keys come from
// SESSION_SECRET_PREVIOUS and from DATA_DIR/session.key.previous (rotate with: mv session.key session.key.previous, then restart).
func loadSecrets(dir string, configured []byte, previousEnv [][]byte) (current []byte, previous [][]byte, err error) {
	previous = append(previous, previousEnv...)
	if b, err := os.ReadFile(filepath.Join(dir, "session.key.previous")); err == nil && len(b) >= 32 {
		previous = append(previous, b)
	}
	if len(configured) > 0 {
		return configured, previous, nil
	}
	p := filepath.Join(dir, "session.key")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b, previous, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, err
	}
	return b, previous, os.WriteFile(p, b, 0o600)
}

var b64 = base64.RawURLEncoding

// mac computes HMAC-SHA256(kind|payload) with key number i, using a pooled hasher, appending the sum to dst.
// kind separates the token kinds ("s" session, "t" ticket) so one can never be used as the other.
func (s *Sessions) mac(i int, kind, payload string, dst []byte) []byte {
	m, _ := s.pools[i].Get().(hash.Hash)
	if m == nil {
		m = hmac.New(sha256.New, s.keys[i])
	}
	m.Reset()
	io.WriteString(m, kind)
	io.WriteString(m, "|")
	io.WriteString(m, payload)
	dst = m.Sum(dst)
	s.pools[i].Put(m)
	return dst
}

func (s *Sessions) sign(kind, payload string) string {
	var sum [sha256.Size]byte
	return b64.EncodeToString(s.mac(0, kind, payload, sum[:0]))
}

// token layout: user.aud.exp.gen[.extra…] (user and aud are base64url, so they can never contain the "." separator).
// gen is the user's session generation: bumping it on the server revokes every token issued before.
func (s *Sessions) token(kind, user, aud string, exp time.Time, gen int64, extra ...string) string {
	parts := append([]string{b64.EncodeToString([]byte(user)), b64.EncodeToString([]byte(aud)),
		strconv.FormatInt(exp.Unix(), 10), strconv.FormatInt(gen, 10)}, extra...)
	payload := strings.Join(parts, ".")
	return payload + "." + s.sign(kind, payload)
}

// parse checks the signature (with the current key, then the previous ones) and the expiry and returns the payload fields.
func (s *Sessions) parse(kind, v string, fields int) ([]string, time.Time, error) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return nil, time.Time{}, errors.New("format")
	}
	payload, sig := v[:i], v[i+1:]
	got, err := b64.DecodeString(sig)
	if err != nil {
		return nil, time.Time{}, errors.New("signature")
	}
	valid := false
	for k := range s.keys {
		var sum [sha256.Size]byte
		if hmac.Equal(got, s.mac(k, kind, payload, sum[:0])) {
			valid = true
			break
		}
	}
	if !valid {
		return nil, time.Time{}, errors.New("signature")
	}
	parts := strings.Split(payload, ".")
	if len(parts) != fields {
		return nil, time.Time{}, errors.New("format")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || s.now().Unix() > exp {
		return nil, time.Time{}, errors.New("expired")
	}
	return parts, time.Unix(exp, 0), nil
}

func decode(seg string) (string, error) {
	b, err := b64.DecodeString(seg)
	return string(b), err
}

// Session is the content of a verified session token.
type Session struct {
	User, Aud string
	Gen       int64
	Exp, Seen time.Time // absolute expiry; last activity recorded in the token
}

// session token layout: user.aud.exp.gen.seen (seen = last activity, unix seconds).
const sessionFields = 5

// New returns a session token for user, bound to audience aud and to the user's session generation.
func (s *Sessions) New(user, aud string, gen int64) string {
	now := s.now()
	return s.token("s", user, aud, now.Add(s.ttl), gen, strconv.FormatInt(now.Unix(), 10))
}

// Renew returns the same session with its last-activity time moved to now (the absolute expiry is unchanged).
func (s *Sessions) Renew(se Session) string {
	return s.token("s", se.User, se.Aud, se.Exp, se.Gen, strconv.FormatInt(s.now().Unix(), 10))
}

// VerifySession checks the signature, the absolute expiry and, when configured, the idle timeout.
func (s *Sessions) VerifySession(v string) (Session, error) {
	p, exp, err := s.parse("s", v, sessionFields)
	if err != nil {
		return Session{}, err
	}
	se := Session{Exp: exp}
	if se.User, err = decode(p[0]); err != nil {
		return Session{}, err
	}
	if se.Aud, err = decode(p[1]); err != nil {
		return Session{}, err
	}
	if se.Gen, err = strconv.ParseInt(p[3], 10, 64); err != nil {
		return Session{}, err
	}
	seen, err := strconv.ParseInt(p[4], 10, 64)
	if err != nil {
		return Session{}, err
	}
	se.Seen = time.Unix(seen, 0)
	if s.idle > 0 && s.now().Sub(se.Seen) > s.idle {
		return Session{}, errors.New("idle")
	}
	return se, nil
}

// NeedsRenewal reports whether the session should be re-issued with a fresh last-activity time:
// only when an idle timeout is set and a quarter of it has passed, so that most requests set no cookie.
func (s *Sessions) NeedsRenewal(se Session) bool {
	return s.idle > 0 && s.now().Sub(se.Seen) > s.idle/4
}

// Verify returns the user name, audience and generation if the session token is valid.
func (s *Sessions) Verify(v string) (user, aud string, gen int64, err error) {
	se, err := s.VerifySession(v)
	return se.User, se.Aud, se.Gen, err
}

// NewTicket returns a short-lived, single-use ticket granting a session on host aud.
func (s *Sessions) NewTicket(user, aud string, gen int64) string {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	// The ticket carries the identifier of the process that issued it (s.boot, 12 characters). Single use is
	// enforced by an in-memory set of nonces, which a restart empties: a ticket from an earlier run, or from another
	// instance, is therefore refused rather than redeemable a second time.
	return s.token("t", user, aud, s.now().Add(ticketTTL), gen, s.boot+b64.EncodeToString(n))
}

// VerifyTicket returns the ticket's user, audience, generation, nonce and expiry if it is valid.
func (s *Sessions) VerifyTicket(v string) (user, aud string, gen int64, nonce string, exp time.Time, err error) {
	p, exp, err := s.parse("t", v, 5)
	if err != nil {
		return "", "", 0, "", time.Time{}, err
	}
	if user, err = decode(p[0]); err != nil {
		return "", "", 0, "", time.Time{}, err
	}
	if aud, err = decode(p[1]); err != nil {
		return "", "", 0, "", time.Time{}, err
	}
	if gen, err = strconv.ParseInt(p[3], 10, 64); err != nil {
		return "", "", 0, "", time.Time{}, err
	}
	if !strings.HasPrefix(p[4], s.boot) || len(p[4]) <= len(s.boot) {
		return "", "", 0, "", time.Time{}, errors.New("ticket from another run")
	}
	return user, aud, gen, p[4], exp, nil
}

// Seen remembers single-use values (ticket nonces) until they expire.
type Seen struct {
	mu sync.Mutex
	m  map[string]time.Time
}

// Mark records nonce and reports whether it was new (false = replay).
func (s *Seen) Mark(nonce string, exp time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]time.Time{}
	}
	now := time.Now()
	for k, e := range s.m {
		if now.After(e) {
			delete(s.m, k)
		}
	}
	if _, dup := s.m[nonce]; dup {
		return false
	}
	s.m[nonce] = exp
	return true
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
