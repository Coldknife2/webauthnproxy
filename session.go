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
type Sessions struct {
	secret []byte
	ttl    time.Duration
	pool   sync.Pool // reusable HMAC hashers
}

// ticketTTL is how long a login ticket stays valid; it is also single-use.
const ticketTTL = 60 * time.Second

func loadSecret(dir string, configured []byte) ([]byte, error) {
	if len(configured) > 0 {
		return configured, nil
	}
	p := filepath.Join(dir, "session.key")
	if b, err := os.ReadFile(p); err == nil && len(b) >= 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, os.WriteFile(p, b, 0o600)
}

var b64 = base64.RawURLEncoding

// sign separates the token kinds ("s" session, "t" ticket) so one can never be used as the other.
func (s *Sessions) sign(kind, payload string) string {
	var sum [sha256.Size]byte
	return b64.EncodeToString(s.mac(kind, payload, sum[:0]))
}

// mac computes HMAC-SHA256(kind|payload) with a pooled hasher, appending the sum to dst.
func (s *Sessions) mac(kind, payload string, dst []byte) []byte {
	m, _ := s.pool.Get().(hash.Hash)
	if m == nil {
		m = hmac.New(sha256.New, s.secret)
	}
	m.Reset()
	io.WriteString(m, kind)
	io.WriteString(m, "|")
	io.WriteString(m, payload)
	dst = m.Sum(dst)
	s.pool.Put(m)
	return dst
}

func (s *Sessions) token(kind, user, aud string, ttl time.Duration, extra ...string) string {
	parts := append([]string{b64.EncodeToString([]byte(user)), b64.EncodeToString([]byte(aud)),
		strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)}, extra...)
	payload := strings.Join(parts, ".")
	return payload + "." + s.sign(kind, payload)
}

// parse checks the signature and expiry and returns the payload fields.
func (s *Sessions) parse(kind, v string, fields int) ([]string, time.Time, error) {
	i := strings.LastIndexByte(v, '.')
	if i < 0 {
		return nil, time.Time{}, errors.New("format")
	}
	payload, sig := v[:i], v[i+1:]
	var sum [sha256.Size]byte
	got, err := b64.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(kind, payload, sum[:0])) {
		return nil, time.Time{}, errors.New("signature")
	}
	parts := strings.Split(payload, ".")
	if len(parts) != fields {
		return nil, time.Time{}, errors.New("format")
	}
	exp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return nil, time.Time{}, errors.New("expired")
	}
	return parts, time.Unix(exp, 0), nil
}

func decode(seg string) (string, error) {
	b, err := b64.DecodeString(seg)
	return string(b), err
}

// New returns a session token for user, bound to audience aud.
func (s *Sessions) New(user, aud string) string { return s.token("s", user, aud, s.ttl) }

// Verify returns the user name and audience if the session token is valid.
func (s *Sessions) Verify(v string) (user, aud string, err error) {
	p, _, err := s.parse("s", v, 3)
	if err != nil {
		return "", "", err
	}
	if user, err = decode(p[0]); err != nil {
		return "", "", err
	}
	aud, err = decode(p[1])
	return user, aud, err
}

// NewTicket returns a short-lived, single-use ticket granting a session on host aud.
func (s *Sessions) NewTicket(user, aud string) string {
	n := make([]byte, 16)
	_, _ = rand.Read(n)
	return s.token("t", user, aud, ticketTTL, b64.EncodeToString(n))
}

// VerifyTicket returns the ticket's user, audience, nonce and expiry if it is valid.
func (s *Sessions) VerifyTicket(v string) (user, aud, nonce string, exp time.Time, err error) {
	p, exp, err := s.parse("t", v, 4)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	if user, err = decode(p[0]); err != nil {
		return "", "", "", time.Time{}, err
	}
	if aud, err = decode(p[1]); err != nil {
		return "", "", "", time.Time{}, err
	}
	return user, aud, p[3], exp, nil
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
