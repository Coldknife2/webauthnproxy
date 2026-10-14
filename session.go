package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const cookieName = "wap_session"

// Sessions: stateless HMAC-signed cookie (name.expiry.signature).
type Sessions struct {
	secret []byte
	ttl    time.Duration
}

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

func (s *Sessions) sign(payload string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(payload))
	return b64.EncodeToString(m.Sum(nil))
}

func (s *Sessions) New(userName string) string {
	payload := b64.EncodeToString([]byte(userName)) + "." +
		strconv.FormatInt(time.Now().Add(s.ttl).Unix(), 10)
	return payload + "." + s.sign(payload)
}

// Verify returns the user name if the cookie is valid.
func (s *Sessions) Verify(v string) (string, error) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", errors.New("format")
	}
	payload := parts[0] + "." + parts[1]
	if !hmac.Equal([]byte(parts[2]), []byte(s.sign(payload))) {
		return "", errors.New("signature")
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", errors.New("expired")
	}
	name, err := b64.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	return string(name), nil
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
