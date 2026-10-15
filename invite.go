package main

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

// One-time invitations to add a passkey to a user from another device, without opening the enrolment port.
//
// An administrator with access to the container creates one (`webauthnproxy passkeys add <user>`); the link it prints
// carries a random code in the URL *fragment* (so it never reaches a server log or a Referer header). The page uses
// the code to register a passkey for that user, once, within inviteTTL. Only the hash of the code is kept, in memory:
// a restart cancels pending invitations.

const (
	inviteTTL  = 15 * time.Minute
	maxInvites = 20
)

type invite struct {
	user, label string
	exp         time.Time
}

type Invites struct {
	mu  sync.Mutex
	m   map[hash32]invite
	now func() time.Time
}

func NewInvites() *Invites { return &Invites{m: map[hash32]invite{}, now: time.Now} }

// Create returns a new code for user (label may be empty).
func (v *Invites) Create(user, label string) (code string, exp time.Time, err error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	code = b64.EncodeToString(b)
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for h, i := range v.m {
		if !now.Before(i.exp) {
			delete(v.m, h)
		}
	}
	if len(v.m) >= maxInvites {
		return "", time.Time{}, errors.New("too many pending invitations")
	}
	exp = now.Add(inviteTTL)
	v.m[sha256.Sum256([]byte(code))] = invite{user, label, exp}
	return code, exp, nil
}

// Peek returns the invitation for a code if it is still valid, without using it.
func (v *Invites) Peek(code string) (invite, bool) {
	if code == "" {
		return invite{}, false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	i, ok := v.m[sha256.Sum256([]byte(code))]
	if !ok || !v.now().Before(i.exp) {
		return invite{}, false
	}
	return i, true
}

// Consume uses the invitation: true only the first time, while it is valid.
func (v *Invites) Consume(code string) bool {
	h := sha256.Sum256([]byte(code))
	v.mu.Lock()
	defer v.mu.Unlock()
	i, ok := v.m[h]
	delete(v.m, h)
	return ok && v.now().Before(i.exp)
}
