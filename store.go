package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// User implements webauthn.User.
type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	Gen         int64                 `json:"gen,omitempty"` // session generation: bumped to revoke all sessions
	Credentials []webauthn.Credential `json:"credentials"`
}

func (u *User) WebAuthnID() []byte                         { return u.ID }
func (u *User) WebAuthnName() string                       { return u.Name }
func (u *User) WebAuthnDisplayName() string                { return u.Name }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

// Store is a single-file JSON database, written atomically.
type Store struct {
	mu    sync.RWMutex
	path  string
	Users []*User `json:"users"`
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "users.json")}
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	return s, nil
}

// save must be called with s.mu write-locked.
func (s *Store) save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) clone(u *User) *User {
	c := *u
	c.Credentials = append([]webauthn.Credential(nil), u.Credentials...)
	return &c
}

func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Users)
}

func (s *Store) List() []*User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*User, 0, len(s.Users))
	for _, u := range s.Users {
		out = append(out, s.clone(u))
	}
	return out
}

func (s *Store) ByName(name string) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Name == name {
			return s.clone(u)
		}
	}
	return nil
}

// Gen returns the user's session generation and whether the user exists, without copying it (hot path).
func (s *Store) Gen(name string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if u.Name == name {
			return u.Gen, true
		}
	}
	return 0, false
}

// Revoke invalidates every session and ticket issued so far for the user ("sign out everywhere").
func (s *Store) Revoke(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u.Name == name {
			u.Gen++
			return s.save()
		}
	}
	return nil
}

func (s *Store) ByID(id []byte) *User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.Users {
		if string(u.ID) == string(id) {
			return s.clone(u)
		}
	}
	return nil
}

// ErrDuplicate is returned when the passkey is already registered.
var ErrDuplicate = errors.New("passkey already registered")

// userIDFor derives the user handle from the name: the same name always designates the same
// user, whichever enrollment tool is used (automatic or file import).
func userIDFor(name string) []byte {
	h := sha256.Sum256([]byte("webauthnproxy:user:" + name))
	return h[:]
}

// GetOrNew returns the user (a copy); it is only persisted by AddCredential.
func (s *Store) GetOrNew(name string) *User {
	if u := s.ByName(name); u != nil {
		return u
	}
	return &User{ID: userIDFor(name), Name: name}
}

// CredentialCount returns the total number of passkeys.
func (s *Store) CredentialCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, u := range s.Users {
		n += len(u.Credentials)
	}
	return n
}

func (s *Store) AddCredential(u *User, c *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var cur *User
	for _, x := range s.Users {
		for i := range x.Credentials {
			if string(x.Credentials[i].ID) == string(c.ID) {
				return ErrDuplicate
			}
		}
		if string(x.ID) == string(u.ID) {
			cur = x
		}
	}
	if cur == nil {
		cur = &User{ID: u.ID, Name: u.Name}
		s.Users = append(s.Users, cur)
	}
	cur.Credentials = append(cur.Credentials, *c)
	return s.save()
}

// UpdateCredential stores the updated credential (signature counter, flags) after a login.
func (s *Store) UpdateCredential(userID []byte, c *webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if string(u.ID) != string(userID) {
			continue
		}
		for i := range u.Credentials {
			if string(u.Credentials[i].ID) == string(c.ID) {
				u.Credentials[i] = *c
				return s.save()
			}
		}
	}
	return nil
}

// DeleteCredential removes a passkey; the user disappears when none is left.
func (s *Store) DeleteCredential(userID, credID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, u := range s.Users {
		if string(u.ID) != string(userID) {
			continue
		}
		var keep []webauthn.Credential
		for _, c := range u.Credentials {
			if string(c.ID) != string(credID) {
				keep = append(keep, c)
			}
		}
		u.Credentials = keep
		if len(keep) == 0 {
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
		}
		return s.save()
	}
	return nil
}
