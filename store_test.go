package main

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

func TestStorePersistence(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	u := s.GetOrNew("remi")
	if err := s.AddCredential(u, &webauthn.Credential{ID: []byte("c1")}); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(dir)
	if err != nil || s2.ByName("remi") == nil || len(s2.ByName("remi").Credentials) != 1 {
		t.Fatalf("reload failed: %v", err)
	}
	if err := s2.DeleteCredential(u.ID, []byte("c1")); err != nil {
		t.Fatal(err)
	}
	if s2.Count() != 0 {
		t.Fatal("user without passkey kept")
	}
}
