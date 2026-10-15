package main

import (
	"strings"
	"testing"
	"time"

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

func TestPasskeyLabelsAndDates(t *testing.T) {
	dir := t.TempDir()
	s, _ := OpenStore(dir)
	u := s.GetOrNew("remi")
	before := time.Now().Unix()
	if err := s.AddCredentialLabeled(u, &webauthn.Credential{ID: []byte("phone-id")}, "  phone "); err != nil {
		t.Fatal(err)
	}
	if err := s.AddCredential(u, &webauthn.Credential{ID: []byte("key-id")}); err != nil {
		t.Fatal(err)
	}
	m := s.ByName("remi").Meta[b64.EncodeToString([]byte("phone-id"))]
	if m.Label != "phone" || m.Created < before || m.Created > time.Now().Unix() {
		t.Fatalf("meta = %+v", m)
	}
	if k := s.ByName("remi").Meta[b64.EncodeToString([]byte("key-id"))]; k.Label != "" || k.Created == 0 {
		t.Fatalf("unlabelled passkey: %+v", k)
	}
	// persisted
	again, _ := OpenStore(dir)
	if again.ByName("remi").Meta[b64.EncodeToString([]byte("phone-id"))].Label != "phone" {
		t.Fatal("label lost on reload")
	}
	// relabel, and the copy handed out is independent
	if err := s.SetLabel(u.ID, []byte("key-id"), "USB key"); err != nil {
		t.Fatal(err)
	}
	cp := s.ByName("remi")
	cp.Meta[b64.EncodeToString([]byte("key-id"))] = CredMeta{Label: "tampered"}
	if s.ByName("remi").Meta[b64.EncodeToString([]byte("key-id"))].Label != "USB key" {
		t.Fatal("a copy of the user shares the metadata map")
	}
	// deleting the passkey deletes its metadata
	if err := s.DeleteCredential(u.ID, []byte("phone-id")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.ByName("remi").Meta[b64.EncodeToString([]byte("phone-id"))]; ok {
		t.Fatal("metadata of a deleted passkey kept")
	}
	if err := s.SetLabel(u.ID, []byte("missing"), "x"); err == nil {
		t.Fatal("labelling an unknown passkey succeeded")
	}
}

func TestCleanLabel(t *testing.T) {
	for in, want := range map[string]string{"": "", "  phone ": "phone", "clé USB ✔": "clé USB ✔", strings.Repeat("é", 40): strings.Repeat("é", 40)} {
		if got, err := CleanLabel(in); err != nil || got != want {
			t.Errorf("CleanLabel(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"line\nbreak", "tab\there", "nul\x00", "\x7f", strings.Repeat("a", 41)} {
		if _, err := CleanLabel(bad); err == nil {
			t.Errorf("CleanLabel(%q) accepted", bad)
		}
	}
}
