package main

import (
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), nil, time.Hour, 0)
	name, aud, gen, err := s.Verify(s.New("remi", "app.example.com", 7))
	if err != nil || name != "remi" || aud != "app.example.com" || gen != 7 {
		t.Fatalf("got %q %q %d, %v", name, aud, gen, err)
	}
	if _, aud, _, _ := s.Verify(s.New("remi", "", 0)); aud != "" {
		t.Fatalf("empty audience came back as %q", aud)
	}
}

func TestSessionRejects(t *testing.T) {
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), nil, time.Hour, 0)
	tok := s.New("remi", "", 0)
	other := NewSessions([]byte("fedcba9876543210fedcba9876543210"), nil, time.Hour, 0)
	if _, _, _, err := other.Verify(tok); err == nil {
		t.Error("signature from another secret accepted")
	}
	if _, _, _, err := s.Verify(tok + "x"); err == nil {
		t.Error("tampered signature accepted")
	}
	expired := NewSessions(s.keys[0], nil, -time.Minute, 0)
	if _, _, _, err := s.Verify(expired.New("remi", "", 0)); err == nil {
		t.Error("expired session accepted")
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

func TestTicket(t *testing.T) {
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), nil, time.Hour, 0)
	user, aud, gen, nonce, _, err := s.VerifyTicket(s.NewTicket("remi", "app.example.com", 3))
	if err != nil || user != "remi" || aud != "app.example.com" || gen != 3 || nonce == "" {
		t.Fatalf("got %q %q %d %q, %v", user, aud, gen, nonce, err)
	}
	// a session cookie is not a ticket, and a ticket is not a session cookie
	if _, _, _, _, _, err := s.VerifyTicket(s.New("remi", "app.example.com", 0)); err == nil {
		t.Error("session accepted as ticket")
	}
	if _, _, _, err := s.Verify(s.NewTicket("remi", "app.example.com", 0)); err == nil {
		t.Error("ticket accepted as session")
	}
	// tickets are short-lived
	old := s.token("t", "remi", "x", time.Now().Add(-time.Second), 0, "n")
	if _, _, _, _, _, err := s.VerifyTicket(old); err == nil {
		t.Error("expired ticket accepted")
	}
}

func TestSeenRejectsReplay(t *testing.T) {
	var s Seen
	exp := time.Now().Add(time.Minute)
	if !s.Mark("n1", exp) || s.Mark("n1", exp) || !s.Mark("n2", exp) {
		t.Fatal("replay detection wrong")
	}
}
