package main

import (
	"testing"
	"time"
)

func TestSessionRoundTrip(t *testing.T) {
	s := &Sessions{secret: []byte("0123456789abcdef"), ttl: time.Hour}
	name, err := s.Verify(s.New("remi"))
	if err != nil || name != "remi" {
		t.Fatalf("got %q, %v", name, err)
	}
}

func TestSessionRejects(t *testing.T) {
	s := &Sessions{secret: []byte("0123456789abcdef"), ttl: time.Hour}
	tok := s.New("remi")
	other := &Sessions{secret: []byte("fedcba9876543210"), ttl: time.Hour}
	if _, err := other.Verify(tok); err == nil {
		t.Error("signature d'un autre secret acceptée")
	}
	if _, err := s.Verify(tok + "x"); err == nil {
		t.Error("signature altérée acceptée")
	}
	expired := &Sessions{secret: s.secret, ttl: -time.Minute}
	if _, err := s.Verify(expired.New("remi")); err == nil {
		t.Error("session expirée acceptée")
	}
}

func TestCeremonyOneShot(t *testing.T) {
	c := NewCeremonies[string]()
	id := c.Put("x")
	if v, ok := c.Take(id); !ok || v != "x" {
		t.Fatal("première lecture échouée")
	}
	if _, ok := c.Take(id); ok {
		t.Fatal("cérémonie réutilisable")
	}
}
