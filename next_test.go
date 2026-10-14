package main

import (
	"net/url"
	"testing"
)

func TestSafeNext(t *testing.T) {
	lu, _ := url.Parse("https://auth.example.com/_wap/login")
	fwd := &App{cfg: &Config{Mode: "forward", CookieDomain: "example.com", LoginURL: lu}}
	px := &App{cfg: &Config{Mode: "proxy"}}
	cases := []struct {
		a    *App
		in   string
		want string
	}{
		{px, "/x?y=1", "/x?y=1"},
		{px, "//evil.com", "/"},
		{px, `/\evil.com`, "/"},
		{px, "https://example.com/", "/"}, // absolute URL forbidden outside forward mode
		{fwd, "https://app.example.com/a?b=1", "https://app.example.com/a?b=1"},
		{fwd, "https://example.com/", "https://example.com/"},
		{fwd, "https://evilexample.com/", "/"},
		{fwd, "https://example.com.evil.com/", "/"},
		{fwd, "javascript:alert(1)", "/"},
		{fwd, "", "/"},
	}
	for _, c := range cases {
		if got := c.a.safeNext(c.in); got != c.want {
			t.Errorf("safeNext(%q) = %q, expected %q", c.in, got, c.want)
		}
	}
}
