package main

import (
	"crypto/sha256"
	"net/http"
	"strings"
	"time"
)

// Same algorithm as the application: SHA-256 of the cookie value, lookup in a table of sessions (here one entry,
// seeded at start like the benchmark seeds sessions.json), audience and expiry checks, user lookup.
type sess struct {
	user, aud string
	exp       int64
}

const token = "benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var table = map[[32]byte]sess{sha256.Sum256([]byte(token)): {"bench", "app.example.com", time.Now().Unix() + 86400}}
var users = map[string]bool{"bench": true}

func check(r *http.Request) string {
	host := strings.ToLower(r.Header.Get("X-Forwarded-Host"))
	if host != "app.example.com" {
		return ""
	}
	c, err := r.Cookie("wap_session")
	if err != nil {
		return ""
	}
	s, ok := table[sha256.Sum256([]byte(c.Value))]
	if !ok || s.aud != host || s.exp < time.Now().Unix() || !users[s.user] {
		return ""
	}
	return s.user
}

func main() {
	http.HandleFunc("/_wap/verify", func(w http.ResponseWriter, r *http.Request) {
		if u := check(r); u != "" {
			w.Header().Set("X-Authenticated-User", u)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	})
	_ = http.ListenAndServe(":8080", nil)
}
