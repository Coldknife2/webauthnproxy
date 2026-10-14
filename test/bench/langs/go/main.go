package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var secret = []byte("bench-secret-0123456789abcdef0123456789")
var b64 = base64.RawURLEncoding

func dec(s string) string { b, _ := b64.DecodeString(s); return string(b) }

func check(r *http.Request) string {
	host := strings.ToLower(r.Header.Get("X-Forwarded-Host"))
	if host != "app.example.com" {
		return ""
	}
	c, err := r.Cookie("wap_session")
	if err != nil {
		return ""
	}
	i := strings.LastIndexByte(c.Value, '.')
	if i < 0 {
		return ""
	}
	payload := c.Value[:i]
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("s|" + payload))
	got, err := b64.DecodeString(c.Value[i+1:])
	if err != nil || !hmac.Equal(got, m.Sum(nil)) {
		return ""
	}
	f := strings.Split(payload, ".")
	if len(f) != 5 {
		return ""
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || exp < time.Now().Unix() || dec(f[1]) != host {
		return ""
	}
	if user := dec(f[0]); user == "bench" { // user lookup (in-memory set of one)
		return user
	}
	return ""
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
