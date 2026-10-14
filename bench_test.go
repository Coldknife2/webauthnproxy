package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// nullWriter is a ResponseWriter that discards the body, so the benchmark measures the handler only.
type nullWriter struct {
	h    http.Header
	code int
}

func (n *nullWriter) Header() http.Header         { return n.h }
func (n *nullWriter) Write(b []byte) (int, error) { return len(b), nil }
func (n *nullWriter) WriteHeader(code int)        { n.code = code }

// BenchmarkVerify measures the forwardAuth hot path: one authenticated check per request.
func BenchmarkVerify(b *testing.B) {
	a := forwardApp(b)
	addUser(b, a)
	h := a.publicHandler()
	r := httptest.NewRequest("GET", "/_wap/verify", nil)
	r.Header.Set("X-Forwarded-Host", "anysite.com")
	r.Header.Set("X-Forwarded-Uri", "/page?x=1")
	r.Header.Set("Cookie", cookieName+"="+mk(a, "remi", "anysite.com"))
	w := &nullWriter{h: http.Header{}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.code = 0
		h.ServeHTTP(w, r)
		if w.code != http.StatusOK {
			b.Fatalf("status %d", w.code)
		}
	}
}

// BenchmarkSessionVerify isolates the session check (SHA-256 of the token + table lookup + user lookup).
func BenchmarkSessionVerify(b *testing.B) {
	a := testApp(b)
	addUser(b, a)
	r := requestWithCookie(mk(a, "remi", ""))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := a.sessionFor(r); !ok {
			b.Fatal("session refused")
		}
	}
}
