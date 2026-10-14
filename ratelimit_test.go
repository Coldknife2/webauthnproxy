package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	for in, want := range map[string]RateSpec{
		"20/1m": {20, time.Minute}, "100/1h": {100, time.Hour}, "30": {30, time.Minute}, " 5/30s ": {5, 30 * time.Second},
		"0": {}, "off": {}, "": {},
	} {
		got, err := ParseRate(in)
		if err != nil || got != want {
			t.Errorf("ParseRate(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"abc", "10/zz", "-1/1m", "10/-1m", "10/0s"} {
		if _, err := ParseRate(bad); err == nil {
			t.Errorf("ParseRate(%q) accepted", bad)
		}
	}
}

func fakeClockLimiter(spec RateSpec) (*Limiter, *time.Time) {
	now := time.Unix(1_000_000, 0)
	l := NewLimiter(spec)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestLimiterBurstRefillAndIsolation(t *testing.T) {
	l, now := fakeClockLimiter(RateSpec{3, time.Minute})
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, retry := l.Allow("a")
	if ok || retry <= 0 || retry > 21*time.Second {
		t.Fatalf("4th request: ok=%v retry=%v (one token takes 20 s)", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("another client must not be affected")
	}
	*now = now.Add(21 * time.Second) // one token refilled
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("no refill after waiting")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("only one token should have refilled")
	}
	*now = now.Add(time.Hour) // never more than the burst
	for i := 0; i < 3; i++ {
		l.Allow("a")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("the bucket refilled beyond its burst")
	}
}

func TestLimiterDisabledAndNil(t *testing.T) {
	var nilLimiter *Limiter
	for i := 0; i < 1000; i++ {
		if ok, _ := nilLimiter.Allow("x"); !ok {
			t.Fatal("nil limiter refused")
		}
		if ok, _ := NewLimiter(RateSpec{}).Allow("x"); !ok {
			t.Fatal("disabled limiter refused")
		}
	}
}

func TestLimiterMemoryIsBounded(t *testing.T) {
	l, _ := fakeClockLimiter(RateSpec{1, time.Hour})
	for i := 0; i < maxBuckets*3; i++ {
		l.Allow("k" + strconv.Itoa(i)) // every key is "busy" (its single token is spent)
	}
	if n := len(l.buckets); n > maxBuckets {
		t.Fatalf("%d buckets kept, limit is %d", n, maxBuckets)
	}
}

func TestRateKeyGroupsIPv6By64(t *testing.T) {
	a := rateKey(netip.MustParseAddr("2001:db8:1:2::1"))
	b := rateKey(netip.MustParseAddr("2001:db8:1:2:ffff:ffff:ffff:ffff"))
	c := rateKey(netip.MustParseAddr("2001:db8:1:3::1"))
	if a != b || a == c {
		t.Errorf("/64 grouping wrong: %s %s %s", a, b, c)
	}
	if rateKey(netip.MustParseAddr("192.0.2.1")) != "192.0.2.1" || rateKey(netip.Addr{}) != "unknown" {
		t.Error("IPv4 / invalid keys wrong")
	}
}

func limitedApp(t *testing.T, ip, global RateSpec, trusted string) *App {
	a := testApp(t)
	a.cfg.RateLimitIP, a.cfg.RateLimitGlobal = ip, global
	a.ipLimit, a.globalLimit = NewLimiter(ip), NewLimiter(global)
	if trusted != "" {
		a.cfg.TrustedProxies = mustTrust(trusted)
	}
	return a
}

func post(h http.Handler, path, peer string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
	r.RemoteAddr = peer
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestLoginEndpointsAnswer429(t *testing.T) {
	a := limitedApp(t, RateSpec{3, time.Minute}, RateSpec{}, "")
	h := a.publicHandler()
	for i := 0; i < 3; i++ {
		if w := post(h, "/_wap/login/begin", "203.0.113.7:1", nil); w.Code != 200 {
			t.Fatalf("request %d: %d", i+1, w.Code)
		}
	}
	w := post(h, "/_wap/login/begin", "203.0.113.7:1", nil)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("4th request: %d, Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := post(h, "/_wap/login/finish?cid=x", "203.0.113.7:1", nil); w.Code != 429 {
		t.Fatalf("login/finish shares the client's budget: %d", w.Code)
	}
	if w := post(h, "/_wap/login/begin", "203.0.113.8:1", nil); w.Code != 200 {
		t.Fatalf("a different client was limited: %d", w.Code)
	}
}

func TestForgedForwardedForDoesNotDodgeTheLimit(t *testing.T) {
	a := limitedApp(t, RateSpec{2, time.Minute}, RateSpec{}, "10.0.0.0/8")
	h := a.publicHandler()
	var last int
	for i := 0; i < 6; i++ {
		// the attacker connects directly (untrusted) and invents a new client address every time
		last = post(h, "/_wap/login/begin", "203.0.113.7:1", map[string]string{"X-Forwarded-For": "198.51.100." + strconv.Itoa(i+1)}).Code
	}
	if last != 429 {
		t.Fatalf("a forged X-Forwarded-For gave a fresh budget: %d", last)
	}
}

func TestTrustedProxyGivesEachClientItsOwnBudget(t *testing.T) {
	a := limitedApp(t, RateSpec{2, time.Minute}, RateSpec{}, "10.0.0.0/8")
	h := a.publicHandler()
	for i := 0; i < 2; i++ {
		post(h, "/_wap/login/begin", "10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.1"})
	}
	if w := post(h, "/_wap/login/begin", "10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.1"}); w.Code != 429 {
		t.Fatalf("client 1 not limited: %d", w.Code)
	}
	if w := post(h, "/_wap/login/begin", "10.0.0.2:1", map[string]string{"X-Forwarded-For": "198.51.100.2"}); w.Code != 200 {
		t.Fatalf("client 2 shares client 1's budget behind the proxy: %d", w.Code)
	}
}

func TestGlobalLimit(t *testing.T) {
	a := limitedApp(t, RateSpec{}, RateSpec{4, time.Minute}, "")
	h := a.publicHandler()
	codes := []int{}
	for i := 0; i < 6; i++ {
		codes = append(codes, post(h, "/_wap/login/begin", "203.0.113."+strconv.Itoa(i+1)+":1", nil).Code)
	}
	if codes[3] != 200 || codes[4] != 429 || codes[5] != 429 {
		t.Fatalf("global limit not applied across clients: %v", codes)
	}
}

func TestEnrollmentEndpointsAreRateLimitedToo(t *testing.T) {
	a := limitedApp(t, RateSpec{2, time.Minute}, RateSpec{}, "")
	h := a.enrollHandler()
	hdr := map[string]string{"X-Requested-With": "wap", "X-Bootstrap-Token": a.bootstrapToken()}
	for i := 0; i < 2; i++ {
		post(h, "/api/register/begin", "203.0.113.7:1", hdr)
	}
	if w := post(h, "/api/register/begin", "203.0.113.7:1", hdr); w.Code != 429 {
		t.Fatalf("register/begin not limited: %d", w.Code)
	}
	if w := post(h, "/_wap/login/begin", "203.0.113.7:1", nil); w.Code != 429 {
		t.Fatalf("the enrollment host's login shares the budget: %d", w.Code)
	}
}
