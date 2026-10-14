package main

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ParseTrustedProxies parses a comma-separated list of IP addresses and CIDR ranges.
func ParseTrustedProxies(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err != nil {
				return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", e, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("invalid TRUSTED_PROXIES entry %q: %w", e, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// peerAddr returns the address of the directly connected peer.
func peerAddr(r *http.Request) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(r.RemoteAddr); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

func (c *Config) trusts(a netip.Addr) bool {
	for _, p := range c.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// fromTrusted reports whether the request comes from a declared proxy (TRUSTED_PROXIES).
// X-Forwarded-* headers are only believed in that case, never by default.
func (a *App) fromTrusted(r *http.Request) bool {
	peer, ok := peerAddr(r)
	return ok && a.cfg.trusts(peer)
}

// clientIP returns the address of the real client: the peer itself, or, when the peer is a trusted proxy,
// the right-most X-Forwarded-For entry that is not itself a trusted proxy. A malformed header is ignored.
func (a *App) clientIP(r *http.Request) netip.Addr {
	peer, ok := peerAddr(r)
	if !ok {
		return netip.Addr{}
	}
	if !a.cfg.trusts(peer) {
		return peer
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			return peer
		}
		if ip = ip.Unmap(); !a.cfg.trusts(ip) {
			return ip
		}
	}
	return peer
}

// forwarded returns an X-Forwarded-* style header, but only when the request comes from a trusted proxy.
func (a *App) forwarded(r *http.Request, name string) string {
	if !a.fromTrusted(r) {
		return ""
	}
	return r.Header.Get(name)
}

// scheme is "https" when the connection is TLS or a trusted proxy says the client used HTTPS.
func (a *App) scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if p := strings.ToLower(strings.TrimSpace(a.forwarded(r, "X-Forwarded-Proto"))); p == "https" || p == "http" {
		return p
	}
	return "http"
}

// secureSite: the Secure flag of a protected site's cookie.
func (a *App) secureSite(r *http.Request) bool {
	return a.cfg.CookieSecure == "true" || (a.cfg.CookieSecure == "auto" && a.scheme(r) == "https")
}

// secureLogin: the Secure flag of the login host's cookie (also set when the login page is declared as https).
func (a *App) secureLogin(r *http.Request) bool {
	return a.secureSite(r) || (a.cfg.CookieSecure == "auto" && a.cfg.LoginURL != nil && a.cfg.LoginURL.Scheme == "https")
}
