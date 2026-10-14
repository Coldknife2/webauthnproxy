package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is read from environment variables only.
type Config struct {
	Mode          string        // MODE: "proxy" (default) or "forward" (Traefik forwardAuth)
	LoginURL      *url.URL      // LOGIN_URL (forward mode): public URL of the login page
	CookieDomain  string        // COOKIE_DOMAIN (forward mode, optional): parent domain shared by the login host and the sites
	AllowedHosts  []string      // ALLOWED_HOSTS (forward mode): sites allowed to use this login (host, host:port, *.suffix)
	Upstream      *url.URL      // UPSTREAM (proxy mode): site to protect
	Listen        string        // LISTEN: proxy port
	EnrollEnabled bool          // ENROLL_ENABLED: automatic enrollment (passkey-protected)
	EnrollListen  string        // ENROLL_LISTEN: automatic enrollment port
	ToolEnabled   bool          // TOOL_ENABLED: static enrollment tool (manual import)
	ToolListen    string        // TOOL_LISTEN: static tool port
	RPID          string        // RP_ID: WebAuthn domain (e.g. example.com)
	RPName        string        // RP_NAME
	RPOrigins     []string      // RP_ORIGINS: allowed origins (e.g. https://app.example.com)
	DataDir       string        // DATA_DIR
	SessionSecret []byte        // SESSION_SECRET (otherwise generated and stored in DATA_DIR)
	SessionTTL    time.Duration // SESSION_TTL
	PreserveHost  bool          // PRESERVE_HOST: forward the client's Host to the upstream
	UserHeader    string        // USER_HEADER: header carrying the user name to the upstream
}

func splitHost(hp string) (host, port string) {
	if h, p, err := net.SplitHostPort(hp); err == nil {
		return strings.ToLower(h), p
	}
	return strings.ToLower(hp), ""
}

// InCookieDomain reports whether host[:port] is COOKIE_DOMAIN or one of its subdomains.
func (c *Config) InCookieDomain(hostport string) bool {
	if c.CookieDomain == "" {
		return false
	}
	h, _ := splitHost(hostport)
	return h == c.CookieDomain || strings.HasSuffix(h, "."+c.CookieDomain)
}

// HostAllowed reports whether a site (host[:port]) may use this login: it is within COOKIE_DOMAIN or
// matches an ALLOWED_HOSTS entry. An entry is "host" (any port), "host:port" or "*.domain" (subdomains
// only, not the apex).
func (c *Config) HostAllowed(hostport string) bool {
	if c.InCookieDomain(hostport) {
		return true
	}
	h, p := splitHost(hostport)
	if h == "" {
		return false
	}
	for _, pat := range c.AllowedHosts {
		ph, pp := splitHost(pat)
		if pp != "" && pp != p {
			continue
		}
		if strings.HasPrefix(ph, "*.") {
			if strings.HasSuffix(h, ph[1:]) && len(h) > len(ph)-1 {
				return true
			}
		} else if ph == h {
			return true
		}
	}
	return false
}

func getenv(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func getbool(k string) bool {
	b, _ := strconv.ParseBool(os.Getenv(k))
	return b
}

func LoadConfig() (*Config, error) {
	c := &Config{
		Listen:        getenv("LISTEN", ":8080"),
		EnrollEnabled: getbool("ENROLL_ENABLED"),
		EnrollListen:  getenv("ENROLL_LISTEN", ":8081"),
		ToolEnabled:   getbool("TOOL_ENABLED"),
		ToolListen:    getenv("TOOL_LISTEN", ":8082"),
		RPID:          getenv("RP_ID", ""),
		RPName:        getenv("RP_NAME", "WebAuthn Proxy"),
		DataDir:       getenv("DATA_DIR", "/data"),
		PreserveHost:  getbool("PRESERVE_HOST"),
		UserHeader:    getenv("USER_HEADER", "X-Authenticated-User"),
	}

	c.Mode = getenv("MODE", "proxy")
	switch c.Mode {
	case "proxy":
		up := getenv("UPSTREAM", "")
		if up == "" {
			return nil, fmt.Errorf("UPSTREAM is required in proxy mode (e.g. http://mysite:80)")
		}
		u, err := url.Parse(up)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("invalid UPSTREAM: %q", up)
		}
		c.Upstream = u
	case "forward":
		lu, err := url.Parse(getenv("LOGIN_URL", ""))
		if err != nil || (lu.Scheme != "http" && lu.Scheme != "https") || lu.Host == "" {
			return nil, fmt.Errorf("LOGIN_URL is required in forward mode (e.g. https://auth.example.com/_wap/login)")
		}
		c.LoginURL = lu
		c.CookieDomain = strings.ToLower(strings.TrimPrefix(getenv("COOKIE_DOMAIN", ""), "."))
		for _, h := range strings.Split(os.Getenv("ALLOWED_HOSTS"), ",") {
			if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
				if strings.Contains(h, "/") || strings.Contains(h, " ") {
					return nil, fmt.Errorf("invalid ALLOWED_HOSTS entry %q (expected host, host:port or *.domain)", h)
				}
				c.AllowedHosts = append(c.AllowedHosts, h)
			}
		}
		if c.CookieDomain == "" && len(c.AllowedHosts) == 0 {
			return nil, fmt.Errorf("forward mode needs ALLOWED_HOSTS (e.g. anysite.com,*.example.org) and/or COOKIE_DOMAIN (e.g. example.com)")
		}
	default:
		return nil, fmt.Errorf("invalid MODE: %q (proxy or forward)", c.Mode)
	}

	if c.RPID == "" {
		return nil, fmt.Errorf("RP_ID is required (domain, e.g. example.com or localhost)")
	}
	for _, o := range strings.Split(os.Getenv("RP_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			c.RPOrigins = append(c.RPOrigins, o)
		}
	}
	if len(c.RPOrigins) == 0 {
		return nil, fmt.Errorf("RP_ORIGINS is required (comma-separated list, e.g. https://app.example.com)")
	}

	ttl, err := time.ParseDuration(getenv("SESSION_TTL", "12h"))
	if err != nil || ttl <= 0 {
		return nil, fmt.Errorf("invalid SESSION_TTL")
	}
	c.SessionTTL = ttl

	if s := os.Getenv("SESSION_SECRET"); s != "" {
		if len(s) < 16 {
			return nil, fmt.Errorf("SESSION_SECRET too short (16 characters minimum)")
		}
		c.SessionSecret = []byte(s)
	}
	return c, nil
}
