package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config est lu uniquement depuis les variables d'environnement.
type Config struct {
	Mode           string        // MODE : "proxy" (défaut) ou "forward" (forwardAuth Traefik)
	LoginURL       *url.URL      // LOGIN_URL (mode forward) : URL publique de la page de login
	CookieDomain   string        // COOKIE_DOMAIN (mode forward) : domaine parent du cookie de session
	Upstream       *url.URL      // UPSTREAM (mode proxy) : site à protéger
	Listen         string        // LISTEN : port public du proxy
	EnrollEnabled  bool          // ENROLL_ENABLED : active le endpoint d'enrôlement
	EnrollListen   string        // ENROLL_LISTEN : port privé d'enrôlement
	EnrollPassword string        // ENROLL_PASSWORD : mot de passe basic-auth optionnel (user: admin)
	RPID           string        // RP_ID : domaine WebAuthn (ex: example.com)
	RPName         string        // RP_NAME
	RPOrigins      []string      // RP_ORIGINS : origines autorisées (ex: https://app.example.com)
	DataDir        string        // DATA_DIR
	SessionSecret  []byte        // SESSION_SECRET (sinon généré et stocké dans DATA_DIR)
	SessionTTL     time.Duration // SESSION_TTL
	PreserveHost   bool          // PRESERVE_HOST : transmet le Host d'origine à l'upstream
	UserHeader     string        // USER_HEADER : header envoyé à l'upstream avec le nom de l'utilisateur
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
		Listen:         getenv("LISTEN", ":8080"),
		EnrollEnabled:  getbool("ENROLL_ENABLED"),
		EnrollListen:   getenv("ENROLL_LISTEN", ":8081"),
		EnrollPassword: os.Getenv("ENROLL_PASSWORD"),
		RPID:           getenv("RP_ID", ""),
		RPName:         getenv("RP_NAME", "WebAuthn Proxy"),
		DataDir:        getenv("DATA_DIR", "/data"),
		PreserveHost:   getbool("PRESERVE_HOST"),
		UserHeader:     getenv("USER_HEADER", "X-Authenticated-User"),
	}

	c.Mode = getenv("MODE", "proxy")
	switch c.Mode {
	case "proxy":
		up := getenv("UPSTREAM", "")
		if up == "" {
			return nil, fmt.Errorf("UPSTREAM est obligatoire en mode proxy (ex: http://monsite:80)")
		}
		u, err := url.Parse(up)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("UPSTREAM invalide: %q", up)
		}
		c.Upstream = u
	case "forward":
		lu, err := url.Parse(getenv("LOGIN_URL", ""))
		if err != nil || (lu.Scheme != "http" && lu.Scheme != "https") || lu.Host == "" {
			return nil, fmt.Errorf("LOGIN_URL est obligatoire en mode forward (ex: https://auth.example.com/_wap/login)")
		}
		c.LoginURL = lu
		c.CookieDomain = strings.ToLower(strings.TrimPrefix(getenv("COOKIE_DOMAIN", ""), "."))
		if c.CookieDomain == "" {
			return nil, fmt.Errorf("COOKIE_DOMAIN est obligatoire en mode forward (ex: example.com)")
		}
	default:
		return nil, fmt.Errorf("MODE invalide: %q (proxy ou forward)", c.Mode)
	}

	if c.RPID == "" {
		return nil, fmt.Errorf("RP_ID est obligatoire (domaine, ex: example.com ou localhost)")
	}
	for _, o := range strings.Split(os.Getenv("RP_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			c.RPOrigins = append(c.RPOrigins, o)
		}
	}
	if len(c.RPOrigins) == 0 {
		return nil, fmt.Errorf("RP_ORIGINS est obligatoire (liste séparée par des virgules, ex: https://app.example.com)")
	}

	ttl, err := time.ParseDuration(getenv("SESSION_TTL", "12h"))
	if err != nil || ttl <= 0 {
		return nil, fmt.Errorf("SESSION_TTL invalide")
	}
	c.SessionTTL = ttl

	if s := os.Getenv("SESSION_SECRET"); s != "" {
		if len(s) < 16 {
			return nil, fmt.Errorf("SESSION_SECRET trop court (16 caractères minimum)")
		}
		c.SessionSecret = []byte(s)
	}
	return c, nil
}
