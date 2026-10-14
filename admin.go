package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Local administration: list and revoke passkeys, sign a user out everywhere, without editing users.json.
//
// The running server listens on a Unix socket, DATA_DIR/admin.sock, created with mode 0600. Reaching it requires
// access to the data volume, which is already the level of trust needed to import a passkey or recover an account.
// Nothing is exposed on the network. The command line client talks to that socket:
//
//	docker exec webauthnproxy /webauthnproxy passkeys list
//	docker exec webauthnproxy /webauthnproxy passkeys revoke <id>
//	docker exec webauthnproxy /webauthnproxy signout <user>

const adminSocket = "admin.sock"

type passkeyInfo struct {
	User       string   `json:"user"`
	ID         string   `json:"id"` // short non-secret tag, same value as the audit log's "credential"
	Transports []string `json:"transports,omitempty"`
	SignCount  uint32   `json:"signCount"`
	Synced     bool     `json:"synced"` // backup-eligible: a synced passkey, not bound to one device
}

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /passkeys", func(w http.ResponseWriter, r *http.Request) {
		out := []passkeyInfo{}
		for _, u := range a.store.List() {
			for _, c := range u.Credentials {
				p := passkeyInfo{User: u.Name, ID: credTag(c.ID), SignCount: c.Authenticator.SignCount, Synced: c.Flags.BackupEligible}
				for _, t := range c.Transport {
					p.Transports = append(p.Transports, string(t))
				}
				out = append(out, p)
			}
		}
		writeJSON(w, 200, out)
	})
	mux.HandleFunc("DELETE /passkeys/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if len(id) < 6 {
			jsonErr(w, 400, "give at least 6 characters of the id shown by 'passkeys list'")
			return
		}
		var user *User
		var cred []byte
		n := 0
		for _, u := range a.store.List() {
			for _, c := range u.Credentials {
				if strings.HasPrefix(credTag(c.ID), id) {
					user, cred, n = u, c.ID, n+1
				}
			}
		}
		switch {
		case n == 0:
			jsonErr(w, 404, "no passkey with that id")
		case n > 1:
			jsonErr(w, 409, "several passkeys match, give more characters")
		case a.store.CredentialCount() <= 1:
			jsonErr(w, 409, "cannot delete the last passkey (this would lock you out); see docs/enrollment.md to recover")
		default:
			if err := a.store.DeleteCredential(user.ID, cred); err != nil {
				jsonErr(w, 500, err.Error())
				return
			}
			// the passkey is gone; sessions it opened are not tied to it, so end them too
			if err := a.store.Revoke(user.Name); err != nil {
				jsonErr(w, 500, err.Error())
				return
			}
			a.audit.Event("credential_deleted", "user", user.Name, "credential", credTag(cred), "via", "cli")
			writeJSON(w, 200, map[string]string{"ok": "true", "user": user.Name})
		}
	})
	mux.HandleFunc("POST /users/{name}/signout", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if _, ok := a.store.Gen(name); !ok {
			jsonErr(w, 404, "no such user")
			return
		}
		if err := a.store.Revoke(name); err != nil {
			jsonErr(w, 500, err.Error())
			return
		}
		a.audit.Event("sign_out", "user", name, "via", "cli")
		writeJSON(w, 200, map[string]string{"ok": "true"})
	})
	return mux
}

// listenAdmin opens DATA_DIR/admin.sock (mode 0600) and serves the admin handler on it.
func listenAdmin(dir string, h http.Handler) (*http.Server, error) {
	path := filepath.Join(dir, adminSocket)
	_ = os.Remove(path) // stale socket of a previous run
	old := umaskRestrictive()
	l, err := net.Listen("unix", path)
	old()
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	s := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.Serve(l) }()
	return s, nil
}

// ---- command line client

func adminClient(dir string) *http.Client {
	path := filepath.Join(dir, adminSocket)
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}}
}

func adminCall(dir, method, path string) ([]byte, error) {
	req, _ := http.NewRequest(method, "http://admin"+path, nil)
	resp, err := adminClient(dir).Do(req)
	if err != nil {
		return nil, fmt.Errorf("cannot reach the running service (is it started, and is DATA_DIR=%s the same folder?): %w", dir, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		var e struct{ Error string }
		_ = json.Unmarshal(b, &e)
		if e.Error == "" {
			e.Error = resp.Status
		}
		return nil, errors.New(e.Error)
	}
	return b, nil
}

// runCLI executes a command line subcommand; handled reports whether args was one.
func runCLI(args []string, dir string, out io.Writer) (handled bool, err error) {
	if len(args) == 0 {
		return false, nil
	}
	switch args[0] {
	case "passkeys":
		if len(args) == 2 && args[1] == "list" {
			b, err := adminCall(dir, "GET", "/passkeys")
			if err != nil {
				return true, err
			}
			var ps []passkeyInfo
			if err := json.Unmarshal(b, &ps); err != nil {
				return true, err
			}
			if len(ps) == 0 {
				fmt.Fprintln(out, "no passkey registered")
			}
			for _, p := range ps {
				kind := "device-bound"
				if p.Synced {
					kind = "synced"
				}
				fmt.Fprintf(out, "%-12s  user=%s  %s  transports=%s  uses=%d\n", p.ID, p.User, kind, strings.Join(p.Transports, ","), p.SignCount)
			}
			return true, nil
		}
		if len(args) == 3 && args[1] == "revoke" {
			b, err := adminCall(dir, "DELETE", "/passkeys/"+url.PathEscape(args[2]))
			if err != nil {
				return true, err
			}
			var r struct{ User string }
			_ = json.Unmarshal(b, &r)
			fmt.Fprintf(out, "passkey revoked; sessions of %s ended\n", r.User)
			return true, nil
		}
	case "signout":
		if len(args) == 2 {
			if _, err := adminCall(dir, "POST", "/users/"+url.PathEscape(args[1])+"/signout"); err != nil {
				return true, err
			}
			fmt.Fprintf(out, "%s signed out everywhere\n", args[1])
			return true, nil
		}
	case "healthcheck":
		return true, healthcheck(getenv("LISTEN", ":8080"), out)
	default:
		return false, nil
	}
	return true, errors.New("usage: webauthnproxy passkeys list | passkeys revoke <id> | signout <user> | healthcheck")
}

// healthcheck asks the local service whether it is up; it is what the container HEALTHCHECK runs
// (the image has no shell and no curl).
func healthcheck(listen string, out io.Writer) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + prefix + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode != 200 {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	fmt.Fprintln(out, "ok")
	return nil
}
