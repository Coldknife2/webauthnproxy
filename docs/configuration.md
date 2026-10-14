# Configuration

[← README](../README.md)

Everything is set through environment variables.

| Variable | Default | Description |
|---|---|---|
| `MODE` | `proxy` | `proxy` or `forward` (Traefik forwardAuth) |
| `UPSTREAM` | – | **Proxy mode.** URL of the site to protect (`http://mysite:80`) |
| `LOGIN_URL` | – | **Forward mode.** Public URL of the login page |
| `ALLOWED_HOSTS` | – | **Forward mode.** Shortlist of sites allowed to use the login: `host`, `host:port`, `*.domain`, comma-separated |
| `COOKIE_DOMAIN` | – | **Forward mode, optional.** Parent domain shared with the login host (`example.com`); its subdomains are allowed automatically. Forward mode needs `ALLOWED_HOSTS` and/or `COOKIE_DOMAIN` |
| `RP_ID` | – (required) | WebAuthn domain: the domain of the page where passkeys are used, or a parent (`example.com`, `localhost`). In forward mode this is the login host's domain |
| `RP_ORIGINS` | – (required) | Origins allowed for login/enrollment, comma-separated (public URL, no trailing `/`) |
| `RP_NAME` | `WebAuthn Proxy` | Name shown by the authenticator |
| `LISTEN` | `:8080` | Proxy / `/_wap/verify` port |
| `ENROLL_ENABLED` | `false` | Enable automatic enrollment |
| `ENROLL_LISTEN` | `:8081` | Automatic enrollment port |
| `TOOL_ENABLED` | `false` | Enable the static enrollment tool |
| `TOOL_LISTEN` | `:8082` | Static tool port |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` folder (mount as a volume) |
| `SESSION_SECRET` | generated | Cookie-signing secret, **32 characters minimum** (`openssl rand -base64 48`); otherwise 32 random bytes are generated in `DATA_DIR/session.key`. Changing it signs everybody out |
| `SESSION_TTL` | `12h` | Session lifetime |
| `USER_VERIFICATION` | `required` | `preferred` to accept authenticators without PIN/biometrics |
| `PRESERVE_HOST` | `false` | Proxy mode: forward the client's `Host` to the upstream |
| `USER_HEADER` | `X-Authenticated-User` | Header carrying the user |

Ports: only `8080` is meant to be reached by the public (through Traefik). **Never expose `8081` or `8082`**: loopback or a private network, and only while you enroll ([reverse-proxy.md](reverse-proxy.md)).
