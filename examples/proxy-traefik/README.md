# One site behind Traefik (proxy mode)

```
Browser ──► Traefik ──► webauthnproxy ──► site
```

```sh
docker compose up -d
docker compose logs webauthnproxy | grep "bootstrap token"     # copy the token
```

1. Open <http://app.localhost:8081>, paste the token, pick a name: your first passkey (then enrol a second one).
2. Open <http://app.localhost:8000>: passkey prompt, then the site (here `whoami`) shows `X-Authenticated-User`.
3. Remove `ENROLL_ENABLED` and the `8081` port from `compose.yml`, then `docker compose up -d`.

Manage passkeys: `docker compose exec webauthnproxy /webauthnproxy passkeys list`.

Local, plain HTTP, `*.localhost` (browsers treat it as a secure context). For a real domain use HTTPS: [`../../docker-compose.example.yml`](../../docker-compose.example.yml).
This exact file is run by `make examples` (see [`test/examples/run.cjs`](../../test/examples/run.cjs)): anonymous request refused, enrolment, sign-in, header forwarded, cookie not forwarded, healthcheck, CLI.
