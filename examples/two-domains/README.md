# Two unrelated domains, one login (forward mode)

```
Browser ──► Traefik ──forwardAuth──► webauthnproxy        (login host auth.localhost)
               └──────────────────► site one, site two     (one.localhost, two.localhost)
```

```sh
docker compose up -d
docker compose logs webauthnproxy | grep "bootstrap token"
```

1. Open <http://auth.localhost:8081>, paste the token, create your passkey.
2. Open <http://one.localhost:8000>: you are sent to `auth.localhost`, use your passkey, you come back to the site.
3. Open <http://two.localhost:8000>: no new prompt, the login host hands a single-use ticket to the second site.
4. Remove `ENROLL_ENABLED` and the `8081` port, then `docker compose up -d`.

`ALLOWED_HOSTS` lists the only sites this login serves; everything else gets `403`. `TRUSTED_PROXIES` is Traefik's range (required).
On the `localhost` suffix the names merely *look* related; the cookie of each site is host-only either way. In production use real unrelated names such as `auth.com`, `anysite.com`, `other.org` with HTTPS
([`../../docker-compose.forwardauth.example.yml`](../../docker-compose.forwardauth.example.yml)). The real-Traefik e2e suite (`test/e2e/crossdomain.cjs`) covers truly separate domains.

This exact file is run by `make examples`: anonymous request refused, enrolment, prompt on site one, no prompt on site two, `/_wap/verify` hidden from the public login host, healthcheck.
