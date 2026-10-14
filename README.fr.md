# webauthnproxy

[![CI](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

🇬🇧 [English](README.md) · 🇫🇷 Français

**Connexion par passkey devant n'importe quel site. Un conteneur, un fichier JSON.**
Pas de mot de passe. Pas d'annuaire. Pas de fournisseur OIDC.

> La documentation détaillée (`docs/`) est en anglais.

## Démarrage rapide

Protégez un site de démo ([`whoami`](https://github.com/traefik/whoami), il affiche les en-têtes reçus).

```sh
docker network create wap
docker run -d --name whoami --network wap docker.io/traefik/whoami     # le site à protéger : non publié

mkdir -p data && sudo chown 65532 data
docker run -d --name webauthnproxy --network wap \
  -p 8080:8080 -p 127.0.0.1:8081:8081 -v "$PWD/data:/data" \
  -e UPSTREAM=http://whoami:80 \
  -e RP_ID=localhost -e RP_ORIGINS=http://localhost:8080,http://localhost:8081 \
  -e ENROLL_ENABLED=true \
  ghcr.io/coldknife2/webauthnproxy:latest

docker logs webauthnproxy        # copiez « Enrollment bootstrap token: … »
```

1. Ouvrez <http://localhost:8081>, collez le jeton, choisissez un nom : **votre première passkey** (`?lang=fr` pour l'interface en français).
2. Ouvrez <http://localhost:8080> : passkey demandée, puis whoami affiche `X-Authenticated-User: <vous>`.
3. Enrôlement terminé ? Recréez le conteneur sans `ENROLL_ENABLED`.

`UPSTREAM` est le site protégé. Mettez le vôtre : toute URL joignable depuis le conteneur.
Podman : remplacez `docker` par `podman` ; rootless : `podman unshare chown 65532:65532 data`.

## Installation

```yaml
services:
  webauthnproxy:
    image: ghcr.io/coldknife2/webauthnproxy:latest   # en production, épinglez une version : :1.2.3
    restart: unless-stopped
    environment:
      UPSTREAM: http://monsite:80
      RP_ID: example.com
      RP_ORIGINS: https://app.example.com
    volumes: ["./data:/data"]                        # chown 65532 ./data
```

| Tag | |
|---|---|
| `latest`, `main` | dernier commit de `main` |
| `1.2.3`, `1.2`, `1` | versions |

`linux/amd64`, `linux/arm64`. Vérifier : `docker run --rm ghcr.io/coldknife2/webauthnproxy --version`.
Depuis les sources : `docker build -t webauthnproxy .`

HTTPS obligatoire hors `localhost`. Traefik devant : [`docker-compose.example.yml`](docker-compose.example.yml).

## Utilisation

### Deux modes

| `MODE=proxy` (défaut) | `MODE=forward` |
|---|---|
| Relaie le trafic vers `UPSTREAM`. Un site. | `forwardAuth` Traefik. **Plusieurs sites, n'importe quels domaines.** |
| Ajoute `X-Authenticated-User`, retire le cookie de session. | `auth.com` protège `anysite.com`, `other.org`… |

```sh
# mode forward : un hôte de login, une liste blanche de sites protégés
MODE=forward
LOGIN_URL=https://auth.com/_wap/login
ALLOWED_HOSTS=anysite.com,other.org,*.example.net
RP_ID=auth.com
RP_ORIGINS=https://auth.com
```
```yaml
# Traefik : à attacher à n'importe quel routeur
- traefik.http.middlewares.passkey.forwardauth.address=http://webauthnproxy:8080/_wap/verify
- traefik.http.middlewares.passkey.forwardauth.authResponseHeaders=X-Authenticated-User
- traefik.http.routers.monsite.middlewares=passkey
```

Fonctionnement du login multi-domaines : [docs/forwardauth.md](docs/forwardauth.md). Exemple : [`docker-compose.forwardauth.example.yml`](docker-compose.forwardauth.example.yml).

### Enrôler des passkeys

| | Automatique | Outil statique |
|---|---|---|
| Activer | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` | `8082` |
| Protégé par | vos passkeys existantes (jeton pour la première) | rien : sans état, sans écriture |
| Ajouter une passkey | dans la page | copier le JSON fourni dans `data/import/` |

L'outil statique doit être servi en HTTPS sous le domaine `RP_ID` (pas en `file://`). Détails : [docs/enrollment.md](docs/enrollment.md).

### Configurer

| Variable | Défaut | |
|---|---|---|
| `UPSTREAM` | – | mode proxy : site à protéger |
| `RP_ID`, `RP_ORIGINS` | – | domaine WebAuthn et origines autorisées (obligatoires) |
| `LOGIN_URL`, `ALLOWED_HOSTS` | – | mode forward : page de login, liste blanche des sites |
| `SESSION_TTL` | `12h` | durée de session |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

Toutes les variables, sécurité, dépannage : [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Pourquoi

Besoin : connexion par passkey seule devant des sites auto-hébergés, sans rien d'autre à faire tourner. Au 14/10/2026 :

- **Traefik** n'a [aucun plugin passkey](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** : passkey seule, mais fournisseur OIDC et non proxy : il faut [Tinyauth](https://github.com/tinyauthapp/tinyauth) ou OAuth2 Proxy devant les applis sans OIDC ([guide](https://pocket-id.org/docs/guides/proxy-services)). Le README de Tinyauth n'indique aucun support des passkeys.
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)** : connexion par passkey depuis la v4.39, mais une passkey compte pour un seul facteur et un mot de passe peut rester demandé pour les politiques `two_factor`.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Connexion passkey seule | ✅ | ✅ | ⚠️ mot de passe parfois exigé |
| Conteneurs à faire tourner | 1 | 2 (+ Traefik) | 1 (+ stockage) |
| Un login passkey pour des **domaines sans rapport** | ✅ échange de ticket | non vérifié | [un cookie par domaine](https://authelia.com/configuration/session/introduction) ; connexions séparées* |
| Proxy intégré (ni Traefik, Caddy, Nginx) | ✅ | ❌ | ❌ |
| SSO OIDC pour d'autres applis | ❌ | ✅ | ✅ |
| Règles par site, groupes | ❌ | partiel | ✅ |
| Maturité | nouveau, non audité | élevée | élevée |

\*selon un témoignage tiers, non confirmé dans la doc d'Authelia.

**Choisissez les autres** pour des règles par site, des groupes, plusieurs admins, de l'OIDC ou un logiciel audité.
**Choisissez celui-ci** pour un usage perso ou homelab : une passkey, plusieurs sites, rien d'autre.
Les sites officiels (tinyauth.app, docs.pocket-id.org) étaient injoignables lors de la recherche ; revérifiez avant de trancher.

## Développement

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + passkey virtuelle ; Traefik en conteneur
make build   # ./webauthnproxy
make image   # image de conteneur
```

La CI ([`ci.yml`](.github/workflows/ci.yml)) teste, puis construit et pousse l'image sur `ghcr.io` pour `main` et les tags `v*`.
Mise en place et publication : [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnérabilités : [SECURITY.md](SECURITY.md).

MIT — [LICENSE](LICENSE)
