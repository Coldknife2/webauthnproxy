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

## Léger

| | webauthnproxy | Authelia | Pocket ID + Tinyauth |
|---|---|---|---|
| Mémoire au repos | **9 Mio** | 161 Mio | 109 Mio |
| CPU au repos | **0 %** | 0,05 % | 0,10 % |
| Image | **12 Mio** | 77 Mio | 190 Mio |
| Vérifications, 32 connexions | **36k req/s** | 20k req/s | 4,3k req/s |
| Mémoire max sous charge | **16 Mio** | 258 Mio | 119 Mio |

Même machine, même charge, vérification forward-auth authentifiée. Ils font plus que nous (section suivante). Méthode et limites : [docs/performance.md](docs/performance.md) (en anglais).

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
| `SESSION_SECRET` | généré | clé de signature des cookies, 32 caractères minimum |
| `SESSION_TTL` | `12h` | durée de session |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

Toutes les variables, sécurité, dépannage : [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Pourquoi

**Pocket ID, Tinyauth et Authelia sont de bons projets, et ils font un autre métier.** Ce sont des plateformes d'identité et de SSO :
utilisateurs et groupes, OIDC pour vos applis, règles d'accès par site, interfaces d'administration, matures et très utilisées.
webauthnproxy est un portail. Il répond à une seule question, *« ce visiteur possède-t-il une passkey enregistrée ? »*, pour un ou plusieurs sites.
Si vous avez besoin du premier, utilisez-les. Si vous n'avez besoin que du second, inutile de faire tourner deux ou trois services et une base de données.

Ce que disent les sources (code et README lus le 14/10/2026) :

- **Traefik** n'a [aucun plugin passkey](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** : fournisseur OIDC qui n'accepte que les passkeys. Il n'expose pas de point forward-auth :
  pour protéger une appli sans OIDC, on met un proxy devant, comme [Tinyauth](https://github.com/tinyauthapp/tinyauth) ou OAuth2 Proxy ([son guide](https://pocket-id.org/docs/guides/proxy-services)).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)** : forward-auth avec utilisateurs locaux, LDAP et OAuth/OIDC. Son code ne gère ni passkey ni WebAuthn.
  Il pose un seul domaine de cookie, dérivé de sa propre URL, et refuse les applis hors de ce domaine (`domain does not match cookie domain`).
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)** : connexion par passkey depuis la v4.39, mais une passkey compte pour un seul facteur et un mot de passe peut rester demandé
  pour les politiques `two_factor`. Chaque domaine de cookie exige son propre `authelia_url` dans ce domaine : des domaines sans rapport donnent des portails et des connexions séparés.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Conteneurs à faire tourner | 1 | 2 (+ Traefik) | 1 (+ stockage) |
| Un login pour des **domaines sans rapport** | ✅ échange de ticket | ❌ un seul domaine de cookie | un portail et une connexion par domaine |
| Proxy intégré (ni Traefik, Caddy, Nginx) | ✅ | ❌ | ❌ |
| SSO OIDC pour d'autres applis | ❌ | ✅ | ✅ |
| Règles par site, groupes, plusieurs admins | ❌ | partiel | ✅ |
| Maturité | nouveau, non audité | élevée | élevée |

**Choisissez-les** pour de l'OIDC, des groupes, des règles par site, plusieurs administrateurs, ou un logiciel très utilisé et audité.
**Choisissez celui-ci** pour un usage perso ou homelab : une passkey, plusieurs sites, rien d'autre à faire tourner.

## Développement

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + passkey virtuelle ; Traefik en conteneur
make build   # ./webauthnproxy
make image   # image de conteneur
make bench   # empreinte mémoire/CPU vs Authelia
```

Pourquoi Go plutôt que Rust, .NET, Node ou Python : [docs/language-choice.md](docs/language-choice.md) (en anglais).

La CI ([`ci.yml`](.github/workflows/ci.yml)) teste, puis construit et pousse l'image sur `ghcr.io` pour `main` et les tags `v*`.
Mise en place et publication : [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnérabilités : [SECURITY.md](SECURITY.md).

MIT — [LICENSE](LICENSE)
