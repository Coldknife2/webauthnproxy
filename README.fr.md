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
TRUSTED_PROXIES=172.18.0.0/16   # plage d'adresses de Traefik : obligatoire, personne d'autre n'est cru sur X-Forwarded-*
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
| Exposition | **jamais publique** : loopback ou réseau privé, uniquement pendant l'enrôlement | **jamais publique** (inoffensif si atteint, mais aucune raison de la publier) |
| Ajouter une passkey | dans la page | copier le JSON fourni dans `data/import/` |

L'outil statique doit être servi en HTTPS sous le domaine `RP_ID` (pas en `file://`). Détails : [docs/enrollment.md](docs/enrollment.md).

### Configurer

| Variable | Défaut | |
|---|---|---|
| `UPSTREAM` | – | mode proxy : site à protéger |
| `RP_ID`, `RP_ORIGINS` | – | domaine WebAuthn et origines autorisées (obligatoires) |
| `LOGIN_URL`, `ALLOWED_HOSTS` | – | mode forward : page de login, liste blanche des sites |
| `SESSION_SECRET` | généré | clé de signature des cookies, 32 caractères minimum |
| `TRUSTED_PROXIES` | – | mode forward : CIDR dont les `X-Forwarded-*` sont crus (obligatoire ; jamais de confiance par défaut) |
| `SESSION_TTL`, `SESSION_IDLE_TIMEOUT` | `12h`, désactivé | durée de session, déconnexion après inactivité |
| `SESSION_SECRET_PREVIOUS` | – | anciennes clés de signature encore acceptées (rotation sans déconnecter tout le monde) |
| `RATE_LIMIT_IP`, `RATE_LIMIT_GLOBAL` | `20/1m`, `200/1m` | requêtes de login et d'enrôlement par adresse cliente / au total (`429`) |
| `AUDIT_LOG` | `true` | événements d'audit JSON sur la sortie standard |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

Toutes les variables, sécurité, dépannage : [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Notes de sécurité

- **Le login multi-domaines** utilise des tickets à usage unique valables 60 secondes, liés au site cible ; seuls les sites listés dans `ALLOWED_HOSTS` peuvent utiliser le login, et le cookie de chaque site est lié à son hôte.
  Modèle de menace, limites connues et ce qui est testé : [docs/security.md](docs/security.md#cross-domain-login-threat-model) (en anglais).
- **Derrière Traefik :** réglez `TRUSTED_PROXIES` sur la plage de Traefik, laissez `trustForwardHeader` désactivé, gardez `/_wap/verify` hors du routeur public, et **n'exposez jamais les ports 8081 et 8082**.
  `RP_ORIGINS` est vérifié par rapport à l'origine signée par le navigateur, pas par rapport à `Host` ni `X-Forwarded-*`. Détails : [docs/reverse-proxy.md](docs/reverse-proxy.md).

## Limites

- **Navigateur uniquement.** La connexion exige un navigateur interactif (invite de passkey et redirections). Les applis natives et mobiles, clients d'API, WebDAV/CalDAV et clients de type Vaultwarden ne peuvent pas se connecter et reçoivent `401`.
  Pour les applis qui parlent OIDC, préférez un fournisseur d'identité comme Pocket ID.
- **Cookies sans état.** Une session est un cookie signé : la révocation se fait **par utilisateur** (« se déconnecter partout »), pas par session, et un cookie volé fonctionne jusqu'à `SESSION_TTL` (12 h par défaut) ou jusqu'à la déconnexion.
  Faites tourner la clé sans déconnecter personne avec `SESSION_SECRET_PREVIOUS` ; retirer l'ancienne clé déconnecte tout le monde ; les passkeys ne sont pas touchées. [Détails](docs/security.md#session-tokens-hmac-signed-cookies).
- **Pas de récupération de compte à distance.** Si toutes les passkeys sont perdues, on récupère depuis l'hôte : mettre `users.json` de côté, changer la clé de session, réenrôler avec le jeton d'amorçage.
  **Enrôlez au moins deux passkeys** sur des authenticators différents. [Procédure](docs/enrollment.md#account-recovery-lost-passkeys).
- **Nouveau, non audité, un seul mainteneur.** Premier commit le 2026-10-14. Limitation de débit et journal d'audit minimaux (par processus, en mémoire), une seule instance (pas de haute disponibilité), pas de règles par site : toute passkey enrôlée ouvre tous les sites listés.

## Quand ne PAS l'utiliser

- Vos applis parlent OIDC : utilisez un fournisseur d'identité (Pocket ID, Authelia).
- Des clients natifs, des API, du WebDAV ou des applis mobiles doivent continuer à fonctionner via les mêmes noms d'hôte.
- Vous avez besoin de plusieurs utilisateurs avec des groupes, des règles par site ou une administration déléguée.
- L'environnement est critique ou doit être audité, ou vous avez besoin de haute disponibilité, de révocation par session ou de liaison IP/appareil.
- Vous n'avez besoin que d'`auth_request` nginx : [Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) est maintenu depuis 2022 (voir ci-dessous).

## Pourquoi

**Ce n'est pas la première passerelle à passkeys.** [Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) existe depuis le 2022-01-03 (`auth_request` nginx, dernier commit le 2026-08-18) et
[passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) (forward-auth, depuis le 2026-04-17) est proche de ce projet. Liste datée, sources et détails : [docs/alternatives.md](docs/alternatives.md) (en anglais).

| | ce dépôt | Quiq/webauthn_proxy | passkey-forwardauth |
|---|---|---|---|
| Relaie lui-même le trafic vers un upstream | ✅ | ❌ | ❌ |
| `forwardAuth` Traefik | ✅ testé de bout en bout | non documenté | ✅ |
| Un login pour des **domaines sans rapport** | ✅ | ❌ un seul domaine de cookie | ❌ un seul domaine de cookie |
| Connexion sans nom d'utilisateur | ✅ | ❌ | ✅ |
| Enrôlement | page protégée par passkey, ou outil statique + import sans redémarrage | page → coller dans `credentials.yml` → redémarrer | admin d'amorçage sur loopback |
| Sessions | cookie signé, révocation par utilisateur | cookie signé | côté serveur, révocation par session |
| Limitation de débit | ✅ login et enrôlement, par client et global | ❌ | amorçage seulement |
| Image / tests | GHCR via la CI / unitaires + e2e | Docker Hub / aucun dans le dépôt | `.deb`/`.rpm` / unitaires |
| Ancienneté | premier commit le 2026-10-14 | depuis le 2022-01-03 | depuis le 2026-04-17 |

**Apporté ici :** un mode proxy intégré, la connexion entre domaines sans rapport avec une liste de sites autorisés, la connexion sans nom d'utilisateur, un enrôlement sans redémarrage, et une suite de bout en bout avec un vrai Traefik.
**Manquant ici :** sessions côté serveur avec révocation par session, et surtout l'ancienneté.

### Les plateformes d'identité font un autre métier

**Pocket ID, Tinyauth et Authelia sont de bons projets, et ils font un autre métier.** Ce sont des plateformes d'identité et de SSO :
utilisateurs et groupes, OIDC pour vos applis, règles d'accès par site, interfaces d'administration, matures et très utilisées.
webauthnproxy est un portail. Il répond à une seule question, *« ce visiteur possède-t-il une passkey enregistrée ? »*, pour un ou plusieurs sites.
Si vous avez besoin du premier, utilisez-les. Si vous n'avez besoin que du second, inutile de faire tourner deux ou trois services et une base de données.

Ce que dit la documentation officielle (lue le 14/10/2026) :

- **Traefik** n'a [aucun plugin passkey](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** n'accepte que les passkeys et « ne fournit que OpenID Connect, donc ne peut pas protéger seul une appli sans OIDC » :
  on met devant un proxy d'authentification, comme Tinyauth, caddy-security ou OAuth2 Proxy ([guide](https://pocket-id.org/docs/guides/proxy-services)).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)** est ce proxy : forward-auth avec [utilisateur/mot de passe (+ TOTP), LDAP et OpenID Connect](https://tinyauth.app/docs/reference/authentication/) ;
  il n'a pas de passkey en propre et documente [Pocket ID comme moyen d'en avoir](https://tinyauth.app/docs/guides/pocket-id/).
  Il pose son cookie « pour le domaine parent de l'URL de l'application », ses applis étant des sous-domaines ([configuration du domaine](https://tinyauth.app/docs/getting-started/)) ;
  son code refuse les applis hors de ce domaine (`domain does not match cookie domain`), ce que j'ai reproduit avec Tinyauth v5.2.0 derrière Traefik le 2026-10-14
  ([expérience](docs/alternatives.md#experiment-one-login-for-two-unrelated-domains-with-tinyauth) ; Pocket ID ne faisait pas partie de ce test).
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)** propose la connexion par passkey sans mot de passe depuis la v4.39, mais « la passkey est un seul facteur » : un mot de passe peut rester demandé
  pour appliquer une politique `two_factor` (une option expérimentale permet à une passkey avec vérification utilisateur de la satisfaire). Chaque [domaine de cookie](https://www.authelia.com/configuration/session/introduction/) est associé
  à un `authelia_url` situé dans ce domaine : des domaines sans rapport donnent des portails et des connexions séparés.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Conteneurs à faire tourner | 1 | 2 (+ Traefik) | 1 (+ stockage) |
| Un login pour des **domaines sans rapport** | ✅ échange de ticket | ❌ un seul domaine de cookie (testé : Tinyauth v5.2.0) | un portail et une connexion par domaine (d'après sa documentation, non testé) |
| Proxy intégré (ni Traefik, Caddy, Nginx) | ✅ | ❌ | ❌ |
| SSO OIDC pour d'autres applis | ❌ | ✅ | ✅ |
| Règles par site, groupes, plusieurs admins | ❌ | ✅ basique (règles par appli Tinyauth, groupes Pocket ID) | ✅ |
| Maturité | nouveau, non audité | élevée | élevée |

**Choisissez-les** pour de l'OIDC, des groupes, des règles par site, plusieurs administrateurs, ou un logiciel très utilisé et audité.
**Choisissez celui-ci** pour un usage perso ou homelab : une passkey, plusieurs sites, rien d'autre à faire tourner.

## Développement

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + passkey virtuelle ; Traefik en conteneur
make build   # ./webauthnproxy
make image   # image de conteneur
```

Les mesures de performance sont une **expérience**, pas une promesse : comment elles ont été faites, et ce qu'elles montrent ou non, est dans [docs/performance.md](docs/performance.md) (en anglais ; `make bench`).

La CI ([`ci.yml`](.github/workflows/ci.yml)) teste, puis construit et pousse l'image sur `ghcr.io` pour `main` et les tags `v*`.
Mise en place et publication : [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnérabilités : [SECURITY.md](SECURITY.md).

MIT — [LICENSE](LICENSE)
