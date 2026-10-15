# webauthnproxy

[![CI](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

🇬🇧 [English](README.md) · 🇫🇷 Français

**Connexion par passkey devant n'importe quel site. Un conteneur, un fichier JSON.**
Pas de mot de passe. Pas d'annuaire. Pas de fournisseur OIDC.

**Public visé :** une personne, un homelab, plusieurs sites web accessibles par navigateur.

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

Image : `ghcr.io/coldknife2/webauthnproxy` (`linux/amd64`, `linux/arm64`). Tags : `latest`/`main` (dernier commit), `1.2.3`, `1.2`, `1` (versions) : fixez une version en production.
Compose avec Traefik et HTTPS (obligatoire hors `localhost`) : [`docker-compose.example.yml`](docker-compose.example.yml). Depuis les sources : `docker build -t webauthnproxy .`.
Le dossier de données doit être inscriptible par l'uid 65532. Vérifier l'image : `docker run --rm ghcr.io/coldknife2/webauthnproxy --version`.

## Utilisation

### Deux modes

| `MODE=proxy` (défaut) | `MODE=forward` |
|---|---|
| Relaie le trafic vers `UPSTREAM`. Un site. | `forwardAuth` Traefik. **Plusieurs sites.** |
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

**Plusieurs domaines sans rapport ?** C'est le cas pour lequel ce mode existe (`auth.com` protège `anysite.com` et `other.org`). Avec **un seul domaine et ses sous-domaines**, il n'est pas nécessaire : [Tinyauth](https://tinyauth.app) ou [passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) suffisent, et l'écart avec ce projet est faible ([comparaison et ma conclusion](docs/alternatives.md#why-this-project-rather-than-passkey-forwardauth), en anglais).

Exemples complets et testés (`make examples`) : [un site derrière Traefik](examples/proxy-traefik) · [deux domaines sans rapport](examples/two-domains).

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

Lister ou révoquer une passkey sans éditer `users.json` : `docker exec webauthnproxy /webauthnproxy passkeys list` / `passkeys label <id> <texte>` / `passkeys add <utilisateur>` (lien à usage unique pour ajouter un appareil) / `passkeys revoke <id>` / `sessions list` / `sessions revoke <id>` / `signout <utilisateur>`.
L'image embarque un `HEALTHCHECK` (`webauthnproxy healthcheck`).

### Configurer

| Variable | Défaut | |
|---|---|---|
| `UPSTREAM` | – | mode proxy : site à protéger |
| `RP_ID`, `RP_ORIGINS` | – | domaine WebAuthn et origines autorisées (obligatoires) |
| `LOGIN_URL`, `ALLOWED_HOSTS` | – | mode forward : page de login, liste blanche des sites |
| `TRUSTED_PROXIES` | – | mode forward : CIDR dont les `X-Forwarded-*` sont crus (obligatoire ; jamais de confiance par défaut) |
| `SESSION_TTL`, `SESSION_IDLE_TIMEOUT` | `12h`, désactivé | durée de session, déconnexion après inactivité |
| `SESSION_BIND` | – | `ua`, `ip` ou `ua,ip` : lie une session au User-Agent / à l'adresse du navigateur |
| `RATE_LIMIT_IP`, `RATE_LIMIT_GLOBAL` | `20/1m`, `200/1m` | requêtes de login et d'enrôlement par adresse cliente / au total (`429`) |
| `AUDIT_LOG` | `true` | événements d'audit JSON sur la sortie standard |
| `DATA_DIR` | `/data` | `users.json`, `sessions.json`, `import/` |

Toutes les variables, sécurité, dépannage : [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Notes de sécurité

- **Le login multi-domaines** utilise des tickets valables 60 secondes, à usage unique **uniquement dans la mémoire du processus en cours** (un ticket ne survit pas à un redémarrage et est refusé par toute autre instance ; [détails](docs/security.md#single-use-of-tickets), en anglais), liés au site cible ; seuls les sites listés dans `ALLOWED_HOSTS` peuvent utiliser le login, et le cookie de chaque site est lié à son hôte.
  Modèle de menace, limites connues et ce qui est testé : [docs/security.md](docs/security.md#cross-domain-login-threat-model) (en anglais).
- **Derrière Traefik :** réglez `TRUSTED_PROXIES` sur la plage de Traefik, laissez `trustForwardHeader` désactivé, gardez `/_wap/verify` hors du routeur public, et **n'exposez jamais les ports 8081 et 8082**.
  `RP_ORIGINS` est vérifié par rapport à l'origine signée par le navigateur, pas par rapport à `Host` ni `X-Forwarded-*`. Détails : [docs/reverse-proxy.md](docs/reverse-proxy.md).

## Limites

- **Navigateur uniquement.** La connexion exige un navigateur interactif (invite de passkey et redirections). Les applis natives et mobiles, clients d'API, WebDAV/CalDAV et clients de type Vaultwarden ne peuvent pas se connecter et reçoivent `401`.
  Pour les applis qui parlent OIDC, préférez un fournisseur d'identité comme Pocket ID.
- **Cookies porteurs.** Une session est un cookie aléatoire gardé côté serveur : on peut la lister et la révoquer (`sessions list` / `sessions revoke`), mais un cookie volé fonctionne jusqu'à `SESSION_TTL` (12 h par défaut), au délai d'inactivité ou à sa révocation. `SESSION_BIND` (optionnel) la lie au User-Agent/à l'adresse du navigateur. [Détails](docs/security.md#sessions-server-side) (en anglais).
- **Pas de récupération de compte à distance.** Si toutes les passkeys sont perdues, on récupère depuis l'hôte : mettre `users.json` et `sessions.json` de côté, réenrôler avec le jeton d'amorçage.
  **Enrôlez au moins deux passkeys** sur des authenticators différents. [Procédure](docs/enrollment.md#account-recovery-lost-passkeys).
- **Nouveau, non audité, un seul mainteneur.** Premier commit le 2026-10-14. Limitation de débit et journal d'audit minimaux (par processus, en mémoire), une seule instance (pas de haute disponibilité), pas de règles par site : toute passkey enrôlée ouvre tous les sites listés.

## Quand ne PAS l'utiliser

- Vos applis parlent OIDC : utilisez un fournisseur d'identité (Pocket ID, Authelia).
- Des clients natifs, des API, du WebDAV ou des applis mobiles doivent continuer à fonctionner via les mêmes noms d'hôte.
- Vous avez besoin de plusieurs utilisateurs avec des groupes, des règles par site ou une administration déléguée.
- L'environnement est critique ou doit être audité, ou vous avez besoin de haute disponibilité, de révocation par session ou de liaison IP/appareil.
- Vous n'avez besoin que d'`auth_request` nginx : [Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) est maintenu depuis 2022.
- Vos sites partagent un seul domaine et il vous faut seulement le forward-auth Traefik : [passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) ou Tinyauth font le travail et sont plus anciens ; l'avantage de ce projet est ailleurs ([pourquoi](docs/alternatives.md#why-this-project-rather-than-passkey-forwardauth), en anglais).

## Pourquoi celui-ci

Trois choses le distinguent des autres passerelles à passkey. Le reste du tableau (ce que [passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) et
[Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) font mieux, et ma conclusion sur les cas où il ne faut *pas* choisir ce projet) est dans [docs/alternatives.md](docs/alternatives.md) (en anglais).

1. **Un mode proxy intégré** : un conteneur devant un site, sans Traefik, Caddy ni nginx.
2. **Un seul login pour des domaines sans rapport**, via une liste d'hôtes autorisés (mode forward). Usage étroit : avec un seul domaine et ses sous-domaines, il n'est pas nécessaire.
3. **Un enrôlement sans redémarrage ni édition de configuration** : une page protégée par vos passkeys existantes, ou un outil statique et un fichier JSON déposé dans un dossier.

Pocket ID, Tinyauth et Authelia sont de bons projets qui font un autre métier (identité, OIDC, groupes). Comparaison avec citations et expérience : [docs/alternatives.md](docs/alternatives.md#identity-platforms-a-different-job).

## Développement

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + passkey virtuelle ; Traefik en conteneur
make examples # les deux exemples de examples/, exécutés tels quels (compose)
make build   # ./webauthnproxy
make image   # image de conteneur
```

Les mesures de performance sont une **expérience**, pas une promesse : comment elles ont été faites, et ce qu'elles montrent ou non, est dans [docs/performance.md](docs/performance.md) (en anglais ; `make bench`).

La CI ([`ci.yml`](.github/workflows/ci.yml)) teste, puis construit et pousse l'image sur `ghcr.io` pour `main` et les tags `v*`.
Mise en place et publication : [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnérabilités : [SECURITY.md](SECURITY.md).

## Remerciements

Les sessions côté serveur (jeton aléatoire, seul son hachage est stocké, révocation par session, délai d'inactivité, liaison optionnelle au User-Agent/à l'IP) suivent la conception de
[**QirunGao/passkey-forwardauth**](https://github.com/QirunGao/passkey-forwardauth) (Apache-2.0), arrivé le premier ; l'idée de ne croire les en-têtes transmis que depuis des proxys déclarés aussi.
La conception a été lue puis réimplémentée ; aucun code n'a été copié. [**Quiq/webauthn_proxy**](https://github.com/Quiq/webauthn_proxy) (Apache-2.0) montre depuis 2022 qu'une petite passerelle à passkey pour l'auto-hébergement a sa place.
Merci à eux deux, et aux auteurs de [go-webauthn](https://github.com/go-webauthn/webauthn), qui fait le travail WebAuthn ici. Crédits et différences : [docs/alternatives.md](docs/alternatives.md) (en anglais).

MIT — [LICENSE](LICENSE)
