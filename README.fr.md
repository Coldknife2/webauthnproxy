# webauthnproxy

🇬🇧 [English](README.md) · 🇫🇷 Français

> **Langues :** les logs et les messages d'erreur sont en anglais ; les pages web sont en anglais par défaut, ajoutez `?lang=fr` à l'URL pour le français (mémorisé par le navigateur).

[![CI](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

**Protégez n'importe quel site auto-hébergé par une connexion *passkey* (WebAuthn), avec un seul conteneur et un fichier JSON.**

Pas de mot de passe, pas d'annuaire, pas de fournisseur OIDC à déployer. Se place devant un site comme reverse proxy,
ou derrière Traefik comme service `forwardAuth` pour protéger plusieurs sites.

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Comment ça marche](#comment-ça-marche)
- [Démarrage rapide](#démarrage-rapide)
- [Modes de fonctionnement](#modes-de-fonctionnement)
- [Enrôlement des passkeys](#enrôlement-des-passkeys)
- [Configuration](#configuration)
- [Modèle de sécurité](#modèle-de-sécurité)
- [Pourquoi ce projet ? Alternatives](#pourquoi-ce-projet--alternatives)
- [Dépannage](#dépannage)
- [Développement](#développement)
- [Contribuer, sécurité, licence](#contribuer-sécurité-licence)

## Fonctionnalités

- 🔐 Connexion **par passkey uniquement**, sans nom d'utilisateur à saisir (*discoverable credentials*), vérification utilisateur (PIN / biométrie) exigée par défaut.
- 🔁 Deux modes : **proxy** intégré (avec ou sans Traefik, WebSocket compris) ou **forwardAuth** Traefik (un déploiement pour plusieurs sites).
- ➕ Deux façons d'**enrôler** des passkeys, activables séparément : enrôlement automatique protégé par les passkeys existantes, ou outil HTML statique + import manuel d'un fichier JSON.
- 🗃️ **Base de données = un fichier JSON** (clés publiques uniquement), écrit de façon atomique.
- 📦 Image **distroless**, utilisateur non-root, ~13 Mo ; quelques centaines de lignes de Go à auditer.
- ✅ Testé de bout en bout : Chromium avec authenticator virtuel et Traefik réel.

## Comment ça marche

```
Mode proxy        Utilisateur ──► (Traefik) ──► webauthnproxy ──► site web
                                                 │ session valide ? sinon redirection vers /_wap/login
                                                 └ transmet la requête + X-Authenticated-User

Mode forwardAuth  Utilisateur ──► Traefik ──(1) GET /_wap/verify──► webauthnproxy
                                    │  (2) 2xx : la requête continue ──► site web
                                    └──── sinon : redirection vers le login (navigateur) ou 401
```

1. L'utilisateur arrive sur le site sans session : il est redirigé vers la page de connexion (`/_wap/login`).
2. Le navigateur demande la passkey ; la signature est vérifiée par le serveur.
3. Un cookie de session signé (`wap_session`, HttpOnly, SameSite=Lax) est posé, l'utilisateur revient sur la page demandée.

Le site protégé ne doit **pas** être joignable autrement que par le proxy (aucun port publié, aucun routeur Traefik direct en mode proxy).

## Démarrage rapide

Image locale (podman ou docker, les commandes sont identiques) :

```sh
git clone https://github.com/coldknife2/webauthnproxy && cd webauthnproxy
podman build -t webauthnproxy .

mkdir -p data && podman unshare chown 65532:65532 data   # docker : sudo chown 65532 data
podman run -d --name webauthnproxy \
  -p 8080:8080 -p 127.0.0.1:8081:8081 -v ./data:/data:Z \
  -e UPSTREAM=http://host.containers.internal:3000 \
  -e RP_ID=localhost -e RP_ORIGINS=http://localhost:8080,http://localhost:8081 \
  -e ENROLL_ENABLED=true \
  webauthnproxy

podman logs webauthnproxy        # affiche le jeton d'amorçage (« Enrollment bootstrap token: … »)
```

1. Ouvrez <http://localhost:8081>, saisissez le **jeton d'amorçage** et un nom : créez la première passkey.
2. Ouvrez <http://localhost:8080> : connexion par passkey, puis votre site s'affiche.
3. Une fois les passkeys enrôlées, relancez le conteneur **sans** `ENROLL_ENABLED` pour fermer l'enrôlement.

En production : HTTPS obligatoire (WebAuthn l'exige hors `localhost`), `RP_ID` = votre domaine, `RP_ORIGINS` = l'URL publique du site.
Exemples complets avec Traefik : [`docker-compose.example.yml`](docker-compose.example.yml) (mode proxy) et
[`docker-compose.forwardauth.example.yml`](docker-compose.forwardauth.example.yml) (mode forwardAuth).

## Modes de fonctionnement

### Mode proxy (`MODE=proxy`, défaut)

Le service reçoit le trafic et le relaie vers `UPSTREAM`. Pour une requête authentifiée :

- l'en-tête `X-Authenticated-User` (renommable avec `USER_HEADER`) contient l'utilisateur ; toute valeur envoyée par le client est écrasée ;
- le cookie de session n'est **pas** transmis au site ;
- le `Host` est réécrit vers l'upstream (`PRESERVE_HOST=true` pour garder celui du client) ; `X-Forwarded-*` est renseigné.

Convient pour un site unique, avec ou sans Traefik. Le préfixe `/_wap/` est réservé au service.

### Mode forwardAuth (`MODE=forward`)

Le service ne relaie rien : Traefik l'interroge sur `/_wap/verify` pour chaque requête et laisse passer (2xx) ou renvoie la
réponse du service (redirection vers `LOGIN_URL` pour un navigateur, `401` sinon). **Un seul déploiement protège autant de sites
qu'on le souhaite** en ajoutant le middleware à leurs routeurs.

```yaml
# middleware réutilisable
- traefik.http.middlewares.passkey.forwardauth.address=http://webauthnproxy:8080/_wap/verify
- traefik.http.middlewares.passkey.forwardauth.authResponseHeaders=X-Authenticated-User
# sur chaque routeur à protéger
- traefik.http.routers.monsite.middlewares=passkey
```

Variables spécifiques : `LOGIN_URL` (URL publique de la page de login, ex. `https://auth.example.com/_wap/login`) et
`COOKIE_DOMAIN` (domaine parent partagé, ex. `example.com` : tous les sites protégés doivent en être des sous-domaines).
Après connexion, le retour vers la page demandée n'est accepté que pour des URLs de ce domaine.

À savoir : `/_wap/verify` ne doit être joignable que par Traefik (réseau interne) ; le cookie de session est transmis aux sites
par Traefik ; il n'y a pas de règles par site, toute passkey enrôlée donne accès à **tous** les sites protégés.

## Enrôlement des passkeys

Une passkey est liée à un **domaine** (`RP_ID`) : le navigateur refuse d'en créer une pour un domaine différent de celui de
la page (ou d'un de ses parents), et refuse tout contexte non sécurisé hors `localhost`. Deux outils, activables séparément :

| | Enrôlement **automatique** | Outil **statique** + import manuel |
|---|---|---|
| Activation | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` (`ENROLL_LISTEN`) | `8082` (`TOOL_LISTEN`) |
| Accès | **protégé** : connexion par une passkey existante | aucun besoin : page sans état ni écriture |
| Exposition conseillée | privée (défense en profondeur) | peut être publique |
| Ajout d'une passkey | immédiat, depuis la page | l'administrateur copie un fichier JSON dans `DATA_DIR/import/` |
| Première passkey | jeton d'amorçage (logs) | pas de jeton nécessaire |

### Enrôlement automatique (port 8081)

La page `http(s)://<hôte>:8081/` permet d'ajouter et de supprimer des passkeys.

- **Protégée par les passkeys existantes** : sans session, elle redirige vers sa propre page de connexion ; l'API répond `401`.
- **Amorçage** : tant qu'aucune passkey n'existe, un **jeton à usage d'amorçage** est généré et écrit dans les logs au démarrage ;
  il faut le saisir pour créer la première. Dès qu'une passkey existe, le jeton cesse de fonctionner.
- Les écritures exigent l'en-tête `X-Requested-With` (protection CSRF). La **dernière passkey ne peut pas être supprimée** (pas de verrouillage).
- Tout utilisateur connecté peut créer de nouveaux utilisateurs et passkeys : tous les utilisateurs sont administrateurs.
- L'URL de cette page doit figurer dans `RP_ORIGINS` et être sous le domaine `RP_ID`.
- Le cookie d'un hôte est partagé entre ports : sur un même nom d'hôte, être connecté à l'enrôlement donne aussi accès au proxy.

### Outil statique (port 8082) et import manuel

Pour enrôler **sans exposer d'API d'écriture** : une page HTML autonome ([`web/tool.html`](web/tool.html)) qui ne contacte aucun serveur.

1. Ouvrez l'outil (`http(s)://<hôte>:8082/`, domaine pré-rempli avec `RP_ID`), saisissez un nom, cliquez **Créer la passkey** (ajoutez `?lang=fr` à l'URL pour l'interface en français).
2. L'outil affiche un **fichier JSON** (clé publique et métadonnées, aucun secret) : téléchargez-le.
3. Copiez-le **à la main** dans le dossier d'import du proxy : `cp remi-example.com.json data/import/`
   (avec un conteneur : `podman cp remi-example.com.json webauthnproxy:/data/import/`).
4. En quelques secondes le proxy valide et importe le fichier, puis le renomme en `.imported` (ou `.rejected`, cause dans les logs).

La page doit être servie en **HTTPS sous le domaine `RP_ID`** (ex. `https://tool.example.com`), ou sur `localhost` avec `RP_ID=localhost` :
**un fichier ouvert directement (`file://`) ne fonctionne pas**, c'est une règle du navigateur. L'origine de l'outil n'a pas besoin d'être dans `RP_ORIGINS`.
L'outil peut aussi être hébergé tel quel (c'est un fichier unique) sur n'importe quel site statique sous le même domaine.

Ce que le proxy **vérifie** à l'import : version du format, passkey créée pour le bon domaine (empreinte `rpIdHash`),
drapeaux présence/vérification utilisateur, clé publique COSE valide, identifiant de passkey cohérent, identifiant utilisateur cohérent
avec le nom, absence de doublon. Format (version 1) :

```json
{
  "version": 1,
  "rpId": "example.com",
  "user": { "id": "<base64url>", "name": "remi" },
  "credential": { "id": "<base64url>", "authenticatorData": "<base64url>", "transports": ["internal"] }
}
```

Le dossier `import/` est surveillé en permanence : **seul quelqu'un pouvant écrire dans le volume de données peut ajouter une passkey par ce biais**.
Pour ajouter un 2ᵉ appareil à un utilisateur, rejouez l'outil avec le **même nom**.

### Perte de toutes les passkeys

Arrêtez le service, supprimez `data/users.json`, relancez avec `ENROLL_ENABLED=true` : un nouveau jeton d'amorçage est affiché dans les logs.
(Ou déposez un fichier produit par l'outil statique dans `data/import/`.)

## Configuration

Tout se règle par variables d'environnement.

| Variable | Défaut | Description |
|---|---|---|
| `MODE` | `proxy` | `proxy` ou `forward` (forwardAuth Traefik) |
| `UPSTREAM` | – | **Mode proxy.** URL du site à protéger (`http://monsite:80`) |
| `LOGIN_URL` | – | **Mode forward.** URL publique de la page de login |
| `COOKIE_DOMAIN` | – | **Mode forward.** Domaine parent du cookie (`example.com`) |
| `RP_ID` | – (obligatoire) | Domaine WebAuthn : domaine du site ou parent commun (`example.com`, `localhost`) |
| `RP_ORIGINS` | – (obligatoire) | Origines autorisées pour login/enrôlement, séparées par des virgules (URL publique, sans `/` final) |
| `RP_NAME` | `WebAuthn Proxy` | Nom affiché par l'authenticator |
| `LISTEN` | `:8080` | Port du proxy / de `/_wap/verify` |
| `ENROLL_ENABLED` | `false` | Active l'enrôlement automatique |
| `ENROLL_LISTEN` | `:8081` | Port de l'enrôlement automatique |
| `TOOL_ENABLED` | `false` | Active l'outil d'enrôlement statique |
| `TOOL_LISTEN` | `:8082` | Port de l'outil statique |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, dossier `import/` (à monter en volume) |
| `SESSION_SECRET` | généré | Secret de signature des cookies (≥ 16 caractères) ; sinon généré dans `DATA_DIR/session.key` |
| `SESSION_TTL` | `12h` | Durée d'une session |
| `USER_VERIFICATION` | `required` | `preferred` pour accepter les authenticators sans PIN/biométrie |
| `PRESERVE_HOST` | `false` | Mode proxy : transmettre le `Host` du client à l'upstream |
| `USER_HEADER` | `X-Authenticated-User` | En-tête portant l'utilisateur |

Ports : `8080` est le seul à exposer publiquement (via Traefik) ; `8081` en privé ; `8082` est inoffensif mais inutile hors des phases d'enrôlement.

## Modèle de sécurité

**Ce qui est garanti**

- Aucune requête n'atteint le site sans cookie de session valide (signé HMAC-SHA256, expirant, invalidé si l'utilisateur est supprimé).
- Login : challenge à usage unique (5 min), origine et domaine vérifiés, compteur de signatures mis à jour, vérification utilisateur exigée.
- Cookie `HttpOnly`, `SameSite=Lax`, `Secure` dès que l'accès est en HTTPS ; pages servies avec une CSP restrictive.
- Redirection après login (`next`) limitée aux chemins locaux, ou en mode forward au `COOKIE_DOMAIN` : pas de redirection ouverte.
- Enrôlement automatique : session requise, jeton d'amorçage comparé en temps constant, protection CSRF, refus de supprimer la dernière passkey.
- Import : fichier non fiable, entièrement revalidé (voir ci-dessus), taille limitée.
- Outil statique : aucune écriture, CSP par empreinte (`script-src 'sha256-…'`, aucun `unsafe-inline`).
- La base ne contient que des **clés publiques** ; seul `session.key` est secret (sa fuite permet de forger des sessions).

**Hypothèses et limites**

- TLS est terminé en amont (Traefik) ; sans HTTPS, WebAuthn ne fonctionne pas hors `localhost`.
- Pas de limitation de débit, de journal d'audit, de règles par site ou de haute disponibilité (instance unique, cérémonies en mémoire) : à compléter côté reverse proxy.
- Les identifiants utilisateur (*user handle*) sont dérivés du nom (SHA-256) pour que le même nom désigne toujours le même utilisateur quel que soit l'outil d'enrôlement.
- Un domaine racine par instance (`RP_ID`).

Signalement de vulnérabilité : voir [SECURITY.md](SECURITY.md) (en anglais).

## Pourquoi ce projet ? Alternatives

**Besoin** : mettre une authentification *passkey uniquement* devant un ou plusieurs sites auto-hébergés
(derrière Traefik ou non), avec le strict minimum : un conteneur, un fichier JSON, pas d'annuaire,
pas de mot de passe, pas de fournisseur OIDC à déployer, et un enrôlement qu'on peut éteindre.

**Recherche préalable** (état au 14/10/2026, sources en bas de section) :

- **Plugin Traefik** : aucun plugin WebAuthn/passkey trouvé dans le [catalogue](https://plugins.traefik.io)
  ni sur la [communauté](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396), où
  la demande est restée sans réponse native (piste proposée : passer par du ForwardAuth). Les plugins
  d'authentification existants font du basic auth/mTLS ([trauth](https://github.com/leonjza/trauth)), du JWT, de l'OIDC ou du LDAP.
  Les plugins tournent par ailleurs dans un interpréteur (Yaegi), sans stockage ni état de cérémonie : peu adapté au WebAuthn.
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** : fournisseur OIDC/OAuth 2.0 **uniquement par passkey**
  (BSD-2). C'est un *fournisseur d'identité*, pas un proxy : les applications doivent parler OIDC. Son guide officiel
  pour les apps sans OIDC renvoie vers un proxy d'authentification tiers (Tinyauth, caddy-security, OAuth2 Proxy ou
  forward auth Traefik) ([guide](https://pocket-id.org/docs/guides/proxy-services), lu via un extrait de recherche).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)** : middleware d'authentification pour Traefik, Nginx et Caddy
  (AGPL-3.0) ; méthodes citées : OAuth/OIDC, LDAP, contrôle d'accès, TOTP. Le README ne mentionne **ni passkey ni WebAuthn** ;
  une [discussion](https://github.com/tinyauthapp/tinyauth/discussions) demandant la connexion par passkey (fév. 2026) existe, sans réponse que j'aie pu confirmer.
- **Authelia / Authentik** : solutions complètes (portail SSO, politiques, annuaires), plus lourdes à exploiter
  (Authentik demande PostgreSQL ; non revérifié en détail ici).

**Conclusion** : la combinaison *Pocket ID + Tinyauth (ou OAuth2 Proxy) + Traefik* offre déjà des passkeys en
forwardAuth, avec de vrais avantages (SSO OIDC, interface d'administration, multi-utilisateurs, maintenance
communautaire). Mais cela fait **trois composants** et passe par OIDC. webauthnproxy vise le cas plus petit :
**un seul conteneur, sans OIDC, sans autre dépendance**, quelques centaines de lignes de Go à auditer.

| Besoin | webauthnproxy | Pocket ID + Tinyauth | Authelia / Authentik |
|---|---|---|---|
| Passkey comme unique méthode | ✅ | ✅ (via Pocket ID) | ✅ (parmi d'autres) |
| Composants à déployer | 1 | 2 (+ Traefik) | 1 à 3 |
| Stockage | fichier JSON | base de données | base de données |
| SSO OIDC pour d'autres applis | ❌ | ✅ | ✅ |
| Politiques par site / groupes | ❌ | partiel (Tinyauth) | ✅ |
| Fonctionne sans Traefik (proxy intégré) | ✅ | ❌ | ❌ |
| Maturité / communauté | faible (nouveau) | élevée | élevée |

**À choisir autrement si** : vous avez besoin de SSO pour plusieurs applications, de groupes/politiques par site,
de comptes gérés par plusieurs administrateurs, ou d'un projet largement audité. Pocket ID + Tinyauth est alors la voie recommandée.

*Limites de la recherche* : les sites officiels (tinyauth.app, docs.pocket-id.org) n'étaient pas joignables depuis
l'environnement de travail ; les informations proviennent des dépôts GitHub et de pages tierces. À revérifier avant de
trancher, ces projets évoluent vite.

Sources : [Pocket ID](https://github.com/pocket-id/pocket-id) ·
[guide proxy Pocket ID](https://pocket-id.org/docs/guides/proxy-services) ·
[Tinyauth](https://github.com/tinyauthapp/tinyauth) ·
[comparatif](https://sumguy.com/tinyauth-vs-pocket-id-vs-authelia/) ·
[fil communauté Traefik](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396) ·
[catalogue de plugins Traefik](https://plugins.traefik.io)

## Dépannage

| Symptôme | Cause probable |
|---|---|
| `SecurityError` à la création de la passkey | La page n'est pas en HTTPS (hors `localhost`), ou `RP_ID` n'est pas le domaine de la page / un de ses parents. |
| « passkey rejected » à la connexion | L'URL de la page de login n'est pas dans `RP_ORIGINS` (schéma, hôte **et port** exacts), ou la passkey a été créée pour un autre `RP_ID`. |
| Import : `.rejected` | Lisez les logs : mauvais domaine, doublon, vérification utilisateur absente, nom/identifiant incohérents. |
| Import ignoré | Le fichier doit se terminer par `.json` ; le conteneur (uid 65532) doit pouvoir lire/écrire `data/import/`. |
| `permission denied` sur `/data` | `chown 65532 data` (podman rootless : `podman unshare chown 65532:65532 data`). |
| Boucle de redirection en mode forward | `COOKIE_DOMAIN` ne couvre pas le site, ou l'accès à la page de login se fait en HTTP alors que le cookie est `Secure`. |
| Jeton d'amorçage introuvable | `podman logs webauthnproxy`, ligne « Enrollment bootstrap token ». |

## Développement

Prérequis : Go (version de [`go.mod`](go.mod)) ; Node 22 et podman/docker pour les tests e2e.

```sh
make check   # gofmt + go vet + go test -race
make e2e     # Chromium + authenticator virtuel ; mode forwardAuth contre un vrai Traefik
make build   # binaire ./webauthnproxy
make image   # image de conteneur
```

Voir [CONTRIBUTING.md](CONTRIBUTING.md) (en anglais) pour l'organisation du code. Le projet utilise la bibliothèque
[`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) pour toute la cryptographie WebAuthn.

## Contribuer, sécurité, licence

- Contributions bienvenues : [CONTRIBUTING.md](CONTRIBUTING.md) (en anglais) · [Code de conduite](CODE_OF_CONDUCT.md)
- Vulnérabilités : [SECURITY.md](SECURITY.md) (en anglais) · Historique : [CHANGELOG.md](CHANGELOG.md)
- Licence : [MIT](LICENSE)
