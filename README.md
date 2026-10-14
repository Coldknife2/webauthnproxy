# webauthnproxy

Reverse proxy qui protège n'importe quel site derrière une **authentification par passkey** (WebAuthn).
Un seul binaire Go, image Docker distroless, base de données = un fichier JSON.

```
Sans Traefik :  Utilisateur ──► webauthnproxy ──► site web
Avec Traefik :  Utilisateur ──► Traefik ──► webauthnproxy ──► site web
```

Le site web ne doit **pas** être joignable autrement que par le proxy (pas de port publié, pas de label Traefik).

- Non authentifié : redirection vers `/_wap/login` (navigateur) ou `401` (API).
- Authentifié : requête transmise (WebSocket inclus) avec l'en-tête `X-Authenticated-User`
  (toute valeur envoyée par le client est écrasée). Le cookie de session n'est pas transmis à l'upstream.
- Connexion « sans nom d'utilisateur » (passkey discoverable), vérification utilisateur (PIN/biométrie) exigée.

## Enrôlement (endpoint privé, optionnel)

Avec `ENROLL_ENABLED=true`, un **second port** (`ENROLL_LISTEN`, 8081) sert la page d'enrôlement
(ajout/suppression de passkeys). Il n'est jamais routé vers le site : à toi de ne l'exposer qu'en privé
(port non publié, `ipallowlist` Traefik, VPN…), et éventuellement protégé par `ENROLL_PASSWORD` (basic auth, mot de passe seul).
Désactivé (défaut) : aucun port, aucun code d'enrôlement accessible.

⚠️ WebAuthn lie la passkey au domaine : la page d'enrôlement doit être ouverte depuis une URL dont le
domaine est `RP_ID` ou un sous-domaine, et cette URL doit figurer dans `RP_ORIGINS`
(ex. `https://enroll.example.com`). Pour un test local : `RP_ID=localhost`, `http://localhost:8081`.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `UPSTREAM` | – (obligatoire) | URL du site à protéger |
| `RP_ID` | – (obligatoire) | domaine WebAuthn (`example.com`, `localhost`) |
| `RP_ORIGINS` | – (obligatoire) | origines autorisées, séparées par des virgules (URL publique du site + éventuellement celle d'enrôlement) |
| `LISTEN` | `:8080` | port du proxy |
| `ENROLL_ENABLED` | `false` | active l'enrôlement |
| `ENROLL_LISTEN` | `:8081` | port d'enrôlement |
| `ENROLL_PASSWORD` | – | mot de passe basic-auth de l'enrôlement |
| `DATA_DIR` | `/data` | `users.json` + `session.key` (à monter en volume) |
| `SESSION_SECRET` | généré | secret de signature des cookies (≥16 car.) |
| `SESSION_TTL` | `12h` | durée de session |
| `PRESERVE_HOST` | `false` | transmettre le `Host` d'origine à l'upstream |
| `USER_HEADER` | `X-Authenticated-User` | en-tête portant l'utilisateur |
| `USER_VERIFICATION` | `required` | `preferred` pour accepter les clés sans PIN |
| `RP_NAME` | `WebAuthn Proxy` | nom affiché |

## Démarrage rapide

```sh
docker build -t webauthnproxy .
docker run --rm -p 8080:8080 -p 127.0.0.1:8081:8081 -v $PWD/data:/data \
  -e UPSTREAM=http://host.docker.internal:3000 \
  -e RP_ID=localhost -e RP_ORIGINS=http://localhost:8080,http://localhost:8081 \
  -e ENROLL_ENABLED=true webauthnproxy
```

1. Ouvrir http://localhost:8081, saisir un nom, créer la passkey.
2. Ouvrir http://localhost:8080 → connexion par passkey → le site apparaît.
3. Relancer sans `ENROLL_ENABLED` : l'enrôlement disparaît.

Voir `docker-compose.example.yml` pour l'intégration Traefik (TLS, routeur d'enrôlement restreint par IP).

## Podman / permissions

L'image tourne en non-root (uid 65532). Pour un dossier monté depuis l'hôte : `mkdir data && chown 65532 data`
(en podman rootless : `podman unshare chown 65532:65532 data`, ou `--userns=keep-id --user $(id -u)`).
Le `Dockerfile` utilise des noms d'images qualifiés : `podman build -t webauthnproxy .` fonctionne tel quel.

## Limites connues

- Pas de limitation de débit sur `/_wap/login/*` (les passkeys ne sont pas devinables, mais une limite côté Traefik est conseillée).
- Instance unique (cérémonies WebAuthn en mémoire) ; un proxy par site à protéger.
- Le préfixe `/_wap/` est réservé au proxy.
