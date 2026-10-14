# Contribuer

Merci de votre intérêt ! Le projet vise à rester **petit et auditable** : un conteneur, un fichier de données,
peu de dépendances. Les contributions qui préservent cette simplicité sont les bienvenues.

## Avant de commencer

- Ouvrez une issue pour discuter d'une nouvelle fonctionnalité avant d'écrire beaucoup de code.
- Pour une faille de sécurité, suivez [SECURITY.md](SECURITY.md) (pas d'issue publique).

## Environnement

Prérequis : Go (version de `go.mod`), Node 22 et un runtime de conteneurs (podman ou docker) pour les tests e2e.

```sh
make check   # gofmt + go vet + go test -race
make e2e     # Chromium + authenticator virtuel, et Traefik en conteneur
make build   # binaire ./webauthnproxy
make image   # image de conteneur
```

## Règles

- Code formaté par `gofmt`, `go vet` propre, tests verts.
- Tout changement de comportement visible (variable d'environnement, port, format de fichier, sécurité) doit être
  couvert par un test **et** documenté dans le [README](README.md) et le [CHANGELOG](CHANGELOG.md).
- Ne jamais faire confiance à une donnée fournie par le client (en-têtes, fichiers d'import, `next`) : validez-la côté serveur.
- Pas de nouvelle dépendance sans justification dans la PR.
- Commits clairs, à l'impératif (« Ajoute… », « Corrige… »). Une PR = un sujet.

## Structure

| Fichier | Rôle |
|---|---|
| `main.go`, `config.go` | démarrage, serveurs, configuration par variables d'environnement |
| `app.go` | handlers : proxy, forwardAuth, login, enrôlement automatique, outil statique |
| `session.go` | cookies de session signés, cérémonies WebAuthn en mémoire |
| `store.go` | base JSON (utilisateurs, passkeys) |
| `import.go` | validation et import des fichiers JSON de l'outil statique |
| `web/` | pages embarquées (login, enrôlement, `tool.html` autonome) |
| `test/e2e/` | tests de bout en bout (Playwright) |
