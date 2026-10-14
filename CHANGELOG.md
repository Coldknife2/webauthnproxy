# Changelog

Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versionnement [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté
- Mode **proxy** : reverse proxy (WebSocket inclus) qui exige une session obtenue par passkey ; l'utilisateur est transmis dans `X-Authenticated-User`, le cookie de session n'est pas transmis.
- Mode **forwardAuth** (`MODE=forward`) pour Traefik : endpoint `/_wap/verify`, hôte de login dédié, cookie partagé sur `COOKIE_DOMAIN`, retour après login restreint à ce domaine.
- **Enrôlement automatique** (`ENROLL_ENABLED`, port 8081) protégé par les passkeys existantes ; jeton d'amorçage affiché dans les logs tant qu'aucune passkey n'existe ; la dernière passkey ne peut pas être supprimée.
- **Outil d'enrôlement statique** (`TOOL_ENABLED`, port 8082) : page HTML autonome produisant un JSON, à importer à la main dans `DATA_DIR/import/`.
- Connexion sans nom d'utilisateur (passkeys *discoverable*), vérification utilisateur exigée par défaut (`USER_VERIFICATION`).
- Base de données : un fichier JSON écrit de façon atomique.
- Image distroless non-root, exemples Docker Compose / Traefik, tests unitaires et tests de bout en bout (Chromium + authenticator virtuel, Traefik réel).
