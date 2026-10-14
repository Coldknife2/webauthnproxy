# Politique de sécurité

## Signaler une vulnérabilité

**N'ouvrez pas d'issue publique.** Utilisez le signalement privé de GitHub :
*onglet Security → Report a vulnerability* du dépôt
([`coldknife2/webauthnproxy`](https://github.com/coldknife2/webauthnproxy/security/advisories/new)).

Indiquez la version ou le commit, les étapes de reproduction et l'impact. Vous recevrez un accusé de réception
dans un délai raisonnable ; un correctif et un avis sont publiés une fois la faille corrigée.

## Versions supportées

Le projet est jeune : seule la dernière version publiée (ou la branche `main`) reçoit des correctifs.

## Périmètre

Dans le périmètre : contournement de l'authentification, fixation/forge de session, redirection ouverte,
fuite du cookie de session ou de secrets, CSRF sur les endpoints d'enrôlement, import de passkey non validé.

Hors périmètre (voir *Modèle de sécurité* dans le [README](README.md#modèle-de-sécurité)) : déni de service
par volume de requêtes (utilisez la limitation de débit de votre reverse proxy), compromission du serveur
ou du volume `/data`, vulnérabilités du site protégé lui-même.
