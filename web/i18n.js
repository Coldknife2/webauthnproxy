"use strict";
// Minimal i18n: English by default, French with ?lang=fr (remembered in localStorage).
const I18N = {
  en: {
    loginTitle: "Sign in", loginHeading: "🔐 Sign in", loginText: "Authenticate with your passkey.", loginButton: "Sign in with a passkey",
    enrollTitle: "Passkey enrollment", bootHint: "No passkey exists yet. Enter the bootstrap token printed in the service logs.",
    token: "Bootstrap token", labelPh: "Label (e.g. phone)", username: "User name", addPasskey: "Add a passkey", registered: "Registered passkeys",
    signOut: "Sign out", signedInAs: "Signed in as", none: "None.", del: "Delete", passkeyN: "passkey #",
    sessionsTitle: "My sessions", sessionsHint: "Where you are signed in. End the ones you do not recognise.", thisOne: "this one", loginHost: "login host",
    since: "since", lastSeen: "last activity", endSession: "End", endOthers: "End all other sessions", confirmEnd: "End this session?", confirmOthers: "End all other sessions?",
    addTitle: "Add a passkey", addIntro: "This one-time link adds a passkey for", addLabelPh: "Label (e.g. phone)", addNoCode: "This link has no code. Ask for a new invitation.",
    addDone: "Passkey added ✔ You can close this page.", mySessions: "My sessions",
    follow: "Follow your browser's instructions…", saved: "Passkey saved ✔", confirmDelete: "Delete this passkey?",
  },
  fr: {
    loginTitle: "Connexion", loginHeading: "🔐 Connexion", loginText: "Authentifiez-vous avec votre passkey.", loginButton: "Se connecter avec une passkey",
    enrollTitle: "Enrôlement des passkeys", bootHint: "Aucune passkey n'existe encore. Saisissez le jeton d'amorçage affiché dans les logs du service.",
    token: "Jeton d'amorçage", labelPh: "Libellé (ex. téléphone)", username: "Nom d'utilisateur", addPasskey: "Ajouter une passkey", registered: "Passkeys enregistrées",
    signOut: "Se déconnecter", signedInAs: "Connecté en tant que", none: "Aucune.", del: "Supprimer", passkeyN: "passkey n°",
    sessionsTitle: "Mes sessions", sessionsHint: "Où vous êtes connecté. Terminez celles que vous ne reconnaissez pas.", thisOne: "celle-ci", loginHost: "hôte de connexion",
    since: "depuis", lastSeen: "dernière activité", endSession: "Terminer", endOthers: "Terminer toutes les autres sessions", confirmEnd: "Terminer cette session ?", confirmOthers: "Terminer toutes les autres sessions ?",
    addTitle: "Ajouter une passkey", addIntro: "Ce lien à usage unique ajoute une passkey pour", addLabelPh: "Libellé (ex. téléphone)", addNoCode: "Ce lien ne contient pas de code. Demandez une nouvelle invitation.",
    addDone: "Passkey ajoutée ✔ Vous pouvez fermer cette page.", mySessions: "Mes sessions",
    follow: "Suivez les instructions du navigateur…", saved: "Passkey enregistrée ✔", confirmDelete: "Supprimer cette passkey ?",
  },
};
const LANG = (() => {
  let l = new URLSearchParams(location.search).get("lang");
  try { if (l in I18N) localStorage.setItem("wap_lang", l); else l = localStorage.getItem("wap_lang"); } catch (e) { /* storage unavailable */ }
  return l in I18N ? l : "en";
})();
const t = (k) => I18N[LANG][k] || I18N.en[k] || k;
document.documentElement.lang = LANG;
for (const el of document.querySelectorAll("[data-i18n]")) el.textContent = t(el.dataset.i18n);
for (const el of document.querySelectorAll("[data-i18n-ph]")) el.placeholder = t(el.dataset.i18nPh);
if (document.documentElement.dataset.i18nTitle) document.title = t(document.documentElement.dataset.i18nTitle);
