// =============================================================
// PROTECTION BRUTE FORCE (Phase 6)
//
// Cahier des charges : une IP qui accumule 5 tentatives de login
// infructueuses (mot de passe OU code TOTP) est bloquee 15 minutes.
//
// Suivi en memoire (Map ip -> etat), fenetre glissante de 15 min :
// suffisant pour notre serveur mono-processus. Un login reussi
// blanchit l'IP (les echecs oublies).
//
// Complementaire du limiteur global express-rate-limit monte dans
// app.js (anti-flooding general) : ici on vise le BRUTE FORCE,
// en ne comptant que les ECHECS (un utilisateur maladroit qui
// reussit a la 3e tentative n'est jamais bloque).
// =============================================================

const { journaliserRequete } = require("../utils/audit");

const FENETRE_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ECHECS = 5;

// ip -> { echecs: [timestamps], bloqueJusqua: timestamp }
const tentatives = new Map();

function etatDe(ip) {
  if (!tentatives.has(ip)) {
    tentatives.set(ip, { echecs: [], bloqueJusqua: 0 });
  }
  return tentatives.get(ip);
}

// Menage periodique : la Map ne grossit pas indefiniment
setInterval(() => {
  const maintenant = Date.now();
  for (const [ip, etat] of tentatives) {
    const inutile =
      etat.bloqueJusqua < maintenant &&
      etat.echecs.every((t) => maintenant - t >= FENETRE_MS);
    if (inutile) tentatives.delete(ip);
  }
}, 10 * 60 * 1000).unref();

// Garde a poser devant chaque route de connexion (mdp, TOTP) :
// IP bloquee -> 429 + header Retry-After, la route ne s'execute pas.
// Reponse HTML pour le web, JSON pour l'API (meme garde, deux formats).
const gardeAntiBruteForce = (req, res, next) => {
  const etat = etatDe(req.ip);
  const reste = etat.bloqueJusqua - Date.now();

  if (reste > 0) {
    const secondes = Math.ceil(reste / 1000);
    journaliserRequete(req, {
      action: "RATE_LIMIT_TENTATIVE_PENDANT_BLOCAGE",
      level: "warning",
      username: req.body ? req.body.username : null,
      details: { secondesRestantes: secondes, chemin: req.originalUrl },
    });
    res.set("Retry-After", String(secondes));
    if (req.path.startsWith("/api")) {
      return res
        .status(429)
        .json({ erreur: "Trop de tentatives. Reessayez dans " + secondes + " secondes." });
    }
    return res.status(429).render("429", { secondes });
  }
  next();
};

// A appeler quand une tentative de connexion echoue (mauvais mdp
// OU mauvais code TOTP). Retourne true si ce 5e echec vient de
// declencher le blocage (l'appelant doit alors repondre 429).
function echecLogin(req) {
  const etat = etatDe(req.ip);
  const maintenant = Date.now();

  // on ne garde que les echecs de la fenetre glissante
  etat.echecs = etat.echecs.filter((t) => maintenant - t < FENETRE_MS);
  etat.echecs.push(maintenant);

  if (etat.echecs.length >= MAX_ECHECS) {
    etat.bloqueJusqua = maintenant + FENETRE_MS;
    etat.echecs = [];
    journaliserRequete(req, {
      action: "RATE_LIMIT_BLOCAGE",
      level: "warning",
      username: req.body ? req.body.username : null,
      details: {
        dureeBlocageMinutes: FENETRE_MS / 60000,
        cause: MAX_ECHECS + " tentatives de login infructueuses",
      },
    });
    return true;
  }
  return false;
}

// A appeler quand la connexion aboutit (session complete) :
// l'IP est blanchie, les echecs passes oublies.
function succesLogin(req) {
  tentatives.delete(req.ip);
}

module.exports = { gardeAntiBruteForce, echecLogin, succesLogin };
