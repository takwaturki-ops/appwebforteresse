// =============================================================
// JOURNAL D'AUDIT (utils/audit.js)
//
// Chaque evenement sensible est ecrit en UNE ligne JSON dans
// logs/audit.log (format "JSON lines" : 1 objet JSON par ligne,
// facilement parsable et aggregable).
//
// Phase 4 : alertes ACCESS_DENIED (403), creations de comptes,
// changements de roles.
// Phase 7 : etendra aux connexions reussies/echouees, blocages
// rate-limit, etc.
//
// appendFileSync : chaque ecriture ouvre, ecrit a la FIN et ferme
// le fichier - on ne reecrit jamais l'historique (journal append-only).
// =============================================================

const fs = require("fs");
const path = require("path");

const DOSSIER_LOGS = path.join(__dirname, "..", "logs");
const FICHIER_AUDIT = path.join(DOSSIER_LOGS, "audit.log");

// Cree le dossier logs/ s'il n'existe pas (une seule fois)
if (!fs.existsSync(DOSSIER_LOGS)) {
  fs.mkdirSync(DOSSIER_LOGS, { recursive: true });
}

// journaliser({ action, level?, username?, ip?, userAgent?, details? })
// Ne leve JAMAIS d'erreur : un probleme d'audit ne doit pas faire
// tomber la requete traitee (mais il est signale en console).
function journaliser(entree) {
  const ligne = JSON.stringify({
    horodatage: new Date().toISOString(),
    action: entree.action,
    level: entree.level || "info",
    username: entree.username || null,
    ip: entree.ip || null,
    userAgent: entree.userAgent || null,
    details: entree.details || null,
  });

  try {
    fs.appendFileSync(FICHIER_AUDIT, ligne + "\n", { mode: 0o640 });
  } catch (err) {
    console.error("ECHEC ecriture audit.log :", err.message);
  }
}

// Variante pratique : extrait ip/userAgent d'une requete Express
function journaliserRequete(req, entree) {
  journaliser({
    ...entree,
    ip: req.ip,
    userAgent: req.get("User-Agent"),
  });
}

// Lecture des N derniers evenements (ordre du fichier : les plus
// anciens d'abord). Utilisee par la page web /admin/audit (superadmin)
// et par l'endpoint API GET /api/audit (n8n).
// Les lignes incompletes (ecriture concurrente) sont ignorees.
function lireDerniersEvenements(limite = 100) {
  if (!fs.existsSync(FICHIER_AUDIT)) return [];
  const lignes = fs
    .readFileSync(FICHIER_AUDIT, "utf8")
    .trim()
    .split("\n")
    .slice(-limite);

  const evenements = [];
  for (const ligne of lignes) {
    try {
      evenements.push(JSON.parse(ligne));
    } catch {
      // ligne incomplete : ignoree
    }
  }
  return evenements;
}

module.exports = { journaliser, journaliserRequete, lireDerniersEvenements };

// =============================================================
// FILTRAGE POUR LA PAGE /admin/audit (Phase 10)
//
// Tous les parametres viennent de l'URL (?niveau=&action=&q=) :
// ils sont valides ici par LISTES BLANCHES, jamais reutilises
// tels quels (un niveau inconnu = filtre ignore, pas d'erreur).
// Retourne les evenements du PLUS ANCIEN au plus recent (meme
// convention que lireDerniersEvenements : la route inverse).
// =============================================================

const NIVEAUX_VALIDES = ["info", "notice", "warning", "critical"];

// Actions tracées par l'application (README) : seules celles-ci
// sont proposées dans le filtre et acceptees depuis l'URL.
const ACTIONS_CONNUES = [
  "LOGIN_SUCCESS",
  "LOGIN_FAILED",
  "TOTP_FAILED",
  "LOGOUT",
  "ACCESS_DENIED",
  "CSRF_BLOCKED",
  "USER_CREATED",
  "ROLE_CHANGED",
  "PRIVILEGE_ESCALATION_BLOCKED",
  "RATE_LIMIT_BLOCAGE",
  "API_LOGIN_SUCCESS",
  "API_LOGIN_FAILED",
  "API_ACCESS_DENIED",
];

const LIGNES_MAX_FILTRE = 2000; // borne anti-abus (fichier potentiellement gros)
const RECHERCHE_MAX = 64; // idem (username / IP / action)

// { niveau?, action?, recherche? } -> [evenements filtres]
function filtrerEvenements({ niveau, action, recherche } = {}) {
  const niveauOk = NIVEAUX_VALIDES.includes(niveau) ? niveau : null;
  const actionOk = ACTIONS_CONNUES.includes(action) ? action : null;
  const rechercheOk =
    typeof recherche === "string" && recherche.trim() !== ""
      ? recherche.trim().slice(0, RECHERCHE_MAX).toLowerCase()
      : null;

  return lireDerniersEvenements(LIGNES_MAX_FILTRE).filter((e) => {
    if (!e) return false;
    if (niveauOk && e.level !== niveauOk) return false;
    if (actionOk && e.action !== actionOk) return false;
    if (rechercheOk) {
      // Recherche insensible a la casse sur acteur, IP et action.
      // (Comparaison en minuscules ; l'affichage reste echappe par EJS.)
      const cible = `${e.username || ""} ${e.ip || ""} ${e.action || ""}`.toLowerCase();
      if (!cible.includes(rechercheOk)) return false;
    }
    return true;
  });
}

module.exports.filtrerEvenements = filtrerEvenements;
module.exports.NIVEAUX_VALIDES = NIVEAUX_VALIDES;
module.exports.ACTIONS_CONNUES = ACTIONS_CONNUES;
