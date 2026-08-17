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

module.exports = { journaliser, journaliserRequete };
