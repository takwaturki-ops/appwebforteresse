// =============================================================
// SIMULATEUR N8N (Phase 9)
//
// Reproduit EXACTEMENT le comportement du workflow n8n "Surveillance
// Forteresse" (a recreer dans l'instance Azure - voir
// docs/n8n-workflows.md) :
//
//   1. s'authentifier sur l'API -> JWT
//   2. relever les derniers evenements d'audit
//   3. detecter les evenements critiques :
//        - USER_CREATED avec role admin/superadmin
//        - RATE_LIMIT_BLOCAGE (brute force en cours)
//        - PRIVILEGE_ESCALATION_BLOCKED
//   4. emettre les alertes (ici : console ; dans n8n : email/Teams)
//
// Usage : node scripts/n8n-simulation.js [baseURL]
//   baseURL par defaut : http://localhost:3000
//
// Compte utilise : N8N_USER / N8N_PASSWORD du .env (compte dedie
// a l'automatisation, role superadmin en lecture - a creer via
// l'interface web si absent).
// =============================================================

require("dotenv").config();

const BASE_URL = process.argv[2] || "http://localhost:3000";
const IDENTIFIANTS = {
  username: process.env.N8N_USER || "n8n-bot",
  password: process.env.N8N_PASSWORD || "",
};

// Evenements qui declenchent une alerte SecOps
const EVENEMENTS_CRITIQUES = new Set([
  "RATE_LIMIT_BLOCAGE",
  "PRIVILEGE_ESCALATION_BLOCKED",
  "API_ACCESS_DENIED",
]);

async function obtenirJeton() {
  const reponse = await fetch(`${BASE_URL}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(IDENTIFIANTS),
  });
  if (!reponse.ok) {
    throw new Error(`Echec authentification API (${reponse.status}) : ${await reponse.text()}`);
  }
  const donnees = await reponse.json();
  console.log(`[n8n] Authentifie : ${IDENTIFIANTS.username} (${donnees.role}), jeton valable ${donnees.expiresIn}`);
  return donnees.token;
}

async function releverAudit(jeton) {
  const reponse = await fetch(`${BASE_URL}/api/audit?limit=100`, {
    headers: { Authorization: `Bearer ${jeton}` },
  });
  if (!reponse.ok) {
    throw new Error(`Echec lecture audit (${reponse.status})`);
  }
  const donnees = await reponse.json();
  return donnees.evenements;
}

function analyser(evenements) {
  const alertes = [];
  for (const e of evenements) {
    if (EVENEMENTS_CRITIQUES.has(e.action)) {
      alertes.push({ type: e.action, severite: e.level, qui: e.username, details: e.details });
      continue;
    }
    // Creation d'un NOUVEL administrateur (admin ou superadmin)
    if (
      e.action === "USER_CREATED" &&
      e.details &&
      (e.details.nouveauRole === "admin" || e.details.nouveauRole === "superadmin")
    ) {
      alertes.push({
        type: "NOUVEL_ADMINISTRATEUR",
        severite: "notice",
        qui: e.username,
        details: e.details,
      });
    }
    // Changement de privilege vers admin/superadmin
    if (
      e.action === "ROLE_CHANGED" &&
      e.details &&
      (e.details.nouveauRole === "admin" || e.details.nouveauRole === "superadmin")
    ) {
      alertes.push({
        type: "ELEVATION_PRIVILEGE",
        severite: "notice",
        qui: e.username,
        details: e.details,
      });
    }
  }
  return alertes;
}

// Dans n8n, ce step = node "Send Email" / "Microsoft Teams" / "Slack"
function emettreAlertes(alertes) {
  if (alertes.length === 0) {
    console.log("[n8n] Aucun evenement critique detecte. Prochaine verification dans 5 min.");
    return;
  }
  console.log(`\n[n8n] !!! ${alertes.length} ALERTE(S) SECOPS !!!`);
  for (const a of alertes) {
    console.log(`  [${a.severite.toUpperCase()}] ${a.type} (par ${a.qui}) : ${JSON.stringify(a.details)}`);
  }
  console.log("");
}

(async () => {
  console.log(`[n8n] Surveillance Forteresse - cible : ${BASE_URL}`);
  try {
    const jeton = await obtenirJeton();
    const evenements = await releverAudit(jeton);
    console.log(`[n8n] ${evenements.length} evenements d'audit releves.`);
    const alertes = analyser(evenements);
    emettreAlertes(alertes);
  } catch (err) {
    console.error(`[n8n] ERREUR : ${err.message}`);
    process.exit(1);
  }
})();
