// =============================================================
// STATISTIQUES DU TABLEAU DE BORD (utils/dashboard-stats.js)
//
// Rassemble les donnees affichees sur /dashboard et exposees en
// JSON sur /dashboard/stats (rafraichissement auto cote client).
//
// Regles de securite :
//   - AUCUNE donnee sensible ne sort d'ici : jamais de passwordHash
//     ni de totpSecret (seuls des COMPTEURS et des evenements
//     d'audit deja publics pour le role connecte).
//   - Ne leve JAMAIS d'erreur : si PostgreSQL est injoignable, le
//     dashboard affiche "base injoignable" au lieu de planter
//     (meme philosophie que utils/audit.js).
// =============================================================

const { sequelize, User, Role } = require("../models");
const { lireDerniersEvenements } = require("./audit");

const LIGNES_AUDIT_LUES = 2000; // borne : assez pour 7 jours d'historique
const MS_PAR_JOUR = 24 * 60 * 60 * 1000;

// "2026-09-17T..." -> "17/09" (etiquette courte pour les graphiques)
function etiquetteJour(date) {
  const jj = String(date.getUTCDate()).padStart(2, "0");
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${jj}/${mm}`;
}

// Compteurs utilisateurs + repartition par role + adoption 2FA.
// Seuls id/totpEnabled sont lus : aucune empreinte ne transite.
async function statsUtilisateurs() {
  const resultat = { total: 0, parRole: { stagiaire: 0, admin: 0, superadmin: 0 }, totpActives: 0 };
  const users = await User.findAll({
    attributes: ["id", "totpEnabled"],
    include: [{ model: Role, attributes: ["name"] }],
  });
  resultat.total = users.length;
  for (const u of users) {
    const nomRole = u.Role ? u.Role.name : null;
    if (nomRole && Object.hasOwn(resultat.parRole, nomRole)) resultat.parRole[nomRole] += 1;
    if (u.totpEnabled) resultat.totpActives += 1;
  }
  return resultat;
}

// Sessions web actives : table "sessions" (connect-pg-simple).
// Seules les sessions NON expirees comptent (expire > NOW()).
async function sessionsActives() {
  const lignes = await sequelize.query(
    "SELECT COUNT(*)::int AS total FROM sessions WHERE expire > NOW()",
    { type: sequelize.QueryTypes.SELECT }
  );
  return lignes[0] ? lignes[0].total : 0;
}

// Ping PostgreSQL : prouve que la base repond (et mesure la latence).
async function etatBase() {
  const debut = Date.now();
  await sequelize.query("SELECT 1", { type: sequelize.QueryTypes.SELECT });
  return { ok: true, latenceMs: Date.now() - debut };
}

// Agregats issus du journal d'audit (dernières lignes seulement) :
//   - parNiveau24h : compteur info/notice/warning/critical (24 h)
//   - critiques24h : idem pour "critical" seul (pastille d'alerte)
//   - connexions7j : LOGIN_SUCCESS par jour (courbe 7 jours)
//   - recents      : 5 derniers evenements (bruts, echappes a l'affichage)
function statsAudit() {
  const resultat = {
    parNiveau24h: { info: 0, notice: 0, warning: 0, critical: 0 },
    critiques24h: 0,
    connexions7j: { labels: [], data: [] },
    recents: [],
  };

  const maintenant = Date.now();
  const evenements = lireDerniersEvenements(LIGNES_AUDIT_LUES);

  // Fenetre glissante de 7 jours calendaires (UTC) : initialise les 7 compteurs a 0
  const jours = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(maintenant - i * MS_PAR_JOUR);
    const cle = d.toISOString().slice(0, 10); // "AAAA-MM-JJ"
    jours.push({ cle, label: etiquetteJour(d), total: 0 });
  }
  const indexJour = Object.fromEntries(jours.map((j, i) => [j.cle, i]));

  for (const e of evenements) {
    if (!e || !e.horodatage) continue;
    const ts = Date.parse(e.horodatage);
    if (Number.isNaN(ts)) continue;

    // Compteurs 24 h par niveau (niveaux inconnus ignores)
    if (maintenant - ts <= MS_PAR_JOUR && Object.hasOwn(resultat.parNiveau24h, e.level)) {
      resultat.parNiveau24h[e.level] += 1;
    }
    // Courbe des connexions reussies (7 jours)
    if (e.action === "LOGIN_SUCCESS") {
      const cle = new Date(ts).toISOString().slice(0, 10);
      if (cle in indexJour) jours[indexJour[cle]].total += 1;
    }
  }

  resultat.critiques24h = resultat.parNiveau24h.critical;
  resultat.connexions7j.labels = jours.map((j) => j.label);
  resultat.connexions7j.data = jours.map((j) => j.total);
  resultat.recents = evenements.slice(-5).reverse();
  return resultat;
}

// Point d'entree unique : chaque source est isolee dans son try/catch
// pour qu'une panne (ex. base down) n'empeche pas le reste de s'afficher.
async function collecterStats() {
  const stats = {
    utilisateurs: { total: 0, parRole: { stagiaire: 0, admin: 0, superadmin: 0 }, totpActives: 0 },
    sessionsActives: 0,
    base: { ok: false, latenceMs: null },
    audit: { parNiveau24h: { info: 0, notice: 0, warning: 0, critical: 0 }, critiques24h: 0, connexions7j: { labels: [], data: [] }, recents: [] },
  };

  try {
    stats.utilisateurs = await statsUtilisateurs();
  } catch (err) {
    console.error("Stats dashboard (utilisateurs) :", err.message);
  }
  try {
    stats.sessionsActives = await sessionsActives();
  } catch (err) {
    console.error("Stats dashboard (sessions) :", err.message);
  }
  try {
    stats.base = await etatBase();
  } catch (err) {
    console.error("Stats dashboard (base) :", err.message);
  }
  try {
    stats.audit = statsAudit();
  } catch (err) {
    console.error("Stats dashboard (audit) :", err.message);
  }
  return stats;
}

module.exports = { collecterStats, statsAudit, statsUtilisateurs };
