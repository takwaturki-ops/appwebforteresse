// =============================================================
// API REST (Phase 8) - interface programmatique pour scripts et n8n
//
//   POST /api/login            : identifiants -> jeton JWT (15 min)
//   GET  /api/users            : liste des utilisateurs (JSON)
//   POST /api/users/:id/role   : changement de role (superadmin)
//   GET  /api/audit            : derniers evenements d'audit (superadmin,
//                                consomme par n8n en Phase 9)
//
// Differences avec l'interface web :
//   - reponses JSON (pas de pages HTML)
//   - authentification par JWT dans le header Authorization: Bearer
//     (pas de cookie ni de session, pas de CSRF - le jeton doit etre
//     pose explicitement par le code appelant)
//   - RBAC identique au web (meme matrice de roles), reponses 403 JSON
//   - rate limiting identique (le brute force par l'API est bloque
//     exactement comme le brute force web)
// =============================================================

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const router = express.Router();
const { User, Role } = require("../models");
const { journaliserRequete } = require("../utils/audit");
const {
  gardeAntiBruteForce,
  echecLogin,
  succesLogin,
} = require("../middleware/ratelimit");
const { requireJwt, requireRoleApi } = require("../middleware/jwt");

const DUREE_JETON = "15m"; // cahier des charges : jeton ephemerre

// Empreinte bcrypt factice (meme anti-timing-attack que le login web)
const HASH_FACTICE =
  "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBpUuHd0B0FwY8jVJ0mYyOaZQc1mZu";

// -------------------------------------------------------------
// POST /api/login : identifiants -> JWT signe
// -------------------------------------------------------------
router.post("/api/login", gardeAntiBruteForce, async (req, res) => {
  const { username, password } = req.body || {};

  const refuser = (raison) => {
    journaliserRequete(req, {
      action: "API_LOGIN_FAILED",
      level: "warning",
      username: username || null,
      details: { raison },
    });
    if (echecLogin(req)) {
      return res
        .set("Retry-After", "900")
        .status(429)
        .json({ erreur: "Trop de tentatives. Reessayez dans 15 minutes." });
    }
    return res.status(401).json({ erreur: "Identifiants incorrects." });
  };

  try {
    const user = await User.findOne({
      where: { username },
      include: Role,
    });

    if (!user) {
      await bcrypt.compare(String(password ?? ""), HASH_FACTICE);
      return refuser("compte_inconnu");
    }

    const motDePasseOk = await user.verifyPassword(String(password ?? ""));
    if (!user.isActive || !motDePasseOk) {
      return refuser(
        user.isActive ? "mot_de_passe_incorrect" : "compte_desactive"
      );
    }

    // Fabrication du bracelet : charge utile LISIBLE (pas de secret)
    // + signature HMAC (JWT_SECRET) impossible a falsifier.
    const jeton = jwt.sign(
      {
        sub: user.id,
        username: user.username,
        role: user.Role.name,
      },
      process.env.JWT_SECRET,
      { expiresIn: DUREE_JETON }
    );

    journaliserRequete(req, {
      action: "API_LOGIN_SUCCESS",
      level: "notice",
      username: user.username,
      details: { role: user.Role.name, dureeJeton: DUREE_JETON },
    });
    succesLogin(req); // IP blanchie

    return res.json({ token: jeton, expiresIn: DUREE_JETON, role: user.Role.name });
  } catch (err) {
    console.error("Erreur /api/login :", err.message);
    return res.status(500).json({ erreur: "Erreur interne." });
  }
});

// -------------------------------------------------------------
// GET /api/users : liste des utilisateurs (admin + superadmin)
// -------------------------------------------------------------
router.get(
  "/api/users",
  requireJwt,
  requireRoleApi("admin", "superadmin"),
  async (req, res) => {
    try {
      const users = await User.findAll({
        include: Role,
        order: [["username", "ASC"]],
        // jamais d'empreintes ni de secrets TOTP dans les reponses
        attributes: { exclude: ["passwordHash", "totpSecret"] },
      });
      res.json({
        users: users.map((u) => ({
          id: u.id,
          username: u.username,
          email: u.email,
          role: u.Role.name,
          totpEnabled: u.totpEnabled,
          isActive: u.isActive,
        })),
      });
    } catch (err) {
      console.error("Erreur /api/users :", err.message);
      res.status(500).json({ erreur: "Erreur interne." });
    }
  }
);

// -------------------------------------------------------------
// POST /api/users/:id/role : changement de role (SUPERADMIN seul)
// Endpoint utilise par n8n pour valider les elevations de privileges
// a distance (Phase 9).
// -------------------------------------------------------------
router.post(
  "/api/users/:id/role",
  requireJwt,
  requireRoleApi("superadmin"),
  async (req, res) => {
    try {
      const cible = await User.findByPk(req.params.id, { include: Role });
      const nouveauRole = await Role.findOne({ where: { name: req.body?.role } });

      if (!cible || !nouveauRole) {
        return res.status(404).json({ erreur: "Utilisateur ou role inconnu." });
      }

      // Anti-verrouillage : jamais son propre role (idem interface web)
      if (cible.id === req.utilisateur.sub) {
        return res.status(400).json({ erreur: "Impossible de modifier son propre role." });
      }

      const ancienRole = cible.Role.name;
      cible.roleId = nouveauRole.id;
      await cible.save();

      journaliserRequete(req, {
        action: "ROLE_CHANGED",
        level: "notice",
        username: req.utilisateur.username,
        details: {
          cible: cible.username,
          ancienRole,
          nouveauRole: nouveauRole.name,
          via: "api",
        },
      });

      res.json({
        cible: cible.username,
        ancienRole,
        nouveauRole: nouveauRole.name,
      });
    } catch (err) {
      console.error("Erreur /api/users/:id/role :", err.message);
      res.status(500).json({ erreur: "Erreur interne." });
    }
  }
);

// -------------------------------------------------------------
// GET /api/audit?limit=50 : derniers evenements du journal
// (superadmin uniquement) - n8n interrogera cet endpoint pour
// surveiller les creations d'admins et les blocages brute force.
// -------------------------------------------------------------
router.get(
  "/api/audit",
  requireJwt,
  requireRoleApi("superadmin"),
  (req, res) => {
    const limite = Math.min(parseInt(req.query.limit || "50", 10) || 50, 200);
    const fichier = path.join(__dirname, "..", "logs", "audit.log");

    if (!fs.existsSync(fichier)) {
      return res.json({ evenements: [] });
    }

    const lignes = fs
      .readFileSync(fichier, "utf8")
      .trim()
      .split("\n")
      .slice(-limite);

    const evenements = [];
    for (const ligne of lignes) {
      try {
        evenements.push(JSON.parse(ligne));
      } catch {
        // ligne incomplete (ecriture concurrente) : ignoree
      }
    }
    res.json({ evenements });
  }
);

module.exports = router;
