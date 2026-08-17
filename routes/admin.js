// =============================================================
// GESTION DES UTILISATEURS (Phase 4 - RBAC)
//
//   GET  /admin/users        : liste        -> admin + superadmin
//   GET  /admin/users/new    : formulaire   -> admin + superadmin
//   POST /admin/users        : creation     -> admin (stagiaire uniquement)
//                                              superadmin (tous roles)
//   POST /admin/users/:id/role : privileges -> SUPERADMIN SEULEMENT
//
// Regles appliquees :
//   - un admin ne peut creer que des comptes "stagiaire" (standards)
//   - seul un superadmin modifie les roles
//   - personne ne change son propre role (anti-verrouillage)
//   - chaque action sensible est journalisee dans l'audit
// =============================================================

const express = require("express");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");

const router = express.Router();
const { User, Role } = require("../models");
const { requireRole } = require("../middleware/role");
const { journaliserRequete } = require("../utils/audit");

const COUT_BCRYPT = 12;
const NB_ROLES = 3; // stagiaire, admin, superadmin

// Regles de validation du formulaire de creation.
// express-validator : chaque entree utilisateur est verifiee AVANT
// traitement - longueur, format, appartenance a une liste ferree.
const validateurCreation = [
  body("username")
    .trim()
    .matches(/^[a-zA-Z0-9_.-]{3,50}$/)
    .withMessage("Identifiant : 3 a 50 caracteres (lettres, chiffres, _ . -)"),
  body("email").trim().isEmail().withMessage("Adresse email invalide").normalizeEmail(),
  body("password")
    .isLength({ min: 12 })
    .withMessage("Mot de passe : 12 caracteres minimum"),
  body("role")
    .isIn(["stagiaire", "admin", "superadmin"])
    .withMessage("Role inconnu"),
];

// -------------------------------------------------------------
// LISTE DES UTILISATEURS
// -------------------------------------------------------------
router.get("/admin/users", requireRole("admin", "superadmin"), async (req, res, next) => {
  try {
    const users = await User.findAll({
      include: Role,
      order: [["username", "ASC"]],
      attributes: { exclude: ["passwordHash", "totpSecret"] }, // jamais d'empreintes dans la vue
    });
    res.render("admin/users", { users, monId: req.session.userId });
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// FORMULAIRE DE CREATION
// -------------------------------------------------------------
router.get("/admin/users/new", requireRole("admin", "superadmin"), (req, res) => {
  // Un admin ne peut creer que des comptes standards ; le champ
  // role du formulaire est donc restreint selon QUI cree.
  const rolesChoisissables =
    req.session.role === "superadmin" ? ["stagiaire", "admin", "superadmin"] : ["stagiaire"];
  res.render("admin/users-new", { rolesChoisissables, erreurs: null, valeurs: {} });
});

// -------------------------------------------------------------
// CREATION (traitement du formulaire)
// -------------------------------------------------------------
router.post(
  "/admin/users",
  requireRole("admin", "superadmin"),
  validateurCreation,
  async (req, res, next) => {
    const erreurs = validationResult(req).array({ onlyFirstError: true });

    // Verifie a nouveau la regle de privilege : un admin qui
    // forgerait la requete avec role=admin/superadmin doit etre bloque
    // (ne jamais se fier au formulaire cote client)
    const roleDemande = req.body.role;
    if (req.session.role === "admin" && roleDemande !== "stagiaire") {
      journaliserRequete(req, {
        action: "PRIVILEGE_ESCALATION_BLOCKED",
        level: "critical",
        username: req.session.username,
        details: { tentativeRole: roleDemande, chemin: req.originalUrl },
      });
      erreurs.push({ msg: "Un admin ne peut creere que des comptes stagiaire." });
    }

    const rolesChoisissables =
      req.session.role === "superadmin" ? ["stagiaire", "admin", "superadmin"] : ["stagiaire"];

    if (erreurs.length > 0) {
      return res.status(400).render("admin/users-new", {
        rolesChoisissables,
        erreurs,
        valeurs: req.body,
      });
    }

    try {
      const role = await Role.findOne({ where: { name: roleDemande } });
      const hash = await bcrypt.hash(req.body.password, COUT_BCRYPT);

      const user = await User.create({
        username: req.body.username,
        email: req.body.email,
        passwordHash: hash,
        roleId: role.id,
      });

      journaliserRequete(req, {
        action: "USER_CREATED",
        level: "notice",
        username: req.session.username,
        details: { cible: user.username, nouveauRole: roleDemande },
      });

      res.redirect("/admin/users");
    } catch (err) {
      // Doublon username/email (contrainte unique PostgreSQL)
      if (err.name === "SequelizeUniqueConstraintError") {
        return res.status(400).render("admin/users-new", {
          rolesChoisissables,
          erreurs: [{ msg: "Identifiant ou email deja utilise." }],
          valeurs: req.body,
        });
      }
      next(err);
    }
  }
);

// -------------------------------------------------------------
// CHANGEMENT DE ROLE - SUPERADMIN UNIQUEMENT
// -------------------------------------------------------------
router.post(
  "/admin/users/:id/role",
  requireRole("superadmin"),
  async (req, res, next) => {
    try {
      const cible = await User.findByPk(req.params.id, { include: Role });
      const nouveauRole = await Role.findOne({ where: { name: req.body.role } });

      if (!cible || !nouveauRole) {
        return res.status(404).render("403", { chemin: req.originalUrl, roleUtilisateur: req.session.role, rolesRequis: ["superadmin"] });
      }

      // Anti-verrouillage : interdiction de modifier son propre role
      if (cible.id === req.session.userId) {
        return res.status(400).render("admin/users", {
          users: await User.findAll({ include: Role, order: [["username", "ASC"]] }),
          monId: req.session.userId,
          erreur: "Vous ne pouvez pas modifier votre propre role.",
        });
      }

      const ancienRole = cible.Role.name;
      cible.roleId = nouveauRole.id;
      await cible.save();

      journaliserRequete(req, {
        action: "ROLE_CHANGED",
        level: "notice",
        username: req.session.username,
        details: { cible: cible.username, ancienRole, nouveauRole: nouveauRole.name },
      });

      res.redirect("/admin/users");
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
