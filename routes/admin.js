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
const { Op } = require("sequelize");

const router = express.Router();
const { User, Role } = require("../models");
const { requireRole } = require("../middleware/role");
const { journaliserRequete, filtrerEvenements, NIVEAUX_VALIDES, ACTIONS_CONNUES } = require("../utils/audit");
const { statsAudit, statsUtilisateurs } = require("../utils/dashboard-stats");

// Tailles de page proposees (liste fermee : pas de ?limit=100000).
const LIMITES_PAGE = [20, 50, 100];
const LIMITE_DEFAUT = 20;

// Colonnes triables (liste blanche : rien d'autre ne passe au ORDER BY,
// sinon injection SQL via le tri — Sequelize echapperait quand meme,
// mais on ne laisse rien au hasard).
const TRIS_VALIDES = ["username", "email", "role"];
const TRI_DEFAUT = "username";

// Construit la clause ORDER BY Sequelize a partir d'un tri valide.
// Tri par role = tri sur la table jointe Role (include -> alias "Role").
function ordreSequelize(tri, sens) {
  const direction = sens === "desc" ? "DESC" : "ASC";
  if (tri === "role") return [[{ model: Role, as: "Role" }, "name", direction]];
  return [[tri, direction]];
}

// Chaine de requete encodee a partir d'un objet { cle: valeur }.
// Sert a construire les liens de tri/pagination qui conservent les
// autres parametres. URLSearchParams encode tout (XSS impossible
// dans les href, affiches de surcroit via <%= %>).
function chaineRequete(obj) {
  const params = new URLSearchParams();
  for (const [cle, valeur] of Object.entries(obj)) {
    if (valeur !== "" && valeur !== null && valeur !== undefined) params.set(cle, String(valeur));
  }
  return params.toString();
}

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
// LISTE DES UTILISATEURS (recherche + filtres + tri + pagination)
//
// Tous les parametres d'URL sont valides par listes blanches :
// role/tri/sens/limit inconnus -> valeur par defaut, jamais d'erreur.
// La recherche q est bornee a 64 caracteres et passe en ILIKE
// (parametre : Sequelize echappe, aucune concatenation SQL).
// -------------------------------------------------------------
router.get("/admin/users", requireRole("admin", "superadmin"), async (req, res, next) => {
  try {
    const q = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 64) : "";
    const role = ["stagiaire", "admin", "superadmin"].includes(req.query.role) ? req.query.role : "";
    const totp = ["oui", "non"].includes(req.query.totp) ? req.query.totp : "";
    const tri = TRIS_VALIDES.includes(req.query.tri) ? req.query.tri : TRI_DEFAUT;
    const sens = req.query.sens === "desc" ? "desc" : "asc";
    const limite = LIMITES_PAGE.includes(Number(req.query.limit)) ? Number(req.query.limit) : LIMITE_DEFAUT;

    // Clause WHERE : recherche (username OU email, insensible a la
    // casse) + filtre role (jointure) + filtre 2FA.
    const where = {};
    if (q) where[Op.or] = [{ username: { [Op.iLike]: `%${q}%` } }, { email: { [Op.iLike]: `%${q}%` } }];
    if (totp === "oui") where.totpEnabled = true;
    if (totp === "non") where.totpEnabled = false;
    const includeRole = { model: Role, attributes: ["name"], ...(role ? { where: { name: role } } : {}) };

    const total = await User.count({ where, include: [includeRole] });
    const pages = Math.max(1, Math.ceil(total / limite));
    const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), pages);

    const users = await User.findAll({
      where,
      include: [includeRole],
      order: ordreSequelize(tri, sens),
      limit: limite,
      offset: (page - 1) * limite,
      attributes: { exclude: ["passwordHash", "totpSecret"] }, // jamais d'empreintes dans la vue
    });

    // qsBase = filtres seuls (les liens de TRI repartent page 1) ;
    // qsPage = filtres + tri (les liens de PAGINATION gardent le tri).
    const baseFiltrage = { q, role, totp, ...(limite !== LIMITE_DEFAUT ? { limit: limite } : {}) };
    const qsBase = chaineRequete(baseFiltrage);
    const qsPage = chaineRequete({ ...baseFiltrage, tri, sens });

    res.render("admin/users", {
      users,
      monId: req.session.userId,
      pagination: { page, pages, total, limite },
      filtres: { q, role, totp, tri, sens },
      qsBase,
      qsPage,
      limites: LIMITES_PAGE,
      repartition: await statsUtilisateurs(),
      large: true, // mise en page elargie (tableau large)
    });
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

      // Anti-verrouillage : interdiction de modifier son propre role.
      // On re-affiche la liste (page 1, sans filtre) AVEC toutes les
      // variables de la vue paginee, sinon le template plante.
      if (cible.id === req.session.userId) {
        const tous = await User.findAll({
          include: [{ model: Role, attributes: ["name"] }],
          order: [["username", "ASC"]],
          attributes: { exclude: ["passwordHash", "totpSecret"] },
        });
        return res.status(400).render("admin/users", {
          users: tous,
          monId: req.session.userId,
          pagination: { page: 1, pages: 1, total: tous.length, limite: LIMITE_DEFAUT },
          filtres: { q: "", role: "", totp: "", tri: TRI_DEFAUT, sens: "asc" },
          qsBase: "",
          qsPage: `tri=${TRI_DEFAUT}&sens=asc`,
          limites: LIMITES_PAGE,
          repartition: await statsUtilisateurs(),
          large: true,
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

// -------------------------------------------------------------
// JOURNAL D'AUDIT - SUPERADMIN UNIQUEMENT (cahier des charges)
// L'affichage des logs du systeme est reserve au superadmin :
// un admin qui tente -> 403 + alerte ACCESS_DENIED (testable).
// -------------------------------------------------------------
router.get("/admin/audit", requireRole("superadmin"), (req, res) => {
  // --- Validation stricte des parametres d'URL (listes blanches) ---
  // niveau/action inconnus -> ignore (pas d'erreur, pas d'injection).
  // page/limit -> entiers bornes (anti-abus : pas de page 0/negative,
  // pas de limite geante qui saturerait le rendu).
  const niveau = NIVEAUX_VALIDES.includes(req.query.niveau) ? req.query.niveau : "";
  const action = ACTIONS_CONNUES.includes(req.query.action) ? req.query.action : "";
  const recherche = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 64) : "";
  const limite = LIMITES_PAGE.includes(Number(req.query.limit)) ? Number(req.query.limit) : LIMITE_DEFAUT;

  // Filtrage (plus anciens d'abord) -> inversion (recents d'abord)
  // -> decoupe de la page demandee.
  const filtres = filtrerEvenements({ niveau, action, recherche }).reverse();
  const total = filtres.length;
  const pages = Math.max(1, Math.ceil(total / limite));
  const page = Math.min(Math.max(parseInt(req.query.page, 10) || 1, 1), pages);
  const evenements = filtres.slice((page - 1) * limite, page * limite);

  // Chaine de requete SANS "page" (reconstruite par la vue pour les
  // liens de pagination). URLSearchParams encode tout : aucun risque
  // d'injection dans les href (affiches via <%= %> de toute facon).
  const params = new URLSearchParams();
  if (niveau) params.set("niveau", niveau);
  if (action) params.set("action", action);
  if (recherche) params.set("q", recherche);
  if (limite !== LIMITE_DEFAUT) params.set("limit", String(limite));
  const qs = params.toString();

  res.render("admin/audit", {
    evenements,
    pagination: { page, pages, total, limite },
    filtres: { niveau, action, recherche },
    qs,
    niveaux: NIVEAUX_VALIDES,
    actions: ACTIONS_CONNUES,
    limites: LIMITES_PAGE,
    stats24h: statsAudit().parNiveau24h,
    large: true, // mise en page elargie (tableau large)
  });
});



module.exports = router;
