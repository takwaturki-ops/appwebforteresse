// =============================================================
// MIDDLEWARE RBAC - controle d'acces base sur les roles (Phase 4)
//
// Matrice des droits (cahier des charges) :
//   stagiaire  : lecture seule du tableau de bord
//   admin      : + gestion des utilisateurs STANDARDS (creation,
//                pas de changement de roles)
//   superadmin : + modification des privileges + consultation
//                des logs d'audit
//
// Tout acces sans le role adequat -> 403 Forbidden + UNE ENTREE
// D'ALERTE dans le journal d'audit (exigence du cahier des charges).
// =============================================================

const { journaliserRequete } = require("../utils/audit");

// Fabrique de middleware : requireRole("admin", "superadmin")
// retourne le garde correspondant. La session complete (mot de
// passe + TOTP valides) est exigee au prealable.
const requireRole = (...rolesAutorises) => {
  return (req, res, next) => {
    // Pas de session complete -> retour au login (pas un 403 :
    // on ne sait meme pas qui demande)
    if (!req.session || !req.session.userId) {
      return res.redirect("/login");
    }

    if (rolesAutorises.includes(req.session.role)) {
      return next(); // role autorise -> acces
    }

    // ACCES REFUSE : 403 + alerte d'audit (action, qui, ou, quel role)
    journaliserRequete(req, {
      action: "ACCESS_DENIED",
      level: "warning",
      username: req.session.username,
      details: {
        chemin: req.originalUrl,
        roleUtilisateur: req.session.role,
        rolesRequis: rolesAutorises,
      },
    });

    return res.status(403).render("403", {
      chemin: req.originalUrl,
      roleUtilisateur: req.session.role,
      rolesRequis: rolesAutorises,
    });
  };
};

module.exports = { requireRole };
