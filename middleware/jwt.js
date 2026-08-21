// =============================================================
// MIDDLEWARES JWT (Phase 8) - authentification de l'API REST
//
// L'API est destinee aux PROGRAMMES (scripts, n8n) : pas de cookie
// ni de formulaire, mais un jeton JWT presente dans le header
// Authorization: Bearer <jeton>.
//
// JWT = 3 morceaux : entete . charge-utile . signature.
// La charge (qui, role, expiration) est LISIBLE par tous mais
// TAMPOREEE par HMAC avec JWT_SECRET : impossible de falsifier le
// role ou l'identite. Le serveur ne stocke RIEN - il recalcule la
// signature a chaque requete et compare.
// Duree de vie courte (15 min) : un jeton vole ne sert presque a rien.
// =============================================================

const jwt = require("jsonwebtoken");
const { journaliserRequete } = require("../utils/audit");

// Verifie : header present, format "Bearer <jeton>", signature valide,
// jeton non expire. En cas de succes, la charge utile est disponible
// dans req.utilisateur (sub, username, role).
const requireJwt = (req, res, next) => {
  const entete = req.get("Authorization") || "";
  const [type, jeton] = entete.split(" ");

  if (type !== "Bearer" || !jeton) {
    return res
      .status(401)
      .json({ erreur: "Jeton manquant. Header attendu : Authorization: Bearer <jeton>" });
  }

  jwt.verify(jeton, process.env.JWT_SECRET, (err, charge) => {
    if (err) {
      // Signature falsifiee OU jeton expire : reponse identique
      // (pas de details sur la raison - anti-information)
      return res.status(401).json({ erreur: "Jeton invalide ou expire." });
    }
    req.utilisateur = charge;
    next();
  });
};

// RBAC version API : meme matrice de droits que le web, reponse JSON.
// Acces sans le role adequu -> 403 + alerte API_ACCESS_DENIED en audit.
const requireRoleApi = (...rolesAutorises) => {
  return (req, res, next) => {
    if (rolesAutorises.includes(req.utilisateur.role)) {
      return next();
    }
    journaliserRequete(req, {
      action: "API_ACCESS_DENIED",
      level: "warning",
      username: req.utilisateur.username,
      details: {
        chemin: req.originalUrl,
        roleUtilisateur: req.utilisateur.role,
        rolesRequis: rolesAutorises,
      },
    });
    return res.status(403).json({ erreur: "Role insuffisant pour cette action." });
  };
};

module.exports = { requireJwt, requireRoleApi };
