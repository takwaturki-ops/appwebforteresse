const express = require("express");
const router = express.Router();

// =============================================================
// UTILISATEUR DE DEMONSTRATION - PROVISOIRE
//
// Le mot de passe est stocke EN CLAIR dans le code : c'est VULNERABLE
// et volontaire pour l'instant. La Phase 2 remplacera ceci par :
//   - des utilisateurs en base PostgreSQL (Sequelize)
//   - des empreintes bcrypt (jamais de mot de passe en clair)
// =============================================================
const DEMO_USER = {
  username: "turki",
  password: "turki123", // EN CLAIR - a remplacer par bcrypt.compare en Phase 2
};

// GET /login - affiche le formulaire
router.get("/login", (req, res) => {
  // Si deja connecte, inutile de se reconnecter
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }
  res.render("login", { erreur: null });
});

// POST /login - traite le formulaire
router.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Message d'erreur VOLONTAIREMENT generique :
  // ne jamais reveler si c'est l'identifiant ou le mot de passe qui est faux
  // (sinon l'attaquant sait quels comptes existent - "user enumeration")
  const erreurGenerique = "Identifiants incorrects.";

  if (username === DEMO_USER.username && password === DEMO_USER.password) {
    // Connexion reussie : on enregistre l'identite dans la session.
    // Le cookie de session (cryptographiquement signe) part vers le navigateur.
    req.session.userId = DEMO_USER.username;
    return res.redirect("/dashboard");
  }

  // Echec : on reaffiche le formulaire avec le message d'erreur.
  // Pensee securite : le champ est reaffiche VIDE (on ne renvoie jamais
  // le mot de passe saisie dans la page).
  return res.status(401).render("login", { erreur: erreurGenerique });
});

// POST /logout - detruit la session puis redirige
router.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

module.exports = router;
