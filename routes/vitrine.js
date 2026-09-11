const express = require("express");
const router = express.Router();

// GET /vitrine - page publique de demonstration du projet.
// Volontairement SANS requireAuth/requireRole : l'encadrant la consulte
// seul, sans compte. En contrepartie, cette route est strictement
// passive : aucun formulaire POST (pas de CSRF possible), aucune
// requete base de donnees, aucune ecriture dans l'audit.
// Les identifiants affiches viennent du .env (process.env), JAMAIS
// en dur dans le code ni dans le template (cf. .gitignore).
router.get("/vitrine", (req, res) => {
  res.render("vitrine", {
    demo: {
      stagiaire: {
        username: process.env.DEMO_STAGIAIRE_USER,
        password: process.env.DEMO_STAGIAIRE_PASS,
      },
      admin: {
        username: process.env.DEMO_ADMIN_USER,
        password: process.env.DEMO_ADMIN_PASS,
      },
      superadmin: {
        username: process.env.DEMO_SUPERADMIN_USER,
        password: process.env.DEMO_SUPERADMIN_PASS,
      },
    },
  });
});

module.exports = router;
