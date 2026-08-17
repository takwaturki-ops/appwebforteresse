const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();

// Modeles Sequelize : requetes parametrees -> defense injection SQL (OWASP)
const { User, Role } = require("../models");

// Empreinte bcrypt factice (format valide, cout 12, meme duree de calcul).
// Utilisee quand le compte n'existe pas : le temps de reponse reste
// identique, un attaquant ne peut pas deviner quels comptes existent
// en mesurant la duree des reponses (timing attack / enumeration).
const HASH_FACTICE =
  "$2b$12$C6UzMDM.H6dfI/f/IKcEeO7ZBpUuHd0B0FwY8jVJ0mYyOaZQc1mZu";

// GET /login - affiche le formulaire
router.get("/login", (req, res) => {
  if (req.session.userId) {
    return res.redirect("/dashboard");
  }
  res.render("login", { erreur: null });
});

// POST /login - traite le formulaire (utilisateurs en base + bcrypt)
router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Message d'erreur VOLONTAIREMENT generique (anti enumeration de comptes)
  const erreurGenerique = "Identifiants incorrects.";

  try {
    // Recherche parametree via l'ORM : la valeur voyage separement du SQL,
    // un payload "'; DROP TABLE users; --" sera traite comme du simple texte.
    const user = await User.findOne({
      where: { username },
      include: { model: Role },
    });

    if (!user) {
      // Compte inconnu : comparaison factice (duree identique) + meme erreur
      await bcrypt.compare(String(password ?? ""), HASH_FACTICE);
      return res.status(401).render("login", { erreur: erreurGenerique });
    }

    // verifyPassword = bcrypt.compare : on re-hache la tentative avec le
    // salt stocke DANS le hash de la base, puis on compare les empreintes.
    // Le mot de passe en clair n'est jamais stocke ni compare directement.
    const motDePasseOk = await user.verifyPassword(String(password ?? ""));

    if (!user.isActive || !motDePasseOk) {
      return res.status(401).render("login", { erreur: erreurGenerique });
    }

    // Succes : identite et role entres en session (cookie signe, HttpOnly)
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.role = user.Role ? user.Role.name : "stagiaire";

    return res.redirect("/dashboard");
  } catch (err) {
    // Erreur technique : message generique aussi (pas de fuite d'information)
    console.error("Erreur pendant le login :", err.message);
    return res
      .status(500)
      .render("login", { erreur: "Erreur interne, reessayez." });
  }
});

// POST /logout - detruit la session puis redirige
router.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

module.exports = router;
