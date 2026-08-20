const express = require("express");
const bcrypt = require("bcryptjs");
const router = express.Router();

// Modeles Sequelize : requetes parametrees -> defense injection SQL (OWASP)
const { User, Role } = require("../models");
const { journaliserRequete } = require("../utils/audit");
const {
  gardeAntiBruteForce,
  echecLogin,
} = require("../middleware/ratelimit");

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
// gardeAntiBruteForce : IP bloquee apres 5 echecs -> 429 sans executer
// la route (le mot de passe n'est meme pas examine).
router.post("/login", gardeAntiBruteForce, async (req, res) => {
  const { username, password } = req.body;

  // Message d'erreur VOLONTAIREMENT generique (anti enumeration de comptes)
  const erreurGenerique = "Identifiants incorrects.";

  // Refus unifie : audit LOGIN_FAILED + compteur brute force.
  // La RAISON precise ne va QUE dans l'audit (interne), jamais dans
  // la reponse visible (sinon enumeration de comptes).
  const refuser = (raison) => {
    journaliserRequete(req, {
      action: "LOGIN_FAILED",
      level: "warning",
      username: username || null,
      details: { etape: "mot_de_passe", raison },
    });
    if (echecLogin(req)) {
      // 5e echec : blocage 15 minutes (cahier des charges)
      res.set("Retry-After", "900");
      return res.status(429).render("429", { secondes: 900 });
    }
    return res.status(401).render("login", { erreur: erreurGenerique });
  };

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
      return refuser("compte_inconnu");
    }

    // verifyPassword = bcrypt.compare : on re-hache la tentative avec le
    // salt stocke DANS le hash de la base, puis on compare les empreintes.
    // Le mot de passe en clair n'est jamais stocke ni compare directement.
    const motDePasseOk = await user.verifyPassword(String(password ?? ""));

    if (!user.isActive || !motDePasseOk) {
      return refuser(
        user.isActive ? "mot_de_passe_incorrect" : "compte_desactive"
      );
    }

    // Mot de passe VALIDE - etape 1 sur 2.
    // On ne cree PAS encore la session complete : seulement une
    // demi-session (pending2fa) en attendant le code TOTP.
    // needsSetup : true si la 2FA n'a jamais ete associee
    // (premiere connexion -> passage par le QR code).
    // NB : le compteur brute force N'EST PAS remis a zero ici - ce
    // sera fait apres le code TOTP valide (succesLogin), sinon un
    // attaquant avec le bon mot de passe pourrait essayer les codes
    // TOTP a l'infini.
    req.session.pending2fa = {
      userId: user.id,
      username: user.username,
      needsSetup: !user.totpEnabled,
    };

    return res.redirect(user.totpEnabled ? "/login/totp" : "/2fa/setup");
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
  journaliserRequete(req, {
    action: "LOGOUT",
    level: "info",
    username: req.session ? req.session.username : null,
  });
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

module.exports = router;
