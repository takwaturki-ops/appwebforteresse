// =============================================================
// MIDDLEWARES D'AUTHENTIFICATION
//
// Phase 3 : la connexion se fait en deux etapes.
//   Etape 1 (mot de passe)  -> session "a l'etat pending" (pending2fa)
//   Etape 2 (code TOTP)     -> session complete (userId)
//
// pending2fa memorise QUE l'identite a mi-chemin : tant que le code
// TOTP n'est pas valide, req.session.userId n'existe pas et aucune
// route protegee n'est accessible.
// =============================================================

// Garde des routes protegees : exige une session COMPLETE
// (mot de passe + TOTP valides).
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    return next(); // session complete -> acces autorise
  }
  // Demi-session ? Renvoyer a l'etape qui lui correspond
  if (req.session && req.session.pending2fa) {
    return res.redirect(
      req.session.pending2fa.needsSetup ? "/2fa/setup" : "/login/totp"
    );
  }
  res.redirect("/login");
};

// Garde des etapes intermediaires (setup QR / saisie du code) :
// exige la demi-session, cad un mot de passe DEJA valide.
const requirePending2FA = (req, res, next) => {
  if (req.session && req.session.pending2fa) {
    return next();
  }
  res.redirect("/login");
};

module.exports = { requireAuth, requirePending2FA };
