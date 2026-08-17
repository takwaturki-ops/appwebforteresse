// Middleware d'authentification (pattern de la Lecon 3 applique au projet)
// Verifie que la session contient un utilisateur identifie.
// Sinon : redirection vers /login (la page protegee reste inacessible).
const requireAuth = (req, res, next) => {
  if (req.session && req.session.userId) {
    next(); // session valide -> on continue vers la route
  } else {
    res.redirect("/login");
  }
};

module.exports = { requireAuth };
