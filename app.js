// =============================================================
// APPLICATION WEB FORTERESSE - Socle (Phase 1)
//
// Objectif de cette phase : structure Express + page de connexion
// + sessions + en-tetes de securite de base.
// Le login est provisoirement "en dur" ; bcrypt + PostgreSQL
// arrivent en Phase 2, le TOTP en Phase 3, etc.
// =============================================================

// dotenv en PREMIER : charge le .env pour que process.env soit rempli
// avant tout autre module qui l'utilise.
require("dotenv").config();

const express = require("express");
const path = require("path");
const helmet = require("helmet");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { doubleCsrf } = require("csrf-csrf");

const authRoutes = require("./routes/auth");
const totpRoutes = require("./routes/totp");
const adminRoutes = require("./routes/admin");
const apiRoutes = require("./routes/api");
const { requireAuth } = require("./middleware/auth");
const { journaliserRequete } = require("./utils/audit");

const app = express();
const PORT = process.env.PORT || 3000;
const EST_PRODUCTION = process.env.NODE_ENV === "production";

// -------------------------------------------------------------
// 1. HELMET - en-tetes HTTP de securite
// Masque X-Powered-By, CSP stricte, X-Frame-Options, etc.
// img-src autorise "data:" uniquement pour le QR code d'association
// 2FA (genere cote serveur par nos soins, pas une donnee externe).
// -------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "img-src": ["'self'", "data:"],
      },
    },
  })
);

// -------------------------------------------------------------
// 1bis. LIMITEUR GLOBAL DE REQUETES (Phase 6)
// Toute l'application : 300 requetes / 15 min / IP. Un humain
// naviguant normalement reste tres en dessous ; un script qui
// bombarde le serveur (flooding) est coupe vite.
// Complementaire au garde anti brute-force (middleware/ratelimit.js)
// qui, lui, ne compte que les ECHECS de login (5 -> blocage 15 min).
// -------------------------------------------------------------
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: "429 - Trop de requetes, reessayez plus tard.",
  })
);

// -------------------------------------------------------------
// 2. PARSING - traduit les formulaires HTML vers req.body (Lecon 4)
// -------------------------------------------------------------
app.use(express.urlencoded({ extended: false }));

// Parsing JSON (Phase 8) : traduit le corps des requetes API
// (Content-Type: application/json) vers req.body. Limite volontairement
// petite : un payload volumineux n'a rien a faire sur nos endpoints.
app.use(express.json({ limit: "16kb" }));

// -------------------------------------------------------------
// 3. FICHIERS STATIQUES - sert /public (css, js client) sur /
// -------------------------------------------------------------
app.use(express.static(path.join(__dirname, "public")));

// -------------------------------------------------------------
// 4. SESSIONS - identite de l'utilisateur entre les requetes
//
// Store PostgreSQL (connect-pg-simple) : les sessions survivent
// aux redemarrages du serveur et peuvent etre revoquees proprement.
//
// Durcissement du cookie de session (cahier des charges) :
//   httpOnly  : interdit l'acces au cookie depuis JavaScript
//               (defense contre le vol de session par XSS)
//   sameSite  : "strict" -> le cookie n'est envoye que sur les
//               navigations internes (defense contre le CSRF)
//   secure    : cookie envoye uniquement en HTTPS (desactive en dev
//               local car pas de certificat - actif en production)
//   maxAge    : expiration apres 30 minutes d'inactivite
// -------------------------------------------------------------
const PgSessionStore = connectPgSimple(session);

app.use(
  session({
    store: new PgSessionStore({
      conString: process.env.DATABASE_URL,
      tableName: "sessions",
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "strict",
      secure: EST_PRODUCTION,
      maxAge: 30 * 60 * 1000, // 30 minutes
    },
  })
);

// Force la creation effective de la session des la premiere requete.
// Necessaire pour lier le jeton CSRF a un identifiant de session
// stable (avec saveUninitialized:false, une session vierge n'est
// pas sauvegardee et changerait d'identifiant a chaque requete).
// Les requetes API (JWT, sans session) sont exclues : inutile de
// creer des lignes dans la table sessions pour elles.
app.use((req, res, next) => {
  if (!req.path.startsWith("/api") && !req.session.init) req.session.init = true;
  next();
});

// cookie-parser : rempli req.cookies - requis par csrf-csrf pour
// lire son cookie "__csrf-token" (modele double-submit cookie).
app.use(cookieParser());

// -------------------------------------------------------------
// 5. JETONS CSRF (Phase 5) - defense anti Cross-Site Request Forgery
//
// Principe du jeton de synchronisation : chaque formulaire emis par
// notre site contient un jeton ALEATOIRE lie a la session de
// l'utilisateur ; tout POST sans le bon jeton est rejete en 403.
// Un site pirate peut forcer l'envoi d'un POST avec le cookie de
// session de la victime, mais il ne peut PAS lire le contenu de nos
// pages (same-origin policy) -> il ne connait jamais le jeton.
//
// Defense en profondeur avec le drapeau SameSite=Strict du cookie
// de session (deuxieme couche, deja en place).
// -------------------------------------------------------------
const { doubleCsrfProtection, generateCsrfToken, invalidCsrfTokenError } =
  doubleCsrf({
    getSecret: () => process.env.CSRF_SECRET,
    getSessionIdentifier: (req) => req.session.id,
    // IMPORTANT : par defaut la lib lit le header "x-csrf-token" (usage
    // AJAX/SPA). Nos formulaires HTML classiques transportent le jeton
    // dans le corps : on lit donc req.body._csrf.
    getCsrfTokenFromRequest: (req) => req.body._csrf,
    // L'API /api/* est authentifiee par JWT (header Authorization) :
    // pas de cookie ni de formulaire -> pas de CSRF possible, on
    // l'exempte de la verification (sinon tout POST /api serait 403).
    skipCsrfProtection: (req) => req.path.startsWith("/api"),
    cookieName: "csrf-token",
    cookieOptions: {
      httpOnly: true,
      sameSite: "strict",
      secure: EST_PRODUCTION,
      path: "/",
    },
    size: 64,
  });

app.use(doubleCsrfProtection);

// Le jeton est disponible dans TOUTES les vues via csrfToken
// (chaque formulaire l'inclut dans un champ cache name="_csrf").
// Inutile pour les requetes API (JSON, pas de template).
app.use((req, res, next) => {
  if (!req.path.startsWith("/api")) {
    res.locals.csrfToken = generateCsrfToken(req, res);
  }
  next();
});

// -------------------------------------------------------------
// 6. MOTEUR DE TEMPLATES - EJS avec echappement automatique (Lecon 5)
// -------------------------------------------------------------
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Petite aide pour toutes les vues : la session est accessible
// dans les templates sans la passer a chaque render().
app.use((req, res, next) => {
  res.locals.session = req.session;
  next();
});

// -------------------------------------------------------------
// 6. ROUTES
// -------------------------------------------------------------
app.use("/", authRoutes);   // /login, /logout (etape 1 : mot de passe)
app.use("/", totpRoutes);   // /2fa/*, /login/totp (etape 2 : code TOTP)
app.use("/", adminRoutes);  // /admin/* (RBAC : requireRole par route)
app.use("/", apiRoutes);    // /api/* (JWT : scripts et n8n)

app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

// -------------------------------------------------------------
// 8. GESTIONNAIRE D'ERREUR CSRF
// Requête POST sans jeton valide = tentative CSRF (ou formulaire
// périmé) -> 403 + alerte dans le journal d'audit.
// Signature a 4 arguments : c'est ainsi qu'Express reconnait un
// middleware de gestion d'erreurs.
// -------------------------------------------------------------
app.use((err, req, res, next) => {
  if (err === invalidCsrfTokenError || err.code === "ERR_CSRF_MISSING_TOKEN" || err.code === "ERR_CSRF_INVALID_TOKEN") {
    journaliserRequete(req, {
      action: "CSRF_BLOCKED",
      level: "warning",
      username: req.session ? req.session.username : null,
      details: { chemin: req.originalUrl, methode: req.method },
    });
    return res.status(403).render("403", {
      chemin: req.originalUrl,
      roleUtilisateur: (req.session && req.session.role) || "inconnu",
      rolesRequis: ["un jeton CSRF valide"],
    });
  }
  // Autre erreur : la passer au gestionnaire par defaut d'Express
  next(err);
});

// -------------------------------------------------------------
// 9. DEMARRAGE
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Forteresse demarree sur http://localhost:${PORT}`);
  console.log(`Mode : ${EST_PRODUCTION ? "production" : "developpement"}`);
});
