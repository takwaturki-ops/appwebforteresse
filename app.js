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

const authRoutes = require("./routes/auth");
const { requireAuth } = require("./middleware/auth");

const app = express();
const PORT = process.env.PORT || 3000;
const EST_PRODUCTION = process.env.NODE_ENV === "production";

// -------------------------------------------------------------
// 1. HELMET - en-tetes HTTP de securite (Phase 5 : personnalisation)
// Entre autres : masque X-Powered-By (divulgation decouverte en Lecon 2),
// CSP stricte, X-Frame-Options, etc.
// -------------------------------------------------------------
app.use(helmet());

// -------------------------------------------------------------
// 2. PARSING - traduit les formulaires HTML vers req.body (Lecon 4)
// -------------------------------------------------------------
app.use(express.urlencoded({ extended: false }));

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

// -------------------------------------------------------------
// 5. MOTEUR DE TEMPLATES - EJS avec echappement automatique (Lecon 5)
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
app.use("/", authRoutes); // /login, /logout

app.get("/dashboard", requireAuth, (req, res) => {
  res.render("dashboard");
});

// -------------------------------------------------------------
// 7. DEMARRAGE
// -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Forteresse demarree sur http://localhost:${PORT}`);
  console.log(`Mode : ${EST_PRODUCTION ? "production" : "developpement"}`);
});
