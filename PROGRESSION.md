# Progression - Application Web Forteresse

## Contexte
- Projet SecOps : app Node.js/Express + PostgreSQL natif (WSL2) + n8n (Azure) + bcrypt
- Objectif : APPRENDRE la secu, comprendre chaque mecanisme pas a pas
- Methode revisee : l'assistant ecrit le code du projet (avec accord), je l'execute,
  le teste et le questionne en mode "revue de code" ; le sandbox reste 100% fait main

## Infrastructure (faite)
- [x] PostgreSQL 18 WSL actif (systemd), user+bdd "forteresse"
- [x] git init + .gitignore, push GitHub takwaturki-ops/appwebforteresse
- [x] Dependance npm installees dans le projet (expliquees en Lecon 1)

## Lecons
- [x] L0 Kit de survie JS (sandbox/01 a 04) : const/let, ===, template literals,
      fonctions flechees, objets, .find/.map, JSON.stringify
- [x] L1 Node.js et npm (modules, require/module.exports, encapsulation, nodemon)
- [x] L2 Premier serveur Express (routes, req/res, codes 200/403/404, curl -i)
- [x] L3 Middlewares (chaine, next, ordre, garde d'acces par cle API)
- [x] L4 POST et req.body + XSS reflechi (payload <script> et <img onerror>)
- [x] L5 EJS : <%= %> echappe vs <%- %> brut, CSP, helmet a venir

## Projet Forteresse (phases)
- [x] Phase 0 : PostgreSQL + git + GitHub
- [x] Phase 1 : socle Express + page de connexion (login en dur, SANS bcrypt ni DB)
- [x] Phase 2 : bcrypt (cout 12) + utilisateurs en DB (Sequelize) + sessions en
      PostgreSQL (connect-pg-simple) + test injection SQL bloque + session survivante
- [ ] Phase 3 : TOTP 2FA + QR code
- [x] Phase 3 : TOTP 2FA (otplib v13 + QR code) - login en 2 etapes,
      demi-session pending2fa, session regenerate a la promotion (anti-fixation),
      codes mal formes -> 401 (validation format avant verify)
- [ ] Phase 4 : RBAC 3 roles + 403 + alertes
- [x] Phase 4 : RBAC - middleware requireRole (403 + alerte audit ACCESS_DENIED),
      gestion utilisateurs (/admin/users : liste, creation avec validation
      express-validator, changement de role superadmin seul, anti-self-change,
      escalation bloquee cote serveur), comptes demo stagetest/admintest
      (creds dans comptes-demo.local.md, hors git)
- [x] Phase 5 : CSRF - jetons de synchronisation (csrf-csrf, modele double-submit
      cookie) dans TOUS les formulaires, cookie parser ajoute, gestionnaire
      d'erreur 403 + alerte CSRF_BLOCKED en audit ; point cle : getCsrfTokenFromRequest
      doit lire req.body._csrf (defaut = header x-csrf-token pour SPA)
- [ ] Phase 6 : rate limiting login
- [ ] Phase 6 : rate limiting login
- [ ] Phase 7 : audit.log JSON
- [ ] Phase 8 : API JWT
- [ ] Phase 9 : n8n Azure + tests + livrables

## Point de reprise
Prochaine etape : Phase 6 - rate limiting (5 essais/min par IP -> blocage 15 min)
+ retester le parcours navigateur complet apels Phase 5 (CSRF)

