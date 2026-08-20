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
- [x] Phase 1 : socle Express + page de connexion + sessions durcies
- [x] Phase 2 : bcrypt (cout 12) + utilisateurs en DB (Sequelize) + sessions en
      PostgreSQL (connect-pg-simple) + test injection SQL bloque + session survivante
- [x] Phase 3 : TOTP 2FA (otplib v13 + QR code) - login en 2 etapes,
      demi-session pending2fa, session regenerate a la promotion (anti-fixation),
      codes mal formes -> 401 (validation format avant verify)
- [x] Phase 4 : RBAC - middleware requireRole (403 + alerte audit ACCESS_DENIED),
      gestion utilisateurs (/admin/users : liste, creation avec validation
      express-validator, changement de role superadmin seul, anti-self-change,
      escalation bloquee cote serveur), comptes demo stagetest/admintest
      (creds dans comptes-demo.local.md, hors git)
- [x] Phase 5 : CSRF - jetons de synchronisation (csrf-csrf, modele double-submit
      cookie) dans TOUS les formulaires, cookie parser ajoute, gestionnaire
      d'erreur 403 + alerte CSRF_BLOCKED en audit ; point cle : getCsrfTokenFromRequest
      doit lire req.body._csrf (defaut = header x-csrf-token pour SPA)
- [x] Phase 6 : rate limiting - garde anti brute force (5 echecs ->
      blocage IP 15 min, fenetre glissante, IP blanchie au succes) sur
      /login, /login/totp et /2fa/verify + limiteur global express-rate-limit
      (300 req/15min/IP) ; reponses 429 avec Retry-After + page dediee
- [x] Phase 7 : audit complet - LOGIN_FAILED (raison en interne seulement),
      LOGIN_SUCCESS, TOTP_FAILED, LOGOUT, RATE_LIMIT_BLOCAGE (s'ajoutent a
      ACCESS_DENIED, CSRF_BLOCKED, USER_CREATED, ROLE_CHANGED,
      PRIVILEGE_ESCALATION_BLOCKED)
- [ ] Phase 8 : API JWT (pour scripts + n8n)
- [ ] Phase 9 : n8n Azure + tests + livrables (screenshots 2FA, extrait audit.log)

## Point de reprise
Prochaine etape : Phase 8 - API REST /api/* avec JWT (login API -> jeton signe
15 min, header Authorization: Bearer, middleware requireJwt + requireRole API) ;
puis n8n (Azure) qui consomme cette API ; cote utilisateur : retester le
parcours navigateur complet et prendre les screenshots livrables

