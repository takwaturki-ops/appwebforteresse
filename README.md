# Forteresse — Application Web Sécurisée (SecOps)

Application web de gestion d'infrastructure hautement sécurisée :
double authentification TOTP, contrôle d'accès RBAC à 3 rôles, durcissement
OWASP complet et journalisation d'audit. Projet pédagogique — chaque
mécanisme de sécurité est documenté, testé par des attaques réelles
(simulées) et traçable dans le journal d'audit.

> Variante « sans Docker » : l'application et PostgreSQL sont installés
> nativement dans WSL 2 (Ubuntu). L'automatisation n8n est hébergée
> sur Azure.

## Stack

| Composant | Technologie |
|---|---|
| Application | Node.js 20, Express 5, EJS |
| Base de données | PostgreSQL 18 (Sequelize ORM) |
| Sessions | express-session + connect-pg-simple (store PostgreSQL) |
| Mots de passe | bcryptjs (coût 12, salt unique) |
| 2FA | otplib (TOTP RFC 6238) + qrcode |
| API | jsonwebtoken (HS256, jetons 15 min) |
| Sécurité HTTP | helmet, csrf-csrf, express-rate-limit |

## Mécanismes de sécurité implémentés

| Mécanisme | Implémentation | Preuve (tests rejoués) |
|---|---|---|
| **Mots de passe hachés** | bcrypt coût 12, salt unique — jamais de clair en base | `SELECT password_hash FROM users` → `$2b$12$...` |
| **Anti-injection SQL** | Requêtes paramétrées via Sequelize ORM | payload `' OR '1'='1' --` et `DROP TABLE` → 401, base intacte |
| **Double authentification** | TOTP 6 chiffres/30 s, QR code d'association, demi-session `pending2fa` | login sans code → aucune page accessible |
| **Anti-fixation de session** | `req.session.regenerate()` à la promotion | l'ID de session change après authentification |
| **RBAC 3 rôles** | stagiaire (lecture) / admin (users standards) / superadmin (privièges + audit), vérification serveur sur chaque route | stagiaire → `/admin/users` : 403 + alerte audit |
| **Anti-escalade** | revalidation serveur du rôle demandé + anti-self-change | admin forge `role=superadmin` → 400 + alerte critical |
| **XSS** | échappement automatique EJS (`<%= %>`), CSP helmet | payload `<img onerror=...>` affiché comme texte |
| **CSRF** | jetons de synchronisation (double-submit cookie) + `SameSite=Strict` | POST sans jeton → 403 + alerte `CSRF_BLOCKED` |
| **Cookies durcis** | `HttpOnly; SameSite=Strict; Secure` (prod) | visible dans l'en-tête `Set-Cookie` |
| **Rate limiting** | 5 échecs (web OU API) → IP bloquée 15 min ; 300 req/15 min global | 5e échec → 429 + `Retry-After: 900`, même le bon mot de passe bloqué |
| **Journal d'audit** | `logs/audit.log`, 1 ligne JSON par événement, append-only | voir extrait plus bas |
| **API JWT** | jetons HS256 15 min, `Authorization: Bearer` | jeton falsifié → 401 (signature HMAC) |

## Installation (WSL 2 / Ubuntu)

```bash
# 1. PostgreSQL
sudo apt install postgresql
sudo -u postgres psql -c "CREATE USER forteresse WITH PASSWORD '...';"
sudo -u postgres psql -c "CREATE DATABASE forteresse OWNER forteresse;"

# 2. Application
npm install
cp .env.example .env        # puis remplir les secrets (commandes de
                            # generation indiquees dans le fichier)
node scripts/seed.js <mot_de_passe_superadmin>   # tables + roles + compte initial

# 3. Démarrage
node app.js                 # http://localhost:3000
```

À la première connexion : le QR code TOTP s'affiche → scanner avec
Google Authenticator/Bitwarden/Aegis → saisir le code → dashboard.

## Comptes de démonstration

| Compte | Rôle | Usage démo |
|---|---|---|
| `turki` | superadmin | tout est accessible |
| `admintest` | admin | liste/création users, mais 403 sur les changements de rôle |
| `stagetest` | stagiaire | 403 sur tout /admin + lien admin absent du dashboard |
| `n8n-bot` | superadmin | compte d'automatisation (API/JWT uniquement) |

*(Mots de passe des comptes de démo : fichier local `comptes-demo.local.md`,
hors git. Identifiants n8n : `.env`.)*

## L'API (pour scripts et n8n)

```bash
# Obtenir un jeton (15 min)
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"n8n-bot","password":"..."}'

# L'utiliser
curl http://localhost:3000/api/users -H "Authorization: Bearer <jeton>"
curl "http://localhost:3000/api/audit?limit=50" -H "Authorization: Bearer <jeton>"
```

Endpoints : `POST /api/login`, `GET /api/users` (admin+),
`POST /api/users/:id/role` (superadmin), `GET /api/audit` (superadmin).
RBAC et rate limiting identiques à l'interface web.

## Automatisation n8n

Workflows documentés nœud par nœud dans [docs/n8n-workflows.md](docs/n8n-workflows.md) :

1. **Surveillance SecOps** (toutes les 5 min) : relève l'audit via l'API
   et alerte l'équipe sur les créations d'admins, blocages brute force
   et tentatives d'escalade — testable en local avec
   `node scripts/n8n-simulation.js`
2. **Validation d'élévation à distance** : le SuperAdmin approuve/refuse
   les changements de rôles depuis son téléphone, appliqués via l'API

## Extrait du journal d'audit (`logs/audit.log`)

```json
{"horodatage":"2026-08-20T19:09:20.285Z","action":"RATE_LIMIT_BLOCAGE","level":"warning","username":"turki","ip":"::1","details":{"dureeBlocageMinutes":15,"cause":"5 tentatives de login infructueuses"}}
{"horodatage":"2026-08-17T23:50:02.525Z","action":"ACCESS_DENIED","level":"warning","username":"stagetest","ip":"::1","details":{"chemin":"/admin/users","roleUtilisateur":"stagiaire","rolesRequis":["admin","superadmin"]}}
{"horodatage":"2026-08-17T23:50:21.599Z","action":"PRIVILEGE_ESCALATION_BLOCKED","level":"critical","username":"admintest","ip":"::1","details":{"tentativeRole":"superadmin","chemin":"/admin/users"}}
{"horodatage":"2026-08-20T19:09:44.814Z","action":"LOGIN_SUCCESS","level":"notice","username":"turki","ip":"::1","details":{"etape":"mot_de_passe_plus_2fa"}}
{"horodatage":"2026-08-18T22:31:13.249Z","action":"CSRF_BLOCKED","level":"warning","username":null,"ip":"::1","details":{"chemin":"/login","methode":"POST"}}
```

Événements tracés : `LOGIN_SUCCESS/FAILED`, `TOTP_FAILED`, `LOGOUT`,
`ACCESS_DENIED`, `CSRF_BLOCKED`, `USER_CREATED`, `ROLE_CHANGED`,
`PRIVILEGE_ESCALATION_BLOCKED`, `RATE_LIMIT_BLOCAGE`, `API_LOGIN_*`,
`API_ACCESS_DENIED`.

## Structure du projet

```
app.js                 chaîne de middlewares + démarrage
routes/  auth.js       login/logout (bcrypt, demi-session 2FA)
         totp.js       association QR + vérification TOTP
         admin.js      gestion utilisateurs (RBAC)
         api.js        API REST JWT (scripts, n8n)
middleware/  auth.js   requireAuth, requirePending2FA
             role.js   requireRole (RBAC web, 403 + alerte)
             jwt.js    requireJwt, requireRoleApi (RBAC API)
             ratelimit.js  anti brute force (5 échecs → 15 min)
models/                User, Role, AuditLog (Sequelize)
utils/audit.js         journal d'audit JSON append-only
scripts/seed.js        initialisation base + rôles + superadmin
         n8n-simulation.js  workflow surveillance (test local)
views/                 templates EJS (échappement automatique)
docs/n8n-workflows.md  workflows n8n documentés
```

## Limites connues (assumées)

- Le compte d'automatisation `n8n-bot` n'a pas de 2FA (les machines ne
  peuvent pas saisir de code TOTP) — en production : IP allowlist + secret rotatif
- Le rate limiting anti brute force est en mémoire (Map) : adapté à un
  serveur mono-processus, à passer en store Redis pour un cluster
- Pas de codes de secours TOTP (backup codes) pour les utilisateurs
- `Secure` (HTTPS) actif uniquement avec `NODE_ENV=production`
