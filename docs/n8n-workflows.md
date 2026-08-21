# Workflows n8n — Surveillance Forteresse

Ces workflows sont à recréer dans ton instance **n8n (Azure)**.
Le script `scripts/n8n-simulation.js` reproduit le workflow 1 en local :
la logique et les endpoints sont identiques — seule la brique "alerte"
(console ici) change dans n8n (email, Teams, Slack...).

## Prérequis

1. Le compte d'automatisation `n8n-bot` existe (créé en Phase 9,
   identifiants dans le `.env` local : `N8N_USER` / `N8N_PASSWORD`)
2. n8n (Azure) doit pouvoir joindre l'application. Deux options :
   - **Test/démo** : faire tourner l'app sur ta machine et utiliser un
     tunnel HTTPS (cloudflared : `cloudflared tunnel --url http://localhost:3000`)
     → URL publique temporaire à mettre dans n8n
   - **Production** : déployer l'app sur un serveur joignable (VM Azure)
3. Aucune 2FA sur ce compte : les machines ne peuvent pas taper de code
   TOTP. C'est une **limite documentée** — en production réelle on
   utiliserait une IP allowlist et un secret rotatif.

---

## Workflow 1 — Surveillance SecOps (le vigile qui ne dort jamais)

**Déclencheur** : toutes les 5 minutes
**Effet** : alerte dès qu'un admin est créé, un brute force est bloqué,
ou une escalade de privilèges est tentée.

### Nœuds à créer dans n8n

| # | Nœud n8n | Type | Configuration |
|---|---|---|---|
| 1 | **Tous les 5 min** | Schedule Trigger | Mode : Every 5 minutes |
| 2 | **Login API** | HTTP Request | Method : POST<br>URL : `https://<ton-app>/api/login`<br>Body (JSON) : `{ "username": "n8n-bot", "password": "<N8N_PASSWORD>" }`<br>⚠️ Mot de passe dans un **credential** n8n, pas en clair |
| 3 | **Lire audit** | HTTP Request | Method : GET<br>URL : `https://<ton-app>/api/audit?limit=100`<br>Header : `Authorization` = `Bearer {{ $json.token }}` |
| 4 | **Filtrer alertes** | Code (JavaScript) | Coller le code de la fonction `analyser()` de `scripts/n8n-simulation.js` (adaptée : `return items` avec les alertes) |
| 5 | **Si alerte** | IF | Condition : `{{ $json.alertes.length }}` > 0 (ou Split Out sur le tableau) |
| 6 | **Envoyer l'alerte** | Email (SMTP) / Microsoft Teams / Slack | Destinataire : l'équipe SecOps<br>Contenu : type d'alerte, sévérité, utilisateur, détails JSON |

### Événements surveillés (règles du nœud 4)

| Action audit | Alerte | Sévérité |
|---|---|---|
| `USER_CREATED` avec rôle admin/superadmin | NOUVEL_ADMINISTRATEUR | notice |
| `ROLE_CHANGED` vers admin/superadmin | ELEVATION_PRIVILEGE | notice |
| `RATE_LIMIT_BLOCAGE` | BRUTE_FORCE détecté | warning |
| `PRIVILEGE_ESCALATION_BLOCKED` | Escalade bloquée | critical |
| `API_ACCESS_DENIED` | Accès API refusé | warning |

---

## Workflow 2 — Validation d'élévation de privilèges à distance

**Déclencheur** : un webhook (demande envoyée par l'application ou un admin)
**Effet** : le SuperAdmin approuve/refuse DEPUIS SON TÉLÉPHONE, et le
changement de rôle est appliqué via l'API.

### Nœuds à créer dans n8n

| # | Nœud n8n | Type | Configuration |
|---|---|---|---|
| 1 | **Demande reçue** | Webhook | Method : POST<br>Body : `{ "userId": 2, "roleDemande": "admin", "demandeur": "admintest" }` |
| 2 | **Préparer la demande** | Set | Message : « admintest demande le rôle admin pour stagetest — approuver ? » |
| 3 | **Envoyer pour approbation** | Email/Teams + **Wait** (n8n) | Lien « Approuver » / « Refuser » (approval email n8n ou formulaire) |
| 4a | **Si approuvé** | HTTP Request | POST `https://<ton-app>/api/users/{{userId}}/role`<br>Header : `Authorization: Bearer <jeton du workflow 1>`<br>Body : `{ "role": "{{roleDemande}}" }` |
| 4b | **Si refusé** | NoOp | Rien (la demande expire, rien n'est changé) |
| 5 | **Confirmer** | Email | Résultat de l'opération (nouveau rôle ou refus) |

### Pourquoi c'est sûr

- n8n s'authentifie avec JWT (compte dédié `n8n-bot`)
- Le changement de rôle passe par `POST /api/users/:id/role` → **RBAC
  vérifié côté serveur** (superadmin requis), anti-self-change actif,
  et chaque application est tracée dans `audit.log` (`via: "api"`)
- Un humain (le SuperAdmin) reste dans la boucle : rien n'est automatique
  sans approbation explicite

---

## Test local avant Azure

```bash
node app.js                                 # serveur Forteresse
node scripts/n8n-simulation.js              # le workflow 1 en local
N8N_PASSWORD=faux node scripts/n8n-simulation.js   # vérifier le refus propre
```

Sortie attendue : authentification, relevé des événements, et les
alertes détectées imprimées (voir capture dans le README).
