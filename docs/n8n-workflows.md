# Workflows n8n — Surveillance Forteresse

Ces workflows sont à importer dans ton instance **n8n (Azure)**.

## Méthode recommandée : importer les JSON

Deux fichiers prêts à l'emploi sont fournis :

| Fichier | Workflow |
|---|---|
| `docs/n8n/forteresse-surveillance.json` | Surveillance SecOps (toutes les 5 min) |
| `docs/n8n/forteresse-elevation.json` | Validation d'élévation de privilèges (approbation par email) |

**Dans n8n** : menu **Workflows** → bouton **Import from File** (ou `...` → Import from File) → sélectionner le JSON → le workflow apparaît avec tous ses nœuds et connexions.

**Après import, 3 réglages obligatoires** :
1. Vérifier les URLs : `http://host.docker.internal:3000` (n8n Docker local
   vers app WSL) ; au déploiement, remplacer par l'adresse réelle de l'app
2. Configurer le **credential SMTP** dans les nœuds Email (et l'adresse de destination)
3. Mot de passe du compte `n8n-bot` via la **variable d'environnement du
   conteneur** `FORTERESSE_API_PASSWORD` (`docker run -e ...`, jamais en clair),
   référencée par `{{$env.FORTERESSE_API_PASSWORD}}` dans les nœuds Login
   (+ `N8N_BLOCK_ENV_ACCESS_IN_NODE=false` requis pour l'accès `$env`).
   ⚠️ **Limite constatée sur n8n 2.28.5 (sept. 2026)** : `$env` reste
   non résolu à l'exécution malgré un flag correct et une variable
   présente (vérifié : la valeur conteneur == hash base en bcrypt).
   **Solution de contournement** : coller temporairement le mot de passe
   en clair dans les 2 nœuds Login pour les tests/démos, puis **rotation
   du mot de passe** après (`seed` ou `ALTER USER`, + mise à jour du nœud).
    Compromis assumé et documenté : visible dans l'UI et les logs
    d'exécution n8n le temps des tests.

## Mise en production : le clair y est INTERDIT

Le contournement ci-dessus est strictement limité aux tests locaux.
Une instance n8n déployée (URL publique, logs conservés, exports JSON
partagés, sauvegardes) ne doit jamais contenir le secret en clair.
Avant le déploiement :

1. **Rotation du mot de passe** `n8n-bot` (l'ancienne valeur a transité
   en clair) : nouveau secret → `ALTER USER` en base + variable d'env
   du conteneur + nœuds mis à jour. L'ancienne valeur devient inutile.
2. **Stocker le secret hors workflow**, par ordre de préférence :
   a. **External Secrets → Azure Key Vault** (recommandé ici : déjà sur
      Azure ; menu n8n Settings → External Secrets ; le secret n'est
      ni dans le workflow ni dans les logs, accès traçable et révocable) ;
   b. **Variables n8n** (`$vars`, Settings → Variables si disponible sur
      l'instance : chiffrées au repos, masquées dans l'UI) ;
   c. `$env` du conteneur (`N8N_BLOCK_ENV_ACCESS_IN_NODE=false`), si la
      version déployée résout correctement (à retester : bug constaté
      sur 2.28.5, corrigé ou non selon version).
3. Vérifier après déploiement : exporter le workflow en JSON et contrôler
   qu'aucune valeur secrète n'y figure en clair (`grep -i password`).

Le script `scripts/n8n-simulation.js` reproduit le workflow de surveillance en local :
la logique et les endpoints sont identiques — seule la brique "alerte"
(console ici) change dans n8n (email, Teams, Slack...).

## Prérequis

1. Le compte d'automatisation `n8n-bot` existe (créé en Phase 9,
   identifiants dans le `.env` local : `N8N_USER` / `N8N_PASSWORD`)
2. Connectivité n8n → application :
   - **Local (n8n Docker + app WSL)** : `http://host.docker.internal:3000`
     (`localhost` dans un conteneur = le conteneur lui-même, pas l'app).
     PREREQUIS Windows 11 : WSL en mode reseau miroir, sinon le conteneur
     ne peut pas joindre les ports WSL (connexion refusee). Creer
     `%USERPROFILE%\.wslconfig` avec :
     ```
     [wsl2]
     networkingMode=mirrored
     ```
     puis `wsl --shutdown` et rouvrir Ubuntu. Verifier depuis le conteneur :
     `docker exec n8n wget -qO- --timeout=8 http://host.docker.internal:3000/login`
   - **Test/démo à distance** : tunnel HTTPS (cloudflared :
     `cloudflared tunnel --url http://localhost:3000`)
   - **Production** : URL publique de l'app déployée (VM Azure)
3. Aucune 2FA sur ce compte : les machines ne peuvent pas taper de code
   TOTP. C'est une **limite documentée** — en production réelle on
   utiliserait une IP allowlist et un secret rotatif.

---

## Méthode alternative : construction manuelle

*(utile si tu veux comprendre chaque nœud — mais l'import des JSON ci-dessus fait la même chose en 30 secondes)*

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
