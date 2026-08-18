// =============================================================
// ROUTES TOTP (Phase 3) - double authentification
//
//   GET  /2fa/setup   : association - QR code + cle manuelle
//   POST /2fa/verify  : confirmation de l'association (1er code)
//   GET  /login/totp  : saisie du code a 6 chiffres au login
//   POST /login/totp  : verification de ce code
//
// Principe TOTP : le serveur et le telephone partagent le meme
// secret ; chacun le combine avec l'horloge (blocs de 30 s) via
// HMAC-SHA1 -> meme code a 6 chiffres, sans jamais communiquer.
// Fenetre de tolerance window:1 (bloc precedent/suivant) pour
// absorber le decalage des horloges.
// =============================================================

const express = require("express");
const { generateSecret, generateURI, verify } = require("otplib");
const QRCode = require("qrcode");

const router = express.Router();
const { User, Role } = require("../models");
const { requirePending2FA } = require("../middleware/auth");

const ISSUER = process.env.TOTP_ISSUER || "Forteresse";
const FENETRE = 1; // tolerance : +/- 1 bloc de 30 s

// Le code TOTP est-il valide pour ce secret ?
// 1. validation du format (6 chiffres) : otplib v13 LEVE une exception
//    sur un format invalide - sans ce garde, un attaquant qui envoie
//    n'importe quoi obtiendrait des erreurs 500 (bruit + info).
// 2. verify() est asynchrone et renvoie { valid, delta }.
const codeValide = async (token, secret) => {
  const code = String(token ?? "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(code)) return false;
  try {
    const resultat = await verify({
      secret: String(secret),
      token: code,
      window: FENETRE,
    });
    return Boolean(resultat && resultat.valid);
  } catch {
    return false; // toute erreur de verification = refus, jamais un 500
  }
};

// Passage demi-session -> session complete.
// req.session.regenerate() cree une session TOUTE neuve :
// defense contre la fixation de session (un attaquant ne peut pas
// reutiliser un identifiant de session forge avant le login).
const promouvoirSession = (req, user) =>
  new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.Role ? user.Role.name : "stagiaire";
      resolve();
    });
  });

// -------------------------------------------------------------
// ASSOCIATION (enrollment) - pour les comptes sans 2FA activee
// -------------------------------------------------------------

// GET /2fa/setup : genere le secret, l'affiche en QR code
router.get("/2fa/setup", requirePending2FA, async (req, res, next) => {
  try {
    const pending = req.session.pending2fa;
    if (!pending.needsSetup) {
      return res.redirect("/login/totp"); // deja associe -> saisie du code
    }

    // Secret genere cote serveur, memorise dans la DEMI-session.
    // Genere UNE SEULE fois : un rafraichissement de la page (F5)
    // reutilise le meme secret et le meme QR. Sans cette precaution,
    // tout rafraichissement entre le scan et la saisie invaliderait
    // le QR deja scanne par le telephone.
    // Il ne sera ecrit en base qu'apres confirmation par un code valide,
    // ce qui garantit que le telephone a bien scanne le bon QR.
    const secret = pending.secret || generateSecret({ length: 32 });
    pending.secret = secret;

    const uri = generateURI({ issuer: ISSUER, label: pending.username, secret });
    const qrDataUrl = await QRCode.toDataURL(uri, { width: 240, margin: 2 });

    res.render("2fa-setup", { qrDataUrl, secret, erreur: null });
  } catch (err) {
    next(err);
  }
});

// POST /2fa/verify : confirme l'association avec un premier code
router.post("/2fa/verify", requirePending2FA, async (req, res, next) => {
  try {
    const pending = req.session.pending2fa;
    if (!pending.needsSetup || !pending.secret) {
      return res.redirect("/2fa/setup");
    }

    // include Role : la promotion doit connaitre le VRAI role
    // (sans lui, le fallback stagiaire s'appliquerait a tort)
    const user = await User.findByPk(pending.userId, { include: Role });
    const ok = user && (await codeValide(req.body.token, pending.secret));

    if (!ok) {
      // Meme secret : l'utilisateur peut rescanner ou retaper le code
      const uri = generateURI({ issuer: ISSUER, label: pending.username, secret: pending.secret });
      const qrDataUrl = await QRCode.toDataURL(uri, { width: 240, margin: 2 });
      return res
        .status(401)
        .render("2fa-setup", { qrDataUrl, secret: pending.secret, erreur: "Code invalide, reessayez." });
    }

    // Association confirmee : on persiste le secret et on active la 2FA
    user.totpSecret = pending.secret;
    user.totpEnabled = true;
    await user.save();

    await promouvoirSession(req, user);
    res.redirect("/dashboard");
  } catch (err) {
    next(err);
  }
});

// -------------------------------------------------------------
// VERIFICATION AU LOGIN - pour les comptes dont la 2FA est activee
// -------------------------------------------------------------

// GET /login/totp : page de saisie du code a 6 chiffres
router.get("/login/totp", requirePending2FA, (req, res) => {
  if (req.session.pending2fa.needsSetup) {
    return res.redirect("/2fa/setup");
  }
  res.render("2fa-login", { erreur: null });
});

// POST /login/totp : verifie le code contre le secret stocke en base
router.post("/login/totp", requirePending2FA, async (req, res, next) => {
  try {
    const pending = req.session.pending2fa;
    if (pending.needsSetup) {
      return res.redirect("/2fa/setup");
    }

    const user = await User.findByPk(pending.userId, { include: Role });
    const ok =
      user &&
      user.isActive &&
      user.totpEnabled &&
      (await codeValide(req.body.token, user.totpSecret));

    if (!ok) {
      // Message generique, comme pour le mot de passe
      return res.status(401).render("2fa-login", { erreur: "Code invalide." });
    }

    await promouvoirSession(req, user);
    res.redirect("/dashboard");
  } catch (err) {
    next(err);
  }
});

module.exports = router;
