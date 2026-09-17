// =============================================================
// GRAPHIQUES + RAFRAICHISSEMENT DU DASHBOARD (dashboard-charts.js)
//
// 100 % externe (exigence CSP). Regle anti-XSS : les donnees du
// JSON ne sont JAMAIS injectees via innerHTML — uniquement via
// textContent / createElement (canvas Chart.js : pas de HTML).
// =============================================================

(function () {
  "use strict";

  var URL_STATS = "/dashboard/stats";
  var DELAI_REFRESH_MS = 30 * 1000;

  var graphiques = {};

  // Couleurs adaptees au theme courant (relues a chaque rendu pour
  // suivre la bascule jour/nuit sans recharger la page).
  function palette() {
    var sombre = document.documentElement.getAttribute("data-theme") === "dark";
    return {
      texte: sombre ? "#e2e8f0" : "#1f2937",
      grille: sombre ? "rgba(148,163,184,0.2)" : "rgba(100,116,139,0.2)",
      roles: ["#0ea5e9", "#f59e0b", "#ef4444"],
      severites: ["#0ea5e9", "#22c55e", "#f59e0b", "#ef4444"],
      courbe: sombre ? "#38bdf8" : "#1d4ed8",
    };
  }

  function detruireGraphiques() {
    Object.keys(graphiques).forEach(function (cle) {
      try { graphiques[cle].destroy(); } catch (e) { /* deja detruit */ }
      delete graphiques[cle];
    });
  }

  // Compteur anime (count-up) a la premiere ouverture uniquement.
  var premiereOuverture = true;
  function afficherNombre(id, valeur) {
    var el = document.getElementById(id);
    if (!el) return;
    if (!premiereOuverture) {
      el.textContent = String(valeur);
      return;
    }
    var cible = Number(valeur) || 0;
    var debut = null;
    function etape(ts) {
      if (debut === null) debut = ts;
      var progres = Math.min((ts - debut) / 600, 1);
      el.textContent = String(Math.round(cible * progres));
      if (progres < 1) requestAnimationFrame(etape);
    }
    requestAnimationFrame(etape);
  }

  // Reconstruit la liste d'activite SANS innerHTML (textContent only).
  function majActivite(recents) {
    var liste = document.getElementById("activite-liste");
    if (!liste || !Array.isArray(recents)) return;
    while (liste.firstChild) liste.removeChild(liste.firstChild);
    if (recents.length === 0) {
      var vide = document.createElement("p");
      vide.className = "muted";
      vide.textContent = "Aucun événement enregistré pour le moment.";
      liste.appendChild(vide);
      return;
    }
    recents.forEach(function (e) {
      var li = document.createElement("li");
      var badge = document.createElement("span");
      badge.className = "badge-level level-" + (e.level || "info");
      badge.textContent = e.level || "info";
      var texte = document.createElement("span");
      var fort = document.createElement("strong");
      fort.textContent = e.action || "?";
      texte.appendChild(fort);
      texte.appendChild(document.createTextNode(" — " + (e.username || "-")));
      li.appendChild(badge);
      li.appendChild(texte);
      liste.appendChild(li);
    });
  }

  function construireGraphiques(stats) {
    if (typeof Chart === "undefined") return; // vendor absent : cartes seules
    var pal = palette();
    Chart.defaults.color = pal.texte;
    Chart.defaults.borderColor = pal.grille;
    Chart.defaults.font.family = "system-ui, sans-serif";
    detruireGraphiques();

    var ctxRoles = document.getElementById("graphRoles");
    if (ctxRoles) {
      graphiques.roles = new Chart(ctxRoles, {
        type: "doughnut",
        data: {
          labels: ["stagiaire", "admin", "superadmin"],
          datasets: [{
            data: [stats.utilisateurs.parRole.stagiaire, stats.utilisateurs.parRole.admin, stats.utilisateurs.parRole.superadmin],
            backgroundColor: pal.roles,
            borderWidth: 2,
          }],
        },
        options: { plugins: { legend: { position: "bottom" } }, cutout: "62%" },
      });
    }

    var ctxSev = document.getElementById("graphSeverites");
    if (ctxSev) {
      graphiques.sev = new Chart(ctxSev, {
        type: "bar",
        data: {
          labels: ["info", "notice", "warning", "critical"],
          datasets: [{
            data: [stats.audit.parNiveau24h.info, stats.audit.parNiveau24h.notice, stats.audit.parNiveau24h.warning, stats.audit.parNiveau24h.critical],
            backgroundColor: pal.severites,
            borderRadius: 6,
          }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }

    var ctxCo = document.getElementById("graphConnexions");
    if (ctxCo) {
      graphiques.co = new Chart(ctxCo, {
        type: "line",
        data: {
          labels: stats.audit.connexions7j.labels,
          datasets: [{
            label: "Connexions",
            data: stats.audit.connexions7j.data,
            borderColor: pal.courbe,
            backgroundColor: pal.courbe,
            fill: false,
            tension: 0.35,
            pointRadius: 4,
          }],
        },
        options: {
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }
  }

  function appliquerStats(stats) {
    afficherNombre("stat-users", stats.utilisateurs.total);
    afficherNombre("stat-sessions", stats.sessionsActives);
    afficherNombre("stat-alertes", stats.audit.critiques24h);
    var totp = document.getElementById("stat-totp");
    if (totp) totp.textContent = stats.utilisateurs.totpActives + "/" + stats.utilisateurs.total;

    var carteAlertes = document.getElementById("carte-alertes");
    if (carteAlertes) carteAlertes.classList.toggle("stat-alerte", stats.audit.critiques24h > 0);

    var dbEtat = document.getElementById("db-etat");
    if (dbEtat) {
      if (stats.base.ok) {
        dbEtat.className = "etat-ok";
        dbEtat.textContent = "● Connectée (" + stats.base.latenceMs + " ms)";
      } else {
        dbEtat.className = "etat-ko";
        dbEtat.textContent = "● Injoignable";
      }
    }
    majActivite(stats.audit.recents);
    construireGraphiques(stats);

    var pastille = document.getElementById("pastille-fraicheur");
    if (pastille) pastille.title = "Dernière actualisation : " + new Date().toLocaleTimeString("fr-FR");
    premiereOuverture = false;
  }

  function rafraichir() {
    fetch(URL_STATS, { credentials: "same-origin" })
      .then(function (reponse) {
        if (!reponse.ok) throw new Error("HTTP " + reponse.status);
        return reponse.json();
      })
      .then(appliquerStats)
      .catch(function (err) {
        // Session expiree ou reseau : on garde l'affichage serveur,
        // la prochaine tentative aura lieu dans 30 s.
        console.warn("Refresh dashboard impossible :", err.message);
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    rafraichir(); // 1er rendu : graphiques + compteurs animes
    setInterval(rafraichir, DELAI_REFRESH_MS);
    // Re-rendu des graphiques a la bascule jour/nuit (couleurs)
    new MutationObserver(function (mutations) {
      var themeChange = mutations.some(function (m) { return m.attributeName === "data-theme"; });
      if (themeChange) rafraichir();
    }).observe(document.documentElement, { attributes: true });
  });
})();
