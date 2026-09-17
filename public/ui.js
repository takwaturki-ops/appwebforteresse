// =============================================================
// UI GENERALE (public/ui.js) - charge dans <head>, 100 % externe
// (exigence CSP : aucun <script> inline).
//
// 1. Applique le theme memorise AVANT le premier rendu (pas de flash).
// 2. Apres chargement du DOM : toggle jour/nuit + sidebar mobile.
// =============================================================

// --- 1. Theme immediat (document.body n'existe pas encore ici) ---
(function appliquerThemeMemorise() {
  try {
    var theme = localStorage.getItem("forteresse-theme") || "light";
    if (theme !== "light" && theme !== "dark") theme = "light";
    document.documentElement.setAttribute("data-theme", theme);
  } catch (e) {
    document.documentElement.setAttribute("data-theme", "light");
  }
})();

// --- 2. Interactions (DOM pret) ---
document.addEventListener("DOMContentLoaded", function () {
  // Bascule jour/nuit + memorisation
  var boutonTheme = document.getElementById("boutonTheme");
  if (boutonTheme) {
    boutonTheme.addEventListener("click", function () {
      var courant = document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
      var suivant = courant === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", suivant);
      try {
        localStorage.setItem("forteresse-theme", suivant);
      } catch (e) {
        /* stockage indisponible : le theme s'applique quand meme */
      }
      boutonTheme.textContent = suivant === "dark" ? "\u2600" : "\u263E";
    });
    // Icone coherente avec le theme actif au chargement
    if (document.documentElement.getAttribute("data-theme") === "dark") {
      boutonTheme.textContent = "\u2600";
    }
  }

  // Sidebar mobile : burger <-> voile <-> Echap
  var boutonSidebar = document.getElementById("boutonSidebar");
  var voile = document.getElementById("sidebarVoile");
  function basculerSidebar(ouvrir) {
    var ouvrirVraiment = typeof ouvrir === "boolean" ? ouvrir : !document.body.classList.contains("sidebar-ouverte");
    document.body.classList.toggle("sidebar-ouverte", ouvrirVraiment);
  }
  if (boutonSidebar) boutonSidebar.addEventListener("click", function () { basculerSidebar(); });
  if (voile) voile.addEventListener("click", function () { basculerSidebar(false); });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") basculerSidebar(false);
  });
});
