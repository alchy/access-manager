/* Audit: automatic refresh every minute, on top of a page that works without it.
 *
 * The page is a plain GET; the Refresh button reloads it with the same
 * filters. This file only adds the "every minute" switch: it reveals the
 * hidden checkbox, remembers the choice per view in localStorage and reloads
 * the page after a 60 s countdown. While a record detail is open the
 * countdown stays paused - reloading would move the rows under the reader.
 */
(function () {
  "use strict";

  var lista = document.querySelector("[data-obnova]");
  if (!lista) return;
  var prepinac = lista.querySelector(".prepinac");
  var box = prepinac && prepinac.querySelector("input");
  var odpocet = lista.querySelector(".odpocet");
  if (!box || !odpocet) return;

  var klic = "access-manager.audit.auto." + lista.getAttribute("data-obnova");
  var detailOtevreny = lista.getAttribute("data-detail") === "1";
  var INTERVAL = 60;
  var zbyva = INTERVAL;

  function nacti() {
    try { return window.localStorage.getItem(klic) === "1"; } catch (e) { return false; }
  }
  function uloz(zapnuto) {
    try { window.localStorage.setItem(klic, zapnuto ? "1" : "0"); } catch (e) { /* bez pameti */ }
  }

  function vykresli() {
    if (!box.checked) { odpocet.hidden = true; return; }
    odpocet.hidden = false;
    odpocet.textContent = detailOtevreny
      ? lista.getAttribute("data-pozastaveno")
      : lista.getAttribute("data-dalsi").replace("{s}", String(zbyva));
  }

  prepinac.hidden = false;
  box.checked = nacti();
  box.addEventListener("change", function () {
    uloz(box.checked);
    zbyva = INTERVAL;
    vykresli();
  });

  window.setInterval(function () {
    if (!box.checked || detailOtevreny) return;
    zbyva -= 1;
    if (zbyva <= 0) {
      window.location.reload();
      return;
    }
    vykresli();
  }, 1000);
  vykresli();
})();
