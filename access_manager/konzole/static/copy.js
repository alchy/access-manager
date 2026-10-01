/* Copy button: puts the text of another element on the clipboard.
 *
 * Usage: <button data-copy-from="element-id">. The handler lives in a file
 * because the reverse proxy sends "script-src 'self'" and the browser then
 * ignores inline handlers (onclick=...). Without this script the page still
 * works - the value stays visible and can be selected by hand.
 */
(function () {
  "use strict";

  document.addEventListener("click", function (event) {
    var button = event.target.closest("[data-copy-from]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy-from"));
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent.trim());
  });
})();
