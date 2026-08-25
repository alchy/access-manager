/* Login codes: convenience on top of inputs that work without this script.
 *
 * The template renders one box per digit and the server joins them back
 * together (_kod_z_formulare). This file only removes clicking: it advances
 * the caret, steps back on delete and spreads a pasted code across the
 * boxes. If it fails to load, signing in still works - you just move
 * between the boxes with Tab.
 */
(function () {
  "use strict";

  /** Digits only; drop everything else (spaces, dashes from an SMS). */
  function digitsOnly(text) {
    return (text || "").replace(/\D+/g, "");
  }

  function attach(group) {
    var boxes = Array.prototype.slice.call(
      group.querySelectorAll(".code-box")
    );
    if (!boxes.length) return;

    /** Spread a string of digits starting at the given box. */
    function spread(from, text) {
      var digits = digitsOnly(text);
      if (!digits) return;
      var start = boxes.indexOf(from);
      var last = start;
      for (var i = 0; i < digits.length && start + i < boxes.length; i++) {
        boxes[start + i].value = digits.charAt(i);
        last = start + i;
      }
      var next = Math.min(last + 1, boxes.length - 1);
      boxes[next].focus();
      boxes[next].select();
    }

    boxes.forEach(function (box, index) {
      box.addEventListener("input", function () {
        var digits = digitsOnly(box.value);
        if (digits.length > 1) {
          // Fast typing, or a phone dropped the whole code into box one.
          box.value = "";
          spread(box, digits);
          return;
        }
        box.value = digits;
        if (digits && index + 1 < boxes.length) {
          boxes[index + 1].focus();
          boxes[index + 1].select();
        }
      });

      box.addEventListener("keydown", function (event) {
        if (event.key === "Backspace" && !box.value && index > 0) {
          // Empty box + backspace = step back and clear that one.
          event.preventDefault();
          boxes[index - 1].value = "";
          boxes[index - 1].focus();
        } else if (event.key === "ArrowLeft" && index > 0) {
          event.preventDefault();
          boxes[index - 1].focus();
          boxes[index - 1].select();
        } else if (event.key === "ArrowRight" && index + 1 < boxes.length) {
          event.preventDefault();
          boxes[index + 1].focus();
          boxes[index + 1].select();
        }
      });

      box.addEventListener("paste", function (event) {
        var clipboard = event.clipboardData || window.clipboardData;
        if (!clipboard) return;
        event.preventDefault();
        spread(box, clipboard.getData("text"));
      });

      // Clicking a box selects it - overwriting is then one keystroke.
      box.addEventListener("focus", function () {
        box.select();
      });
    });
  }

  document.querySelectorAll(".code-group").forEach(attach);
})();
