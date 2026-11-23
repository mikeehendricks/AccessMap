/* CSP-compliant confirmation handler for destructive admin forms. */
(function () {
  "use strict";
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var msg = form.getAttribute("data-confirm") || "Are you sure?";
      if (!window.confirm(msg)) {
        event.preventDefault();
      }
    });
  });
})();
