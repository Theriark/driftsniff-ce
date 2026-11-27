/* Escape closes the open menu of the shell.

   The user menu and the phone navigation are details elements, so they open and close without
   script; a details element has no key of its own to close it. Escape closes whichever is open
   and puts the focus back on its summary, so a keyboard user is where they opened it. */
(function () {
  "use strict";

  document.addEventListener("keydown", function (event) {
    if (event.key !== "Escape") {
      return;
    }
    document.querySelectorAll("details.user-menu[open], details.menu-toggle[open]").forEach(
      function (menu) {
        menu.open = false;
        var summary = menu.querySelector("summary");
        if (summary && menu.contains(document.activeElement)) {
          summary.focus();
        }
      }
    );
  });
})();
